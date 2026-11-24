//! End-to-end tests over the real transport.

use crate::frame::{FrameError, MAX_FRAME, read_msg, write_msg};
use crate::proto::{ClientMsg, Hello, HelloReply, read_response};
use crate::{Client, Handler, PairingStore, Server, Session, os};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use warden_core::ClientToken;
use warden_core::ipc::{Capability, Request, Response};
use warden_core::{ItemId, RotationPolicy, SecretValue};

struct Store(HashMap<String, Vec<Capability>>);

#[async_trait::async_trait]
impl PairingStore for Store {
    async fn lookup(&self, token: &ClientToken) -> Option<Vec<Capability>> {
        self.0.get(token.expose()).cloned()
    }
}

#[derive(Default)]
struct Counting(AtomicUsize);

#[async_trait::async_trait]
impl Handler for Counting {
    async fn handle(&self, _s: &Session, req: Request) -> Response {
        self.0.fetch_add(1, Ordering::SeqCst);
        match req {
            Request::ListItems => Response::Items { items: vec![] },
            Request::Pair { capabilities, .. } => Response::Paired {
                capabilities,
                token: SecretValue::new(ClientToken::generate().expose()),
            },
            _ => Response::Ok,
        }
    }
}

struct Fixture {
    path: PathBuf,
    handler: Arc<Counting>,
    pairing: crate::PairingMode,
    full: String,
    mcp: String,
    _dir: Option<tempfile::TempDir>,
}

fn is_forbidden(r: &Response) -> bool {
    matches!(r, Response::Error { code, .. } if code == "forbidden")
}

fn start(tag: &str) -> Fixture {
    #[cfg(unix)]
    let (path, dir) = {
        let d = tempfile::tempdir().unwrap();
        (d.path().join("w.sock"), Some(d))
    };
    #[cfg(windows)]
    let (path, dir) = (
        PathBuf::from(format!(
            r"\\.\pipe\aivory-warden-test-{tag}-{}",
            std::process::id()
        )),
        None::<tempfile::TempDir>,
    );
    let _ = tag;
    let full = ClientToken::generate().expose().to_string();
    let mcp = ClientToken::generate().expose().to_string();
    let store = Store(HashMap::from([
        (full.clone(), vec![Capability::Full]),
        (mcp.clone(), vec![Capability::McpUse]),
    ]));
    let server = Server::bind(Some(&path))
        .unwrap()
        .with_pairing_store(Arc::new(store));
    let pairing = server.pairing_mode();
    let handler = Arc::new(Counting::default());
    tokio::spawn(server.serve(handler.clone()));
    Fixture {
        path,
        handler,
        pairing,
        full,
        mcp,
        _dir: dir,
    }
}

#[tokio::test]
async fn roundtrip() {
    let f = start("roundtrip");
    let mut c = Client::connect(Some(&f.path), Some(&f.full)).await.unwrap();
    assert_eq!(c.capabilities(), &[Capability::Full]);
    let r = c.call(Request::ListItems).await.unwrap();
    assert!(matches!(r, Response::Items { items: v } if v.is_empty()));
    let r = c.call(Request::Lock).await.unwrap();
    assert!(matches!(r, Response::Ok));
}

#[tokio::test]
async fn unpaired_client_refused() {
    let f = start("unpaired");
    // No token, no pairing window.
    assert!(Client::connect(Some(&f.path), None).await.is_err());
    // Token with a valid checksum that the store does not know.
    let unknown = ClientToken::generate();
    assert!(
        Client::connect(Some(&f.path), Some(unknown.expose()))
            .await
            .is_err()
    );
    // Malformed token.
    assert!(
        Client::connect(Some(&f.path), Some("aivw_nope"))
            .await
            .is_err()
    );
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mcp_use_cannot_change_policy_or_delete() {
    let f = start("mcpuse");
    let mut c = Client::connect(Some(&f.path), Some(&f.mcp)).await.unwrap();
    let r = c
        .call(Request::UpdatePolicy {
            item: ItemId::new(),
            policy: RotationPolicy::default(),
        })
        .await
        .unwrap();
    assert!(is_forbidden(&r));
    let r = c
        .call(Request::DeleteItem {
            item: ItemId::new(),
        })
        .await
        .unwrap();
    assert!(is_forbidden(&r));
    assert!(is_forbidden(&c.set_pairing_mode(true).await.unwrap()));
    assert!(!f.pairing.is_active());
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 0);
    // An allowed request still works on the same session.
    assert!(matches!(
        c.call(Request::ListItems).await.unwrap(),
        Response::Items { .. }
    ));
}

#[tokio::test]
async fn pairing_window_allows_one_pair() {
    let f = start("pairing");
    let pair = || Request::Pair {
        name: "mcp".into(),
        capabilities: vec![Capability::McpUse],
    };
    // A Full client opens the window.
    let mut admin = Client::connect(Some(&f.path), Some(&f.full)).await.unwrap();
    assert!(matches!(
        admin.set_pairing_mode(true).await.unwrap(),
        Response::Ok
    ));
    assert!(f.pairing.is_active());

    let mut c = Client::connect(Some(&f.path), None).await.unwrap();
    assert!(c.is_bootstrap());
    // A bootstrap session may do nothing but Pair.
    assert!(is_forbidden(&c.call(Request::ListItems).await.unwrap()));
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 0);
    assert!(matches!(
        c.call(pair()).await.unwrap(),
        Response::Paired { .. }
    ));
    // The window is closed now.
    assert!(is_forbidden(&c.call(pair()).await.unwrap()));
    assert!(Client::connect(Some(&f.path), None).await.is_err());
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversize_frame_refused() {
    let f = start("oversize");
    // Client side: the request never goes out.
    let mut c = Client::connect(Some(&f.path), Some(&f.full)).await.unwrap();
    let big = Request::InboxAdd {
        origin: "o".into(),
        label: "l".into(),
        value: SecretValue::new("a".repeat(MAX_FRAME + 1)),
    };
    assert!(c.call(big).await.is_err());

    // Server side: a length above the limit gets an error and a closed connection.
    let mut raw = os::connect(Some(&f.path)).await.unwrap();
    write_msg(
        &mut raw,
        &Hello {
            client_token: Some(f.full.clone()),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_msg::<_, HelloReply>(&mut raw).await.unwrap(),
        HelloReply::Accepted { .. }
    ));
    raw.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    let r = read_response(&mut raw).await.unwrap();
    assert!(matches!(r, Response::Error { code, .. } if code == "frame_too_large"));
    assert!(matches!(
        read_response(&mut raw).await,
        Err(FrameError::Closed | FrameError::Io(_))
    ));
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 0);
    let _ = ClientMsg::SetPairingMode { enabled: false };
}

/// Needs `sudo -n` and Python 3 and a second user (`nobody`). It runs in CI on Linux only.
#[cfg(unix)]
#[tokio::test]
#[ignore = "other-user test: runs in CI on Linux (needs sudo -n -u nobody)"]
async fn other_user_cannot_connect() {
    let f = start("otheruser");
    let script = format!(
        "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ns.connect({:?})",
        f.path.to_str().unwrap()
    );
    let out = std::process::Command::new("sudo")
        .args(["-n", "-u", "nobody", "python3", "-c", &script])
        .output()
        .unwrap();
    assert!(!out.status.success(), "other user connected");
}
