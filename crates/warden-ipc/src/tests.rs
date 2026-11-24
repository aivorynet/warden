//! End-to-end tests over the real transport.

use crate::frame::{FrameError, MAX_FRAME, read_msg, write_msg};
use crate::proto::{Hello, HelloReply, read_response};
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
    let handler = Arc::new(Counting::default());
    tokio::spawn(server.serve(handler.clone()));
    Fixture {
        path,
        handler,
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
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 0);
    // An allowed request still works on the same session.
    assert!(matches!(
        c.call(Request::ListItems).await.unwrap(),
        Response::Items { .. }
    ));
}

#[tokio::test]
async fn tokenless_connection_refused_always() {
    let f = start("nobootstrap");
    // Even after a Full client paired another client, a tokenless client has no way in.
    let mut admin = Client::connect(Some(&f.path), Some(&f.full)).await.unwrap();
    let r = admin
        .call(Request::Pair {
            name: "mcp".into(),
            capabilities: vec![Capability::McpUse],
        })
        .await
        .unwrap();
    assert!(matches!(r, Response::Paired { .. }));
    assert!(Client::connect(Some(&f.path), None).await.is_err());
    assert_eq!(f.handler.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversize_response_keeps_session() {
    struct Big;
    #[async_trait::async_trait]
    impl Handler for Big {
        async fn handle(&self, _s: &Session, req: Request) -> Response {
            match req {
                Request::Lock => Response::Error {
                    code: "x".into(),
                    message: "a".repeat(MAX_FRAME + 10),
                },
                _ => Response::Ok,
            }
        }
    }
    let f = start("bigresp");
    // A second server is not needed: reuse the fixture path with a new handler is impossible,
    // so bind a dedicated one.
    #[cfg(unix)]
    let (path, _d) = {
        let d = tempfile::tempdir().unwrap();
        (d.path().join("b.sock"), d)
    };
    #[cfg(windows)]
    let (path, _d) = (
        PathBuf::from(format!(
            r"\\.\pipe\aivory-warden-test-big-{}",
            std::process::id()
        )),
        (),
    );
    let _ = f;
    let token = ClientToken::generate().expose().to_string();
    let store = Store(HashMap::from([(token.clone(), vec![Capability::Full])]));
    let server = Server::bind(Some(&path))
        .unwrap()
        .with_pairing_store(Arc::new(store));
    tokio::spawn(server.serve(Arc::new(Big)));
    let mut c = Client::connect(Some(&path), Some(&token)).await.unwrap();
    let r = c.call(Request::Lock).await.unwrap();
    assert!(matches!(r, Response::Error { code, .. } if code == "response_too_large"));
    assert!(matches!(
        c.call(Request::Status).await.unwrap(),
        Response::Ok
    ));
}

#[tokio::test]
async fn call_times_out_and_marks_session_broken() {
    struct Slow;
    #[async_trait::async_trait]
    impl Handler for Slow {
        async fn handle(&self, _s: &Session, _req: Request) -> Response {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Response::Ok
        }
    }
    #[cfg(unix)]
    let (path, _d) = {
        let d = tempfile::tempdir().unwrap();
        (d.path().join("s.sock"), d)
    };
    #[cfg(windows)]
    let (path, _d) = (
        PathBuf::from(format!(
            r"\\.\pipe\aivory-warden-test-slow-{}",
            std::process::id()
        )),
        (),
    );
    let token = ClientToken::generate().expose().to_string();
    let store = Store(HashMap::from([(token.clone(), vec![Capability::Full])]));
    let server = Server::bind(Some(&path))
        .unwrap()
        .with_pairing_store(Arc::new(store));
    tokio::spawn(server.serve(Arc::new(Slow)));
    let mut c = Client::connect(Some(&path), Some(&token)).await.unwrap();
    let r = c
        .call_with_timeout(Request::Lock, std::time::Duration::from_millis(200))
        .await;
    assert!(r.is_err());
    assert!(c.is_broken());
    assert!(c.call(Request::Lock).await.is_err());
    // A caller that drops the future in the middle also leaves a broken session.
    let mut c2 = Client::connect(Some(&path), Some(&token)).await.unwrap();
    let r = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        c2.call(Request::Lock),
    )
    .await;
    assert!(r.is_err());
    assert!(c2.is_broken());
}

#[test]
fn restrict_to_owner_works() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cli.token");
    std::fs::write(&p, "x").unwrap();
    crate::restrict_to_owner(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // The owner can still read the file.
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "x");
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
        provider_hint: None,
        expires_at: None,
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
