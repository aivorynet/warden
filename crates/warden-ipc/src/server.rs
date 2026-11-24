//! The IPC server.

use crate::frame::{FrameError, read_msg, write_msg};
use crate::os::{BoxedStream, Listener};
use crate::proto::{ClientMsg, Hello, HelloReply, write_response};
use crate::session::{EmptyStore, PAIRING_WINDOW, PairingMode, PairingStore, Session};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use warden_core::ClientToken;
use warden_core::Result;
use warden_core::ipc::{Capability, Request, Response};

/// Time that a client has to send its first frame.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// The daemon side of request handling.
#[async_trait::async_trait]
pub trait Handler: Send + Sync {
    /// Handle one request. The server already checked `session.allows(&req)`.
    async fn handle(&self, session: &Session, req: Request) -> Response;
}

/// An IPC server bound to a socket or a named pipe.
pub struct Server {
    listener: Listener,
    store: Arc<dyn PairingStore>,
    pairing: PairingMode,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("path", &self.listener.path())
            .field("pairing", &self.pairing)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind the endpoint. `None` selects the per-user default path. Call it inside a Tokio runtime.
    ///
    /// The server refuses every token until you call [`Server::with_pairing_store`].
    pub fn bind(path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            listener: Listener::bind(path)?,
            store: Arc::new(EmptyStore),
            pairing: PairingMode::default(),
        })
    }

    /// Set the store that resolves client tokens.
    pub fn with_pairing_store(mut self, store: Arc<dyn PairingStore>) -> Self {
        self.store = store;
        self
    }

    /// Handle of the pairing window. Clones share the same window.
    pub fn pairing_mode(&self) -> PairingMode {
        self.pairing.clone()
    }

    /// The socket path or pipe name.
    pub fn path(&self) -> PathBuf {
        self.listener.path()
    }

    /// Accept connections until the future is dropped. One task serves each connection.
    pub async fn serve(mut self, handler: Arc<dyn Handler>) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok(stream) => {
                    let ctx = Ctx {
                        handler: Arc::clone(&handler),
                        store: Arc::clone(&self.store),
                        pairing: self.pairing.clone(),
                    };
                    tokio::spawn(connection(stream, ctx));
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    tracing::warn!("ipc: peer check refused a connection");
                }
                Err(e) => {
                    tracing::warn!("ipc: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

struct Ctx {
    handler: Arc<dyn Handler>,
    store: Arc<dyn PairingStore>,
    pairing: PairingMode,
}

fn error(code: &str, message: &str) -> Response {
    Response::Error {
        code: code.into(),
        message: message.into(),
    }
}

async fn handshake(stream: &mut BoxedStream, ctx: &Ctx) -> Option<Session> {
    let hello: Hello = match tokio::time::timeout(HELLO_TIMEOUT, read_msg(stream)).await {
        Ok(Ok(h)) => h,
        _ => return None,
    };
    let session = match hello.client_token {
        Some(raw) => {
            let caps = match ClientToken::parse(&raw) {
                Ok(t) => ctx.store.lookup(&t).await,
                Err(_) => None,
            };
            caps.map(Session::paired)
        }
        None => ctx.pairing.is_active().then(Session::bootstrap),
    };
    let reply = match &session {
        Some(s) => HelloReply::Accepted {
            capabilities: s.capabilities().to_vec(),
            bootstrap: s.is_bootstrap(),
        },
        None => HelloReply::Refused {
            message: "client is not paired".into(),
        },
    };
    write_msg(stream, &reply).await.ok()?;
    session
}

async fn connection(mut stream: BoxedStream, ctx: Ctx) {
    let Some(session) = handshake(&mut stream, &ctx).await else {
        return;
    };
    loop {
        let msg: ClientMsg = match read_msg(&mut stream).await {
            Ok(m) => m,
            Err(FrameError::TooLarge(_)) => {
                // The stream cannot resync after a refused length. Tell the client and close.
                let _ =
                    write_response(&mut stream, &error("frame_too_large", "frame too large")).await;
                return;
            }
            Err(FrameError::Json(_)) => {
                if write_response(&mut stream, &error("bad_request", "invalid request"))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            Err(_) => return,
        };
        let resp = match msg {
            ClientMsg::SetPairingMode { enabled } => {
                if session.capabilities().contains(&Capability::Full) {
                    if enabled {
                        ctx.pairing.enable(PAIRING_WINDOW);
                    } else {
                        ctx.pairing.disable();
                    }
                    Response::Ok
                } else {
                    error("forbidden", "capability does not allow this request")
                }
            }
            ClientMsg::Request(req) if !session.allows(&req) => {
                error("forbidden", "capability does not allow this request")
            }
            ClientMsg::Request(req) => {
                if session.is_bootstrap() && !ctx.pairing.take() {
                    error("forbidden", "pairing window is closed")
                } else {
                    ctx.handler.handle(&session, *req).await
                }
            }
        };
        if write_response(&mut stream, &resp).await.is_err() {
            return;
        }
    }
}
