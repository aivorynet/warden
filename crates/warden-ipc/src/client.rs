//! The IPC client.

use crate::frame::{FrameError, read_msg, write_msg};
use crate::os::{self, BoxedStream};
use crate::proto::{ClientMsg, Hello, HelloReply, read_response};
use std::path::Path;
use std::time::Duration;
use warden_core::ipc::{Capability, Request, Response};
use warden_core::{Result, WardenError};

/// Default time limit of one call.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Time limit of a call that runs a rotation or an HTTP request.
const LONG_TIMEOUT: Duration = Duration::from_secs(120);

/// A connected, authenticated client.
pub struct Client {
    stream: BoxedStream,
    capabilities: Vec<Capability>,
    broken: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connect and run the handshake.
    ///
    /// `path` is `None` for the per-user default endpoint. `token` is the `aivw_` client token.
    /// The server refuses a connection without a token.
    pub async fn connect(path: Option<&Path>, token: Option<&str>) -> Result<Self> {
        let mut stream = os::connect(path).await?;
        let hello = Hello {
            client_token: token.map(str::to_owned),
        };
        write_msg(&mut stream, &hello).await?;
        match read_msg(&mut stream).await? {
            HelloReply::Accepted { capabilities } => Ok(Self {
                stream,
                capabilities,
                broken: false,
            }),
            HelloReply::Refused { message } => Err(WardenError::Ipc(message)),
        }
    }

    /// Capabilities that the server granted to this session.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Send one request and wait for its response.
    ///
    /// A request above 1 MiB fails before it is sent. The wait ends after 30 s (120 s for
    /// `RotateNow` and `McpHttpRequest`). After a timeout the session is out of sync, so every
    /// later call fails and the caller must reconnect. The server may answer with
    /// `Response::Error { code: "forbidden", .. }`.
    pub async fn call(&mut self, req: Request) -> Result<Response> {
        let limit = match req {
            Request::RotateNow { .. } | Request::McpHttpRequest { .. } => LONG_TIMEOUT,
            _ => CALL_TIMEOUT,
        };
        self.call_with_timeout(req, limit).await
    }

    /// Like [`Client::call`] with an explicit time limit.
    pub async fn call_with_timeout(&mut self, req: Request, limit: Duration) -> Result<Response> {
        if self.broken {
            return Err(WardenError::Ipc("session is closed, reconnect".into()));
        }
        let exchange = async {
            write_msg(&mut self.stream, &ClientMsg::Request(Box::new(req))).await?;
            read_response(&mut self.stream).await
        };
        match tokio::time::timeout(limit, exchange).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => {
                // A refused oversize request wrote nothing and keeps the session usable.
                if !matches!(e, FrameError::TooLarge(_)) {
                    self.broken = true;
                }
                Err(e.into())
            }
            Err(_) => {
                self.broken = true;
                Err(WardenError::Ipc(format!(
                    "no answer from the daemon within {} s",
                    limit.as_secs()
                )))
            }
        }
    }

    /// Return true after an I/O failure or a timeout. Connect again.
    pub fn is_broken(&self) -> bool {
        self.broken
    }
}
