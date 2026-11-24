//! The IPC client.

use crate::frame::{read_msg, write_msg};
use crate::os::{self, BoxedStream};
use crate::proto::{ClientMsg, Hello, HelloReply, read_response};
use std::path::Path;
use warden_core::ipc::{Capability, Request, Response};
use warden_core::{Result, WardenError};

/// A connected, authenticated client.
pub struct Client {
    stream: BoxedStream,
    capabilities: Vec<Capability>,
    bootstrap: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("capabilities", &self.capabilities)
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connect and run the handshake.
    ///
    /// `path` is `None` for the per-user default endpoint. `token` is the `aivw_` client token.
    /// Pass `None` to use the pairing bootstrap path; the server accepts it only while its
    /// pairing window is open.
    pub async fn connect(path: Option<&Path>, token: Option<&str>) -> Result<Self> {
        let mut stream = os::connect(path).await?;
        let hello = Hello {
            client_token: token.map(str::to_owned),
        };
        write_msg(&mut stream, &hello).await?;
        match read_msg(&mut stream).await? {
            HelloReply::Accepted {
                capabilities,
                bootstrap,
            } => Ok(Self {
                stream,
                capabilities,
                bootstrap,
            }),
            HelloReply::Refused { message } => Err(WardenError::Ipc(message)),
        }
    }

    /// Capabilities that the server granted to this session.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Return true when this is a pairing bootstrap session.
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap
    }

    /// Send one request and wait for its response.
    ///
    /// A request above 1 MiB fails before it is sent. The server may answer with
    /// `Response::Error { code: "forbidden", .. }`.
    pub async fn call(&mut self, req: Request) -> Result<Response> {
        write_msg(&mut self.stream, &ClientMsg::Request(Box::new(req))).await?;
        Ok(read_response(&mut self.stream).await?)
    }

    /// Open or close the server pairing window. Needs a `Full` session.
    pub async fn set_pairing_mode(&mut self, enabled: bool) -> Result<Response> {
        write_msg(&mut self.stream, &ClientMsg::SetPairingMode { enabled }).await?;
        Ok(read_response(&mut self.stream).await?)
    }
}
