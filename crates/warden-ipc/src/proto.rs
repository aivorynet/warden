//! Envelope types of the session protocol. They wrap the frozen `warden_core::ipc` types.

use crate::frame::{FrameError, read_msg, write_msg};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use warden_core::ipc::{Capability, Request, Response};

/// First frame of a session, from the client.
#[derive(Serialize, Deserialize)]
pub struct Hello {
    /// The `aivw_` client token. `None` asks for the pairing bootstrap path.
    pub client_token: Option<String>,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field(
                "client_token",
                &self.client_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Server answer to [`Hello`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelloReply {
    /// The session is open.
    Accepted {
        /// Capabilities of the session.
        capabilities: Vec<Capability>,
        /// The session is a pairing bootstrap session: only `Pair` works, once.
        bootstrap: bool,
    },
    /// The server refuses the session and closes the connection.
    Refused {
        /// Reason, without secrets.
        message: String,
    },
}

/// Message from the client after the handshake.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMsg {
    /// A request for the handler.
    Request(Box<Request>),
    /// Open the pairing window. Only a `Full` session may send it. The server answers it
    /// itself; the handler never sees it.
    SetPairingMode {
        /// `true` opens the window, `false` closes it.
        enabled: bool,
    },
}

/// Serialize a [`Response`] to its JSON wire form.
pub fn response_to_value(r: &Response) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(r)
}

/// Inverse of [`response_to_value`].
pub fn response_from_value(v: serde_json::Value) -> Result<Response, serde_json::Error> {
    serde_json::from_value(v)
}

/// Write a [`Response`] as one frame.
pub async fn write_response<W>(w: &mut W, r: &Response) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    write_msg(w, &response_to_value(r).map_err(FrameError::Json)?).await
}

/// Read one frame as a [`Response`].
pub async fn read_response<R>(r: &mut R) -> Result<Response, FrameError>
where
    R: AsyncRead + Unpin,
{
    let v: serde_json::Value = read_msg(r).await?;
    response_from_value(v).map_err(FrameError::Json)
}
