//! Native messaging host for the "Save to Warden" browser extension.
//!
//! The browser starts the host and talks to it over stdin and stdout. Each message is a
//! `u32` little-endian length followed by UTF-8 JSON. The limit is 1 MiB in each direction.
//!
//! The host accepts only two message types and refuses everything else:
//!
//! - `inbox_add` becomes `Request::InboxAdd`.
//! - `inbox_list` becomes `Request::InboxList`.
//!
//! The host connects to the daemon with a pairing token that holds only `Capability::InboxWrite`.
//! It never returns a secret value to the browser.

mod frame;
mod manifest;
mod register;

pub use frame::{MAX_MESSAGE, read_message, write_message};
pub use manifest::{HOST_NAME, host_manifest, valid_extension_id};
pub use register::{manifest_dirs, register, register_in, unregister, unregister_in};

use async_trait::async_trait;
use serde_json::{Value, json};
use std::future::Future;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};
use warden_core::SecretValue;
use warden_core::ipc::{Capability, Request, Response};
use warden_ipc::Client;

/// Error that ends the host loop.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// A read or write on stdin or stdout failed.
    #[error("native messaging I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The browser sent a message above the size limit.
    #[error("message of {0} bytes exceeds the 1 MiB limit")]
    TooLarge(usize),
}

/// A connection to the daemon. [`Client`] implements it. Tests use a fake.
#[async_trait]
pub trait Upstream: Send {
    /// Send one request and return the response.
    async fn call(&mut self, req: Request) -> warden_core::Result<Response>;
}

#[async_trait]
impl Upstream for Client {
    async fn call(&mut self, req: Request) -> warden_core::Result<Response> {
        Client::call(self, req).await
    }
}

/// Read a pairing token from a file. Surrounding white space is removed.
pub fn read_token(path: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

/// Connect to the daemon with the token in `token_path`.
///
/// `socket` is `None` for the per-user default endpoint. The function refuses a token
/// that holds more than `Capability::InboxWrite`.
pub async fn connect_with_token(
    socket: Option<PathBuf>,
    token_path: PathBuf,
) -> warden_core::Result<Client> {
    let token = read_token(&token_path)
        .map_err(|e| warden_core::WardenError::Ipc(format!("cannot read token file: {e}")))?;
    let client = Client::connect(socket.as_deref(), Some(&token)).await?;
    if client.capabilities() != [Capability::InboxWrite] {
        return Err(warden_core::WardenError::Ipc(
            "token holds more than the inbox_write capability".into(),
        ));
    }
    Ok(client)
}

fn error_value(code: &str, message: &str) -> Value {
    json!({ "type": "error", "code": code, "message": message })
}

fn str_field<'a>(msg: &'a Value, key: &str) -> Option<&'a str> {
    msg.get(key).and_then(Value::as_str)
}

/// Parse `YYYY-MM-DD` or RFC 3339 into a UTC time.
fn parse_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&chrono::Utc));
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| t.and_utc())
}

/// Translate one browser message into a daemon request.
fn to_request(msg: &Value) -> Result<Request, Value> {
    match str_field(msg, "type") {
        Some("inbox_list") => Ok(Request::InboxList),
        Some("inbox_add") => {
            let origin = str_field(msg, "origin").unwrap_or_default();
            let label = str_field(msg, "label").unwrap_or_default();
            let value = str_field(msg, "value").unwrap_or_default();
            if !(origin.starts_with("https://") || origin.starts_with("http://")) {
                return Err(error_value(
                    "bad_request",
                    "origin must be an http(s) origin",
                ));
            }
            if label.trim().is_empty() || value.is_empty() {
                return Err(error_value("bad_request", "label and value are required"));
            }
            Ok(Request::InboxAdd {
                origin: origin.to_owned(),
                label: label.to_owned(),
                value: SecretValue::new(value),
                provider_hint: str_field(msg, "provider_hint").map(str::to_owned),
                expires_at: str_field(msg, "expires_at").and_then(parse_date),
            })
        }
        _ => Err(error_value("unsupported", "message type is not supported")),
    }
}

/// Convert a daemon response to the JSON that the browser sees.
fn from_response(resp: &Response) -> Value {
    match resp {
        Response::Inbox { .. } | Response::InboxAdded { .. } | Response::Error { .. } => {
            warden_ipc::response_to_value(resp)
                .unwrap_or_else(|_| error_value("internal", "cannot encode response"))
        }
        _ => error_value("internal", "unexpected daemon response"),
    }
}

/// Run the host loop until stdin closes.
///
/// `connect` opens a daemon connection. The host calls it on the first request and again
/// after a failed call. A message above the limit ends the loop with [`HostError::TooLarge`]
/// after the host answers with an error message.
pub async fn run<R, W, C, F, Fut>(mut stdin: R, mut stdout: W, connect: F) -> Result<(), HostError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: Upstream,
    F: Fn() -> Fut,
    Fut: Future<Output = warden_core::Result<C>>,
{
    let mut upstream: Option<C> = None;
    loop {
        let bytes = match read_message(&mut stdin).await {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(()),
            Err(HostError::TooLarge(n)) => {
                let reply = error_value("too_large", "message exceeds the 1 MiB limit");
                write_message(&mut stdout, &reply).await?;
                return Err(HostError::TooLarge(n));
            }
            Err(e) => return Err(e),
        };
        let reply = match serde_json::from_slice::<Value>(&bytes) {
            Err(_) => error_value("bad_request", "message is not valid JSON"),
            Ok(msg) => match to_request(&msg) {
                Err(reply) => reply,
                Ok(req) => dispatch(&mut upstream, &connect, req).await,
            },
        };
        write_message(&mut stdout, &reply).await?;
    }
}

async fn dispatch<C, F, Fut>(upstream: &mut Option<C>, connect: &F, req: Request) -> Value
where
    C: Upstream,
    F: Fn() -> Fut,
    Fut: Future<Output = warden_core::Result<C>>,
{
    if upstream.is_none() {
        match connect().await {
            Ok(c) => *upstream = Some(c),
            Err(_) => return error_value("unavailable", "Warden daemon is not reachable"),
        }
    }
    let Some(conn) = upstream.as_mut() else {
        return error_value("unavailable", "Warden daemon is not reachable");
    };
    match conn.call(req).await {
        Ok(resp) => from_response(&resp),
        Err(_) => {
            *upstream = None;
            error_value("unavailable", "Warden daemon call failed")
        }
    }
}
