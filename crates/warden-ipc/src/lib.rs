//! Local IPC between the Warden daemon and its clients.
//!
//! - Transport: a Unix socket in a `0700` directory (peer UID check), or a Windows named pipe
//!   `\\.\pipe\aivory-warden-<user-sid>` (remote clients rejected, owner-only DACL, client SID check).
//! - Framing: `u32` big-endian length, then JSON of `warden_core::ipc::Request` / `Response`.
//!   The maximum body is 1 MiB.
//! - Session: the first frame is [`proto::Hello`] with the `aivw_` client token. The server
//!   binds the session to the token capabilities and refuses each request that
//!   `Capability::allows` denies.
//!
//! # Pairing bootstrap
//!
//! A client needs a token to talk to the daemon, and it needs the daemon to get a token. The
//! pairing window solves this:
//!
//! 1. A `Full` client (the CLI) sends `set_pairing_mode(true)`, or the daemon calls
//!    [`PairingMode::enable`] itself (for example on first run).
//! 2. For 120 seconds, a client may connect without a token. The session is a bootstrap
//!    session. It allows only `Request::Pair`.
//! 3. The first `Pair` request closes the window before the handler runs. The handler creates
//!    the token and answers `Response::Paired`. A second `Pair` fails until the window opens again.
//!
//! The transport peer check still applies: only the same OS user can connect at all.

mod client;
mod frame;
mod os;
mod proto;
mod server;
mod session;

#[cfg(test)]
mod tests;

pub use client::Client;
pub use frame::{FrameError, MAX_FRAME, read_msg, write_msg};
pub use proto::{
    ClientMsg, Hello, HelloReply, read_response, response_from_value, response_to_value,
    write_response,
};
pub use server::{Handler, Server};
pub use session::{EmptyStore, PAIRING_WINDOW, PairingMode, PairingStore, Session};
