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
//! # Pairing
//!
//! A connection without a token is always refused. A new client gets its token from a `Full`
//! session (the CLI or the desktop app) with `Request::Pair`.
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
pub use session::{EmptyStore, PairingStore, Session};

/// Restrict the file at `path` to its owner: mode 0600 on Unix, an owner-only DACL on Windows.
pub fn restrict_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    os::restrict_to_owner(path)
}
