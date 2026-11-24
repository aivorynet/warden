//! Per-OS transport. The other modules use only [`Listener`], [`connect`] and [`BoxedStream`].

use tokio::io::{AsyncRead, AsyncWrite};

/// A byte stream with the peer already checked.
pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Boxed stream that the server and the client use.
pub(crate) type BoxedStream = Box<dyn AsyncStream>;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::{Listener, connect};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{Listener, connect};
