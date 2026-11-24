//! Unix transport: a socket in a `0700` directory, and a peer UID check on both ends.
//!
//! This module uses no `unsafe` code: `rustix` and Tokio wrap `geteuid` and `SO_PEERCRED` /
//! `getpeereid`.

use super::BoxedStream;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};

const SOCKET_NAME: &str = "warden.sock";
const DIR_NAME: &str = "aivory-warden";

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Default socket path of the current user.
fn default_path() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join(DIR_NAME).join(SOCKET_NAME));
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(home)
            .join("Library/Application Support")
            .join(DIR_NAME)
            .join(SOCKET_NAME));
    }
    Ok(PathBuf::from(format!("/tmp/{DIR_NAME}-{}", euid())).join(SOCKET_NAME))
}

/// Create `dir` with mode `0700` if needed. Refuse a symlink, a foreign owner, or a wide mode.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket directory is not a directory owned by the current user",
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn peer_is_me(stream: &UnixStream) -> io::Result<()> {
    let cred = stream.peer_cred()?;
    if cred.uid() == euid() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer UID differs from the current user",
        ))
    }
}

/// Listening socket.
#[derive(Debug)]
pub(crate) struct Listener {
    inner: UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Bind the socket. A stale socket file (nobody answers) is replaced.
    pub(crate) fn bind(path: Option<&Path>) -> io::Result<Self> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => default_path()?,
        };
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "path exists and is not a socket",
                ));
            }
            // A live server answers; a dead one leaves a stale file.
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another server uses the socket",
                ));
            }
            std::fs::remove_file(&path)?;
        }
        let inner = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { inner, path })
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Accept one connection. A peer of another user gives `PermissionDenied`.
    pub(crate) async fn accept(&mut self) -> io::Result<BoxedStream> {
        let (stream, _) = self.inner.accept().await?;
        peer_is_me(&stream)?;
        Ok(Box::new(stream))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Connect to the server. The client checks that the server runs as the same user.
pub(crate) async fn connect(path: Option<&Path>) -> io::Result<BoxedStream> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    let stream = UnixStream::connect(&path).await?;
    peer_is_me(&stream)?;
    Ok(Box::new(stream))
}

/// Set the mode of the file at `path` to 0600.
pub(crate) fn restrict_to_owner(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
