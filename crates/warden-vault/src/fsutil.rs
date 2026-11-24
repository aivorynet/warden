//! Atomic file writes (temp file, fsync, rename).

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Take an exclusive advisory lock on `path` (created when needed), across processes.
/// The lock ends when the returned file drops.
pub fn lock_exclusive(path: &Path) -> io::Result<fs::File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    f.lock()?;
    Ok(f)
}

/// Write `data` to `path` atomically. The file has mode 0600 on Unix when `private` is set.
pub fn atomic_write(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    write_atomic(path, data, private, false)
}

/// Like [`atomic_write`], but never replaces a file. Fails with `AlreadyExists` when `path`
/// exists, also when another writer creates it at the same time.
///
/// The data goes to a temp file first and a hard link publishes it, so a reader never sees a
/// partial file. Only when the file system reports that hard links are unsupported, the file
/// is created with `create_new` instead, and a failed write removes it.
pub fn publish_new(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    write_atomic(path, data, private, true)
}

fn write_atomic(path: &Path, data: &[u8], private: bool, no_replace: bool) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{:016x}.tmp", rand::rng().next_u64()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        if no_replace {
            match fs::hard_link(&tmp, path) {
                Ok(()) => fs::remove_file(&tmp),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                    // No hard links here: claim the name with `create_new`. A failed write
                    // removes the partial file, so no truncated file stays behind.
                    let mut o = OpenOptions::new();
                    o.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        o.mode(if private { 0o600 } else { 0o644 });
                    }
                    let mut f = o.open(path)?;
                    let written = f.write_all(data).and_then(|()| f.sync_all());
                    drop(f);
                    if let Err(e) = written {
                        let _ = fs::remove_file(path);
                        return Err(e);
                    }
                    fs::remove_file(&tmp)
                }
                Err(e) => Err(e),
            }
        } else {
            fs::rename(&tmp, path)
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
