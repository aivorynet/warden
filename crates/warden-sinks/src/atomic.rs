//! Atomic file replacement: temp file in the same directory, fsync, rename.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `data` to `path` atomically.
///
/// The function writes a temp file in the same directory, copies the mode
/// (Unix) and the attributes (Windows) of the old file, calls fsync, and
/// renames the temp file over `path`. A new file gets mode 0600 on Unix.
/// A symlink at `path` is followed. On failure the old file stays intact.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    atomic_write_with(path, data, |_| Ok(()))
}

/// Same as [`atomic_write`], with a hook that runs after fsync and before the rename.
pub(crate) fn atomic_write_with(
    path: &Path,
    data: &[u8],
    before_rename: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let target = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let old = fs::metadata(&target).ok();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".{name}.warden-{}-{nanos}.tmp", std::process::id()));
    let result = (|| {
        let mut f = open_tmp(&tmp, old.as_ref())?;
        f.write_all(data)?;
        if let Some(m) = &old {
            f.set_permissions(m.permissions())?;
        }
        f.sync_all()?;
        drop(f);
        // The temp file takes the folder ACL. Copy the DACL of the old file, so a tight
        // ACL does not widen. Fail closed: a wider ACL on a secret file is worse.
        #[cfg(windows)]
        if old.is_some() {
            crate::winacl::copy_dacl(&target, &tmp)?;
        }
        before_rename(&tmp)?;
        fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    sync_dir(&dir);
    Ok(())
}

#[cfg(unix)]
fn open_tmp(tmp: &Path, old: Option<&fs::Metadata>) -> io::Result<fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mode = old.map_or(0o600, |m| m.mode() & 0o7777);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(tmp)
}

#[cfg(windows)]
fn open_tmp(tmp: &Path, old: Option<&fs::Metadata>) -> io::Result<fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // HIDDEN | SYSTEM | ARCHIVE | NOT_CONTENT_INDEXED
    const KEEP: u32 = 0x2 | 0x4 | 0x20 | 0x2000;
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    if let Some(m) = old {
        o.attributes(m.file_attributes() & KEEP);
    }
    o.open(tmp)
}

#[cfg(not(any(unix, windows)))]
fn open_tmp(tmp: &Path, _old: Option<&fs::Metadata>) -> io::Result<fs::File> {
    OpenOptions::new().write(true).create_new(true).open(tmp)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_content() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn failure_before_rename_keeps_old_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        fs::write(&p, b"old").unwrap();
        let r = atomic_write_with(&p, b"new", |_| {
            Err(io::Error::other("simulated crash before rename"))
        });
        assert!(r.is_err());
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "temp file left");
    }

    #[cfg(unix)]
    #[test]
    fn mode_is_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        atomic_write(&p, b"new").unwrap();
        let m = fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        atomic_write(&p, b"x").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn hidden_attribute_is_preserved() {
        use std::os::windows::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        fs::write(&p, b"old").unwrap();
        let st = std::process::Command::new("attrib")
            .arg("+h")
            .arg(&p)
            .status()
            .unwrap();
        assert!(st.success());
        atomic_write(&p, b"new").unwrap();
        assert_ne!(fs::metadata(&p).unwrap().file_attributes() & 0x2, 0);
        assert_eq!(fs::read(&p).unwrap(), b"new");
    }

    #[cfg(windows)]
    #[test]
    fn dacl_is_preserved() {
        fn acl(p: &Path) -> String {
            let out = std::process::Command::new("icacls")
                .arg(p)
                .output()
                .unwrap();
            // Drop the path from the first line and the summary line.
            String::from_utf8_lossy(&out.stdout)
                .replace(p.to_str().unwrap(), "")
                .lines()
                .filter(|l| !l.contains("Successfully processed"))
                .map(str::trim)
                .collect::<Vec<_>>()
                .join("|")
        }
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.env");
        fs::write(&p, b"old").unwrap();
        let user = std::env::var("USERNAME").unwrap();
        let st = std::process::Command::new("icacls")
            .arg(&p)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{user}:F"))
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let before = acl(&p);
        assert!(!before.contains(r"BUILTIN\Users"), "{before}");
        atomic_write(&p, b"new").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(acl(&p), before);
    }
}
