//! Write the host manifest and register it with Edge and Chrome.

use crate::manifest::{HOST_NAME, host_manifest, valid_extension_id};
use std::io;
use std::path::{Path, PathBuf};

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

/// Directories that hold the manifest, one per browser, for the current user.
///
/// On Windows there is one directory and the registry keys point to it.
pub fn manifest_dirs() -> io::Result<Vec<PathBuf>> {
    let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
    if cfg!(windows) {
        let base = var("LOCALAPPDATA").ok_or_else(|| bad("LOCALAPPDATA is not set"))?;
        return Ok(vec![base.join("Aivory").join("Warden").join("native-host")]);
    }
    let home = var("HOME").ok_or_else(|| bad("HOME is not set"))?;
    let dirs = if cfg!(target_os = "macos") {
        let s = home.join("Library").join("Application Support");
        vec![
            s.join("Microsoft Edge").join("NativeMessagingHosts"),
            s.join("Google").join("Chrome").join("NativeMessagingHosts"),
        ]
    } else {
        let c = home.join(".config");
        vec![
            c.join("microsoft-edge").join("NativeMessagingHosts"),
            c.join("google-chrome").join("NativeMessagingHosts"),
        ]
    };
    Ok(dirs)
}

fn file_name() -> String {
    format!("{HOST_NAME}.json")
}

/// Write the manifest into each directory in `dirs`. Return the file paths.
pub fn register_in(
    dirs: &[PathBuf],
    exe_path: &Path,
    extension_id: &str,
) -> io::Result<Vec<PathBuf>> {
    if !valid_extension_id(extension_id) {
        return Err(bad("extension id must be 32 letters from a to p"));
    }
    if !exe_path.is_absolute() {
        return Err(bad("exe path must be absolute"));
    }
    let text = serde_json::to_string_pretty(&host_manifest(exe_path, extension_id))
        .map_err(io::Error::other)?;
    let mut files = Vec::new();
    for dir in dirs {
        std::fs::create_dir_all(dir)?;
        let file = dir.join(file_name());
        std::fs::write(&file, &text)?;
        files.push(file);
    }
    Ok(files)
}

/// Remove the manifest files in `dirs`. A missing file is not an error.
pub fn unregister_in(dirs: &[PathBuf]) -> io::Result<()> {
    for dir in dirs {
        match std::fs::remove_file(dir.join(file_name())) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
const REG_KEYS: [&str; 2] = [
    r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\net.aivory.warden",
    r"HKCU\Software\Google\Chrome\NativeMessagingHosts\net.aivory.warden",
];

/// Register the host for Edge and Chrome for the current user.
///
/// `exe_path` must start the host with no extra arguments. Return the manifest files.
pub fn register(exe_path: &Path, extension_id: &str) -> io::Result<Vec<PathBuf>> {
    let files = register_in(&manifest_dirs()?, exe_path, extension_id)?;
    #[cfg(windows)]
    for key in REG_KEYS {
        let out = std::process::Command::new("reg")
            .args(["add", key, "/ve", "/t", "REG_SZ", "/f", "/d"])
            .arg(&files[0])
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("reg add failed for {key}")));
        }
    }
    Ok(files)
}

/// Remove the manifest files and, on Windows, the registry keys.
pub fn unregister() -> io::Result<()> {
    #[cfg(windows)]
    for key in REG_KEYS {
        // A missing key is fine, so the status is not checked.
        std::process::Command::new("reg")
            .args(["delete", key, "/f"])
            .output()?;
    }
    unregister_in(&manifest_dirs()?)
}
