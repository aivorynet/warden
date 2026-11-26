//! Stable binary paths when Warden runs from an MSIX package (Microsoft Store).
//!
//! A packaged binary lives in `C:\Program Files\WindowsApps\<package>_<version>_...\`. That
//! folder changes with every update, so a login entry, a native messaging host or an MCP
//! config that points into it breaks after the next update. The package declares app
//! execution aliases (`aivory-warden.exe`, `awd.exe`) in
//! `%LOCALAPPDATA%\Microsoft\WindowsApps\`, whose path stays the same. Every path that Warden
//! writes outside itself goes through [`stable_exe`].

use std::path::{Path, PathBuf};

/// True when `exe` lies in a package folder under `...\WindowsApps\<package>\`.
pub fn is_packaged(exe: &Path) -> bool {
    let parts: Vec<String> = exe
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    // `WindowsApps` followed by a package folder and the file itself.
    parts
        .iter()
        .position(|p| p == "windowsapps")
        .is_some_and(|i| parts.len() >= i + 3)
}

/// The alias path for a packaged `exe`, below `local_app_data`. `None` when `exe` is not
/// packaged or the alias does not exist.
pub fn alias_for(exe: &Path, local_app_data: &Path) -> Option<PathBuf> {
    if !is_packaged(exe) {
        return None;
    }
    let alias = local_app_data
        .join("Microsoft")
        .join("WindowsApps")
        .join(exe.file_name()?);
    alias.is_file().then_some(alias)
}

/// The path to write into a login entry, a native host manifest or an MCP config: the app
/// alias when `exe` runs from a package, else `exe` itself.
pub fn stable_exe(exe: PathBuf) -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .and_then(|l| alias_for(&exe, Path::new(&l)))
        .unwrap_or(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_package_folders_only() {
        assert!(is_packaged(Path::new(
            r"C:\Program Files\WindowsApps\AIVoryInc.AivoryWarden_2026.11.0.0_x64__abc\aivory-warden.exe"
        )));
        assert!(!is_packaged(Path::new(
            r"C:\Users\me\.cargo\bin\aivory-warden.exe"
        )));
        // The alias folder itself is not a package folder.
        assert!(!is_packaged(Path::new(
            r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\aivory-warden.exe"
        )));
    }

    #[test]
    fn alias_only_when_it_exists() {
        let local = std::env::temp_dir().join(format!("warden-pkg-{}", std::process::id()));
        let exe = Path::new(
            r"C:\Program Files\WindowsApps\AIVoryInc.AivoryWarden_1_x64__abc\aivory-warden.exe",
        );
        assert_eq!(alias_for(exe, &local), None);
        let dir = local.join("Microsoft").join("WindowsApps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("aivory-warden.exe"), b"").unwrap();
        assert_eq!(alias_for(exe, &local), Some(dir.join("aivory-warden.exe")));
        assert_eq!(
            alias_for(Path::new(r"C:\tools\aivory-warden.exe"), &local),
            None
        );
        std::fs::remove_dir_all(&local).unwrap();
    }
}
