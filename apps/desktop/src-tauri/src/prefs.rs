//! App preferences of the desktop app: tray icon, start at login, start in the tray, close
//! button. They live in `desktop.json` in the config directory, not in the vault settings,
//! because they belong to this app on this computer.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Command line flag that the login entry passes. The app then starts in the tray.
pub const HIDDEN_FLAG: &str = "--hidden";

/// Preferences of the desktop app on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Show the tray icon.
    pub show_tray: bool,
    /// When the OS starts the app at login, keep the window closed (tray only).
    pub start_hidden: bool,
    /// The close button hides the window to the tray. Off: the close button quits the app.
    pub close_to_tray: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            show_tray: true,
            start_hidden: true,
            close_to_tray: true,
        }
    }
}

impl Prefs {
    /// Load the file. A missing or bad file gives the defaults.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write the file (temp file, then rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    /// True when the close button hides the window. Without a tray icon it always quits,
    /// so that no invisible process stays behind.
    pub fn hide_on_close(&self) -> bool {
        self.show_tray && self.close_to_tray
    }

    /// True when a start with `args` keeps the window closed. Only the login entry passes
    /// the flag, and only a visible tray icon can open the window again.
    pub fn start_in_tray<S: AsRef<str>>(&self, args: &[S]) -> bool {
        self.show_tray && self.start_hidden && args.iter().any(|a| a.as_ref() == HIDDEN_FLAG)
    }
}

/// Path of the preferences file in the config directory.
pub fn path(config: &Path) -> PathBuf {
    config.join("desktop.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_file_is_missing_or_bad() {
        let dir = std::env::temp_dir().join(format!("warden-prefs-{}", std::process::id()));
        let p = path(&dir);
        assert_eq!(Prefs::load(&p), Prefs::default());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(Prefs::load(&p), Prefs::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_and_load_round_trip_and_old_files_load() {
        let dir = std::env::temp_dir().join(format!("warden-prefs-rt-{}", std::process::id()));
        let p = path(&dir);
        let v = Prefs {
            close_to_tray: false,
            ..Prefs::default()
        };
        v.save(&p).unwrap();
        assert_eq!(Prefs::load(&p), v);
        std::fs::write(&p, br#"{"show_tray":false}"#).unwrap();
        let old = Prefs::load(&p);
        assert!(!old.show_tray && old.start_hidden && old.close_to_tray);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_tray_means_close_quits_and_no_hidden_start() {
        let p = Prefs {
            show_tray: false,
            ..Prefs::default()
        };
        assert!(!p.hide_on_close());
        assert!(!p.start_in_tray(&["app", HIDDEN_FLAG]));
        let p = Prefs::default();
        assert!(p.hide_on_close());
        assert!(p.start_in_tray(&["app", HIDDEN_FLAG]));
        assert!(!p.start_in_tray(&["app"]));
        let p = Prefs {
            start_hidden: false,
            ..Prefs::default()
        };
        assert!(!p.start_in_tray(&["app", HIDDEN_FLAG]));
    }
}
