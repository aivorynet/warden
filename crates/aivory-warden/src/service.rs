//! Service install for systemd (Linux), launchd (macOS) and Task Scheduler (Windows).
//!
//! The render functions are pure, so unit tests run on every OS.

use std::path::{Path, PathBuf};
use warden_core::{Result, WardenError};

/// Name of the systemd unit.
pub const SYSTEMD_UNIT: &str = "aivory-warden.service";
/// Label of the launchd agent.
pub const LAUNCHD_LABEL: &str = "net.aivory.warden";
/// Name of the scheduled task on Windows.
pub const TASK_NAME: &str = "AivoryWarden";

/// Target operating system of a service plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux with systemd.
    Linux,
    /// macOS with launchd.
    MacOs,
    /// Windows with Task Scheduler.
    Windows,
}

impl Os {
    /// The OS of this build.
    pub fn current() -> Self {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }
}

/// A command line: program and arguments.
pub type CmdLine = Vec<String>;

fn cmd(parts: &[&str]) -> CmdLine {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// Render the systemd user unit.
pub fn systemd_unit(exe: &Path) -> String {
    format!(
        "[Unit]\nDescription=Aivory Warden daemon\nAfter=default.target\n\n\
         [Service]\nType=simple\nExecStart=\"{}\" daemon\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n",
        exe.display()
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render the launchd agent plist.
pub fn launchd_plist(exe: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \x20 <key>Label</key><string>{LAUNCHD_LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>daemon</string>\n  </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         </dict>\n</plist>\n",
        xml_escape(&exe.to_string_lossy())
    )
}

/// Arguments of `schtasks` that create the logon task.
pub fn schtasks_create_args(exe: &Path) -> CmdLine {
    vec![
        "/Create".into(),
        "/SC".into(),
        "ONLOGON".into(),
        "/TN".into(),
        TASK_NAME.into(),
        "/TR".into(),
        format!("\"{}\" daemon", exe.display()),
        "/RL".into(),
        "LIMITED".into(),
        "/F".into(),
    ]
}

/// Path of the service definition file (none on Windows).
pub fn unit_path(os: Os, home: &Path) -> Option<PathBuf> {
    match os {
        Os::Linux => Some(
            home.join(".config")
                .join("systemd")
                .join("user")
                .join(SYSTEMD_UNIT),
        ),
        Os::MacOs => Some(
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist")),
        ),
        Os::Windows => None,
    }
}

/// What `service install` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// File to write: path and content.
    pub file: Option<(PathBuf, String)>,
    /// Commands to run after the file is written.
    pub commands: Vec<CmdLine>,
}

/// Plan the install. `uid` is the numeric user id (macOS only).
pub fn install_plan(os: Os, exe: &Path, home: &Path, uid: &str) -> InstallPlan {
    match os {
        Os::Linux => InstallPlan {
            file: unit_path(os, home).map(|p| (p, systemd_unit(exe))),
            commands: vec![
                cmd(&["systemctl", "--user", "daemon-reload"]),
                cmd(&["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT]),
            ],
        },
        Os::MacOs => {
            let file = unit_path(os, home);
            let target = format!("gui/{uid}");
            let plist = file
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            InstallPlan {
                file: file.map(|p| (p, launchd_plist(exe))),
                commands: vec![vec!["launchctl".into(), "bootstrap".into(), target, plist]],
            }
        }
        Os::Windows => {
            let mut c = vec!["schtasks".to_owned()];
            c.extend(schtasks_create_args(exe));
            InstallPlan {
                file: None,
                commands: vec![c, cmd(&["schtasks", "/Run", "/TN", TASK_NAME])],
            }
        }
    }
}

/// What `service uninstall` does. Run the commands first, then remove the file.
pub fn uninstall_plan(os: Os, home: &Path, uid: &str) -> (Vec<CmdLine>, Option<PathBuf>) {
    match os {
        Os::Linux => (
            vec![cmd(&[
                "systemctl",
                "--user",
                "disable",
                "--now",
                SYSTEMD_UNIT,
            ])],
            unit_path(os, home),
        ),
        Os::MacOs => (
            vec![vec![
                "launchctl".into(),
                "bootout".into(),
                format!("gui/{uid}/{LAUNCHD_LABEL}"),
            ]],
            unit_path(os, home),
        ),
        Os::Windows => (
            vec![cmd(&["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])],
            None,
        ),
    }
}

/// The command that reports the service state.
pub fn status_command(os: Os, uid: &str) -> CmdLine {
    match os {
        Os::Linux => cmd(&["systemctl", "--user", "is-active", SYSTEMD_UNIT]),
        Os::MacOs => vec![
            "launchctl".into(),
            "print".into(),
            format!("gui/{uid}/{LAUNCHD_LABEL}"),
        ],
        Os::Windows => cmd(&["schtasks", "/Query", "/TN", TASK_NAME]),
    }
}

fn run(c: &CmdLine) -> Result<std::process::Output> {
    std::process::Command::new(&c[0])
        .args(&c[1..])
        .output()
        .map_err(|e| WardenError::Config(format!("cannot run {}: {e}", c[0])))
}

fn run_ok(c: &CmdLine) -> Result<()> {
    let out = run(c)?;
    if out.status.success() {
        return Ok(());
    }
    Err(WardenError::Config(format!(
        "{} failed: {}",
        c.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .ok_or_else(|| WardenError::Config("cannot find the home directory".into()))
}

fn uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// Install the service for the current user.
pub fn install(exe: &Path) -> Result<()> {
    let os = Os::current();
    let plan = install_plan(os, exe, &home_dir()?, &uid());
    if let Some((path, text)) = &plan.file {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, text)?;
    }
    for c in &plan.commands {
        run_ok(c)?;
    }
    Ok(())
}

/// Remove the service for the current user.
pub fn uninstall() -> Result<()> {
    let os = Os::current();
    let (cmds, file) = uninstall_plan(os, &home_dir()?, &uid());
    for c in &cmds {
        // A service that is not installed is not an error.
        let _ = run(c);
    }
    if let Some(f) = file {
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Report the service state. Return true when the service is installed and active.
pub fn status() -> Result<(bool, String)> {
    let c = status_command(Os::current(), &uid());
    let out = run(&c)?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok((out.status.success(), text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_runs_daemon() {
        let u = systemd_unit(Path::new("/usr/bin/aivory-warden"));
        assert!(u.contains("ExecStart=\"/usr/bin/aivory-warden\" daemon"));
        assert!(u.contains("WantedBy=default.target"));
    }

    #[test]
    fn plist_has_label_and_args() {
        let p = launchd_plist(Path::new("/opt/a&b/aivory-warden"));
        assert!(p.contains("<string>net.aivory.warden</string>"));
        assert!(p.contains("<string>/opt/a&amp;b/aivory-warden</string>"));
        assert!(p.contains("<string>daemon</string>"));
    }

    #[test]
    fn schtasks_command_matches_spec() {
        let a = schtasks_create_args(Path::new(r"C:\Apps\aivory-warden.exe"));
        assert_eq!(
            a,
            [
                "/Create",
                "/SC",
                "ONLOGON",
                "/TN",
                "AivoryWarden",
                "/TR",
                "\"C:\\Apps\\aivory-warden.exe\" daemon",
                "/RL",
                "LIMITED",
                "/F"
            ]
        );
    }

    #[test]
    fn linux_plan() {
        let p = install_plan(
            Os::Linux,
            Path::new("/bin/awd"),
            Path::new("/home/u"),
            "1000",
        );
        let (path, _) = p.file.unwrap();
        assert!(path.ends_with(".config/systemd/user/aivory-warden.service"));
        assert_eq!(
            p.commands[1],
            [
                "systemctl",
                "--user",
                "enable",
                "--now",
                "aivory-warden.service"
            ]
        );
    }

    #[test]
    fn macos_plan() {
        let p = install_plan(
            Os::MacOs,
            Path::new("/bin/awd"),
            Path::new("/Users/u"),
            "501",
        );
        let (path, _) = p.file.unwrap();
        assert!(path.ends_with("Library/LaunchAgents/net.aivory.warden.plist"));
        assert_eq!(p.commands[0][..3], ["launchctl", "bootstrap", "gui/501"]);
        let (cmds, file) = uninstall_plan(Os::MacOs, Path::new("/Users/u"), "501");
        assert_eq!(
            cmds[0],
            ["launchctl", "bootout", "gui/501/net.aivory.warden"]
        );
        assert!(file.is_some());
    }

    #[test]
    fn windows_plan_and_status() {
        let p = install_plan(
            Os::Windows,
            Path::new(r"C:\a.exe"),
            Path::new(r"C:\Users\u"),
            "",
        );
        assert!(p.file.is_none());
        assert_eq!(p.commands[0][0], "schtasks");
        assert_eq!(
            status_command(Os::Windows, ""),
            ["schtasks", "/Query", "/TN", "AivoryWarden"]
        );
        let (cmds, _) = uninstall_plan(Os::Windows, Path::new("."), "");
        assert_eq!(
            cmds[0],
            ["schtasks", "/Delete", "/TN", "AivoryWarden", "/F"]
        );
    }
}
