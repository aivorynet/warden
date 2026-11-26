//! Service install for systemd (Linux), launchd (macOS) and the `HKCU` Run key (Windows).
//!
//! Windows uses the Run key because a logon task in Task Scheduler needs admin rights.
//!
//! The render functions are pure, so unit tests run on every OS.

use std::path::{Path, PathBuf};
use warden_core::{Result, WardenError};

/// Name of the systemd unit.
pub const SYSTEMD_UNIT: &str = "aivory-warden.service";
/// Label of the launchd agent.
pub const LAUNCHD_LABEL: &str = "net.aivory.warden";
/// Name of the autostart entry on Windows.
pub const TASK_NAME: &str = "AivoryWarden";
/// Registry key that holds the Windows autostart entries of the current user.
pub const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

static NAME_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Use another entry name on Windows (tests). Call it once, before any other function.
pub fn set_task_name(name: &str) {
    let _ = NAME_OVERRIDE.set(name.to_owned());
}

fn task_name() -> &'static str {
    NAME_OVERRIDE.get().map_or(TASK_NAME, String::as_str)
}

/// Target operating system of a service plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux with systemd.
    Linux,
    /// macOS with launchd.
    MacOs,
    /// Windows with the `HKCU` Run key.
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

/// Arguments of `reg` that create the Run entry for `name`.
pub fn reg_add_args(exe: &Path, name: &str) -> CmdLine {
    vec![
        "add".into(),
        RUN_KEY.into(),
        "/v".into(),
        name.into(),
        "/t".into(),
        "REG_SZ".into(),
        "/d".into(),
        format!("\"{}\" daemon", exe.display()),
        "/f".into(),
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

/// Image names of the daemon process on Windows: the binary and its alias.
/// PowerShell filter that stops only `daemon` processes of Warden, not `mcp` or the host.
fn windows_stop_daemon(pid: u32) -> String {
    format!(
        r"Get-CimInstance Win32_Process | Where-Object {{ ($_.Name -eq 'aivory-warden.exe' -or $_.Name -eq 'awd.exe') -and $_.CommandLine -match '\sdaemon(\s|$)' -and $_.ProcessId -ne {pid} }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
    )
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
                // `bootout` first: `bootstrap` fails when the job is already loaded.
                commands: vec![
                    vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{target}/{LAUNCHD_LABEL}"),
                    ],
                    vec!["launchctl".into(), "bootstrap".into(), target, plist],
                ],
            }
        }
        Os::Windows => {
            let mut c = vec!["reg".to_owned()];
            c.extend(reg_add_args(exe, task_name()));
            InstallPlan {
                file: None,
                commands: vec![c],
            }
        }
    }
}

/// What `service uninstall` does. Run the commands first, then remove the file.
///
/// `pid` is the id of the current process. On Windows the plan stops the daemon that install
/// started, and it never stops this process.
pub fn uninstall_plan(os: Os, home: &Path, uid: &str, pid: u32) -> (Vec<CmdLine>, Option<PathBuf>) {
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
        Os::Windows => {
            let stop = windows_stop_daemon(pid);
            let cmds = vec![
                cmd(&["reg", "delete", RUN_KEY, "/v", task_name(), "/f"]),
                // The daemon runs as the binary or as its alias. MCP servers keep running.
                cmd(&[
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &stop,
                ]),
            ];
            (cmds, None)
        }
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
        Os::Windows => cmd(&["reg", "query", RUN_KEY, "/v", task_name()]),
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
        if c.get(1).map(String::as_str) == Some("bootout") {
            let _ = run(c); // the job may not be loaded
        } else {
            run_ok(c)?;
        }
    }
    if os == Os::Windows {
        start_detached(exe)?;
    }
    Ok(())
}

/// Start the daemon now, without a console window (Windows has no service manager to do it).
///
/// `Start-Process` uses ShellExecute. The daemon does not inherit the pipes of this process,
/// so a caller that reads our output does not wait for the daemon.
#[cfg(windows)]
fn start_detached(exe: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "Start-Process -WindowStyle Hidden -FilePath '{}' -ArgumentList 'daemon'",
        exe.to_string_lossy().replace('\'', "''")
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| WardenError::Config(format!("cannot start the daemon: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(WardenError::Config(format!(
        "cannot start the daemon: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

#[cfg(not(windows))]
fn start_detached(_exe: &Path) -> Result<()> {
    Ok(())
}

/// Remove the service for the current user.
pub fn uninstall() -> Result<()> {
    let os = Os::current();
    let (cmds, file) = uninstall_plan(os, &home_dir()?, &uid(), std::process::id());
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
    fn reg_command_matches_spec() {
        let a = reg_add_args(Path::new(r"C:\Apps\aivory-warden.exe"), "AivoryWarden");
        assert_eq!(
            a,
            [
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "AivoryWarden",
                "/t",
                "REG_SZ",
                "/d",
                r#""C:\Apps\aivory-warden.exe" daemon"#,
                "/f"
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
        assert_eq!(
            p.commands[0],
            ["launchctl", "bootout", "gui/501/net.aivory.warden"]
        );
        assert_eq!(p.commands[1][..3], ["launchctl", "bootstrap", "gui/501"]);
        let (cmds, file) = uninstall_plan(Os::MacOs, Path::new("/Users/u"), "501", 7);
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
        assert_eq!(p.commands[0][0], "reg");
        assert_eq!(
            status_command(Os::Windows, ""),
            [
                "reg",
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "AivoryWarden"
            ]
        );
        let (cmds, _) = uninstall_plan(Os::Windows, Path::new("."), "", 4242);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1][0], "powershell");
        let script = &cmds[1][4];
        assert!(
            script.contains("daemon") && script.contains("-ne 4242"),
            "{script}"
        );
        assert!(script.contains("'awd.exe'") && script.contains("'aivory-warden.exe'"));
        assert_eq!(
            cmds[0],
            [
                "reg",
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "AivoryWarden",
                "/f"
            ]
        );
    }
}
