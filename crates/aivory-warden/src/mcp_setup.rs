//! Connect AI tools to the Warden MCP server.
//!
//! The module finds the installed AI tools, adds the `aivory-warden` MCP server to the user
//! level config of a tool, and removes it again. Each tool gets its own pairing token. The
//! pairing store is a file, so the module does not need the daemon.
//!
//! Config formats:
//!
//! - JSON clients: only the `aivory-warden` key changes. Other keys keep their value. A file
//!   that is not plain JSON (for example JSON with comments) is never changed.
//! - Codex (TOML): `toml_edit` keeps comments and the order of the keys.
//! - Claude Code: the `claude` CLI does the change when it is on the `PATH`.
//!
//! Every write makes a `.bak` copy of the old file first, then writes atomically.

use crate::paths::Paths;
use crate::store::PairingFile;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use warden_core::ipc::Capability;
use warden_core::{Result, WardenError};
use warden_vault::fsutil::atomic_write;

/// Name of the entry in the config of a client.
pub const ENTRY: &str = "aivory-warden";

/// Operating system. Tests set it to check the paths of every system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Windows.
    Windows,
    /// macOS.
    Mac,
    /// Linux and other Unix systems.
    Linux,
}

impl Os {
    /// The system of this build.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Mac
        } else {
            Self::Linux
        }
    }
}

/// The places where the module looks for AI tools.
#[derive(Debug, Clone)]
pub struct Env {
    /// Operating system.
    pub os: Os,
    /// Home directory of the user.
    pub home: PathBuf,
    /// `%APPDATA%` (Windows only).
    pub appdata: Option<PathBuf>,
    /// Directories of the `PATH`.
    pub path_dirs: Vec<PathBuf>,
    /// Let Claude Code change its config with the `claude` CLI when it is on the `PATH`.
    pub use_cli: bool,
}

impl Env {
    /// The real environment of the current user.
    pub fn real() -> Result<Self> {
        let home = directories::UserDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .ok_or_else(|| WardenError::Config("cannot find the home directory".into()))?;
        Ok(Self {
            os: Os::current(),
            home,
            appdata: std::env::var_os("APPDATA").map(PathBuf::from),
            path_dirs: std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect())
                .unwrap_or_default(),
            use_cli: true,
        })
    }

    /// An environment below one directory. It has no `PATH` entries and no CLI.
    pub fn sandbox(os: Os, home: &Path) -> Self {
        Self {
            os,
            home: home.to_path_buf(),
            appdata: Some(home.join("AppData").join("Roaming")),
            path_dirs: Vec::new(),
            use_cli: false,
        }
    }

    fn appdata_dir(&self) -> PathBuf {
        self.appdata
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }

    /// Path of the CLI `name` when it is on the `PATH`.
    fn find_cli(&self, name: &str) -> Option<PathBuf> {
        let exts: &[&str] = if self.os == Os::Windows {
            &["exe", "cmd", "bat"]
        } else {
            &[""]
        };
        for d in &self.path_dirs {
            for e in exts {
                let f = if e.is_empty() {
                    d.join(name)
                } else {
                    d.join(format!("{name}.{e}"))
                };
                if f.is_file() {
                    return Some(f);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// JSON object with the servers below the key `mcpServers`.
    McpServers,
    /// JSON object with the servers below the key `servers`, `type` field required.
    Servers,
    /// TOML with `[mcp_servers.<name>]`.
    Toml,
}

/// One supported AI tool.
#[derive(Debug, Clone, Copy)]
pub struct Client {
    /// Short id for the command line.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    format: Format,
    /// The `type = "stdio"` field is required.
    typed: bool,
    /// CLI that marks the tool as installed.
    cli: Option<&'static str>,
}

const fn def(
    id: &'static str,
    name: &'static str,
    format: Format,
    typed: bool,
    cli: Option<&'static str>,
) -> Client {
    Client {
        id,
        name,
        format,
        typed,
        cli,
    }
}

/// Every supported client.
pub const CLIENTS: &[Client] = &[
    def(
        "claude-code",
        "Claude Code",
        Format::McpServers,
        false,
        Some("claude"),
    ),
    def(
        "claude-desktop",
        "Claude Desktop",
        Format::McpServers,
        false,
        None,
    ),
    def(
        "codex",
        "OpenAI Codex CLI",
        Format::Toml,
        false,
        Some("codex"),
    ),
    def(
        "gemini",
        "Gemini CLI",
        Format::McpServers,
        false,
        Some("gemini"),
    ),
    def(
        "antigravity",
        "Google Antigravity",
        Format::McpServers,
        false,
        None,
    ),
    def("cursor", "Cursor", Format::McpServers, true, None),
    def("vscode", "VS Code", Format::Servers, true, Some("code")),
    def("windsurf", "Windsurf", Format::McpServers, false, None),
];

/// Find a client by id.
pub fn client(id: &str) -> Result<&'static Client> {
    CLIENTS
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| WardenError::Config(format!("unknown client `{id}`")))
}

/// The state of one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Client id.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// The config dir or the CLI exists.
    pub installed: bool,
    /// The config holds the `aivory-warden` entry.
    pub connected: bool,
    /// The user level config file.
    pub config: PathBuf,
}

/// Result of `add` and `remove`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The entry was added.
    Added,
    /// The entry was there. Nothing changed.
    AlreadyConnected,
    /// The entry was removed.
    Removed,
    /// There was no entry. Nothing changed.
    NotConnected,
}

impl Client {
    /// The user level config file of this client.
    pub fn config_path(&self, env: &Env) -> PathBuf {
        let h = &env.home;
        match self.id {
            "claude-code" => h.join(".claude.json"),
            "claude-desktop" => match env.os {
                Os::Windows => env.appdata_dir().join("Claude"),
                Os::Mac => h.join("Library/Application Support/Claude"),
                Os::Linux => h.join(".config/Claude"),
            }
            .join("claude_desktop_config.json"),
            "codex" => h.join(".codex").join("config.toml"),
            "gemini" => h.join(".gemini").join("settings.json"),
            "antigravity" => h.join(".gemini").join("config").join("mcp_config.json"),
            "cursor" => h.join(".cursor").join("mcp.json"),
            "vscode" => match env.os {
                Os::Windows => env.appdata_dir().join("Code"),
                Os::Mac => h.join("Library/Application Support/Code"),
                Os::Linux => h.join(".config/Code"),
            }
            .join("User")
            .join("mcp.json"),
            _ => h.join(".codeium").join("windsurf").join("mcp_config.json"),
        }
    }

    /// The paths whose existence marks the tool as installed.
    fn markers(&self, env: &Env) -> Vec<PathBuf> {
        let h = &env.home;
        match self.id {
            "claude-code" => vec![h.join(".claude")],
            // The `~/.gemini` dir also belongs to Antigravity, so look for the settings file.
            "gemini" => vec![h.join(".gemini").join("settings.json")],
            "antigravity" => vec![
                h.join(".gemini").join("config"),
                h.join(".gemini").join("antigravity"),
            ],
            "cursor" => vec![h.join(".cursor")],
            "codex" => vec![h.join(".codex")],
            "windsurf" => vec![h.join(".codeium").join("windsurf")],
            _ => self
                .config_path(env)
                .parent()
                .map(|p| vec![p.to_path_buf()])
                .unwrap_or_default(),
        }
    }

    /// Return true when the tool is installed.
    pub fn installed(&self, env: &Env) -> bool {
        self.markers(env).iter().any(|d| d.exists())
            || self.cli.is_some_and(|c| env.find_cli(c).is_some())
    }

    /// Return true when the config holds the entry.
    pub fn connected(&self, env: &Env) -> bool {
        let path = self.config_path(env);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return false;
        };
        match self.format {
            Format::Toml => text
                .parse::<toml_edit::DocumentMut>()
                .ok()
                .is_some_and(|d| {
                    d.get("mcp_servers")
                        .and_then(|t| t.as_table_like())
                        .is_some_and(|t| t.contains_key(ENTRY))
                }),
            f => serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get(json_key(f)).and_then(|s| s.get(ENTRY)).cloned())
                .is_some(),
        }
    }
}

fn json_key(f: Format) -> &'static str {
    match f {
        Format::Servers => "servers",
        _ => "mcpServers",
    }
}

/// The state of every client. Installed clients come first.
pub fn list(env: &Env) -> Vec<Status> {
    let mut v: Vec<Status> = CLIENTS
        .iter()
        .map(|c| Status {
            id: c.id,
            name: c.name,
            installed: c.installed(env),
            connected: c.connected(env),
            config: c.config_path(env),
        })
        .collect();
    v.sort_by_key(|s| !s.installed); // stable: keeps the table order inside each group
    v
}

fn pairing_name(c: &Client) -> String {
    format!("mcp-{}", c.id)
}

fn entry_json(c: &Client, binary: &Path, token: &str) -> Value {
    let mut m = Map::new();
    if c.typed {
        m.insert("type".into(), json!("stdio"));
    }
    m.insert("command".into(), json!(binary.to_string_lossy()));
    m.insert("args".into(), json!(["mcp"]));
    m.insert("env".into(), json!({ "WARDEN_TOKEN": token }));
    Value::Object(m)
}

/// Copy the old file to `<file>.bak`, then write the new text atomically.
fn write_with_backup(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if path.exists() {
        let mut bak = path.as_os_str().to_owned();
        bak.push(".bak");
        std::fs::copy(path, PathBuf::from(bak))?;
    }
    atomic_write(path, text.as_bytes(), false)?;
    Ok(())
}

fn read_or_empty(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

fn parse_json(path: &Path, text: &str) -> Result<Value> {
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(WardenError::Config(format!(
            "{} is not a plain JSON object. Warden changed nothing. Edit the file by hand.",
            path.display()
        ))),
    }
}

fn json_add(c: &Client, path: &Path, binary: &Path, token: &str) -> Result<()> {
    let text = read_or_empty(path)?;
    let mut doc = parse_json(path, &text)?;
    let root = doc.as_object_mut().expect("checked object");
    let servers = root
        .entry(json_key(c.format))
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            WardenError::Config(format!("{}: server list is not an object", path.display()))
        })?;
    servers.insert(ENTRY.into(), entry_json(c, binary, token));
    write_with_backup(path, &(serde_json::to_string_pretty(&doc)? + "\n"))
}

fn json_remove(c: &Client, path: &Path) -> Result<bool> {
    let text = read_or_empty(path)?;
    let mut doc = parse_json(path, &text)?;
    let removed = doc
        .get_mut(json_key(c.format))
        .and_then(Value::as_object_mut)
        .and_then(|s| s.shift_remove(ENTRY))
        .is_some();
    if removed {
        write_with_backup(path, &(serde_json::to_string_pretty(&doc)? + "\n"))?;
    }
    Ok(removed)
}

fn toml_err(path: &Path, e: impl std::fmt::Display) -> WardenError {
    WardenError::Config(format!(
        "{} is not valid TOML ({e}). Warden changed nothing.",
        path.display()
    ))
}

fn toml_add(path: &Path, binary: &Path, token: &str) -> Result<()> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let text = read_or_empty(path)?;
    let mut doc: DocumentMut = text.parse().map_err(|e| toml_err(path, e))?;
    if !doc.contains_key("mcp_servers") {
        let mut t = Table::new();
        t.set_implicit(true);
        doc.insert("mcp_servers", Item::Table(t));
    }
    let servers = doc["mcp_servers"]
        .as_table_mut()
        .ok_or_else(|| toml_err(path, "mcp_servers is not a table"))?;
    let mut entry = Table::new();
    entry.insert("command", value(binary.to_string_lossy().as_ref()));
    let mut args = Array::new();
    args.push("mcp");
    entry.insert("args", value(args));
    let mut env = Table::new();
    env.insert("WARDEN_TOKEN", value(token));
    entry.insert("env", Item::Table(env));
    servers.insert(ENTRY, Item::Table(entry));
    write_with_backup(path, &doc.to_string())
}

fn toml_remove(path: &Path) -> Result<bool> {
    use toml_edit::DocumentMut;
    let text = read_or_empty(path)?;
    let mut doc: DocumentMut = text.parse().map_err(|e| toml_err(path, e))?;
    let removed = doc
        .get_mut("mcp_servers")
        .and_then(|i| i.as_table_like_mut())
        .and_then(|t| t.remove(ENTRY))
        .is_some();
    if removed {
        write_with_backup(path, &doc.to_string())?;
    }
    Ok(removed)
}

fn run_cli(cli: &Path, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cli)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(WardenError::Config(format!(
            "`claude` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn unpair_all(paths: &Paths, c: &Client) -> Result<bool> {
    let pf = PairingFile::new(paths.pairing_file());
    let name = pairing_name(c);
    let mut any = false;
    for k in pf.list()?.into_iter().filter(|k| k.name == name) {
        any |= pf.remove(&k.id)?;
    }
    Ok(any)
}

fn claude_cli(c: &Client, env: &Env) -> Option<PathBuf> {
    (c.id == "claude-code" && env.use_cli)
        .then(|| env.find_cli("claude"))
        .flatten()
}

/// Add the server to one client. Pair a new token first. Undo the pairing when the write fails.
pub fn add(env: &Env, paths: &Paths, id: &str, binary: &Path) -> Result<Outcome> {
    let c = client(id)?;
    if c.connected(env) {
        return Ok(Outcome::AlreadyConnected);
    }
    let path = c.config_path(env);
    unpair_all(paths, c)?; // a leftover pairing of an earlier run
    let pf = PairingFile::new(paths.pairing_file());
    let token = pf.add(&pairing_name(c), &[Capability::McpUse])?;
    let done = match (c.format, claude_cli(c, env)) {
        (_, Some(cli)) => {
            let bin = binary.to_string_lossy();
            let tok = format!("WARDEN_TOKEN={}", token.expose());
            run_cli(
                &cli,
                &[
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "--transport",
                    "stdio",
                    "-e",
                    &tok,
                    ENTRY,
                    "--",
                    &bin,
                    "mcp",
                ],
            )
        }
        (Format::Toml, None) => toml_add(&path, binary, token.expose()),
        (_, None) => json_add(c, &path, binary, token.expose()),
    };
    if let Err(e) = done {
        let _ = unpair_all(paths, c);
        return Err(e);
    }
    Ok(Outcome::Added)
}

/// Remove the entry of one client and unpair it.
pub fn remove(env: &Env, paths: &Paths, id: &str) -> Result<Outcome> {
    let c = client(id)?;
    let path = c.config_path(env);
    let removed = match (c.format, claude_cli(c, env)) {
        (_, Some(cli)) => {
            let was = c.connected(env);
            if was {
                run_cli(&cli, &["mcp", "remove", "--scope", "user", ENTRY])?;
            }
            was
        }
        (Format::Toml, None) => toml_remove(&path)?,
        (_, None) => json_remove(c, &path)?,
    };
    let unpaired = unpair_all(paths, c)?;
    Ok(if removed || unpaired {
        Outcome::Removed
    } else {
        Outcome::NotConnected
    })
}

/// The absolute path of the `aivory-warden` binary that clients start.
///
/// Order: the env var `AIVORY_WARDEN_BIN`, the file next to the running program, the running
/// program itself when it is `aivory-warden` or `awd`, then the `PATH`.
pub fn binary_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AIVORY_WARDEN_BIN").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let name = if cfg!(windows) {
        "aivory-warden.exe"
    } else {
        "aivory-warden"
    };
    let exe = std::env::current_exe()?;
    let sibling = exe.with_file_name(name);
    if sibling.is_file() {
        return Ok(sibling);
    }
    if matches!(
        exe.file_stem().and_then(|s| s.to_str()),
        Some("aivory-warden" | "awd")
    ) {
        return Ok(exe);
    }
    let found = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|f| f.is_file())
    });
    found.ok_or_else(|| WardenError::Config("cannot find the aivory-warden binary".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fx {
        _d: tempfile::TempDir,
        env: Env,
        paths: Paths,
    }

    fn fx(os: Os) -> Fx {
        let d = tempfile::tempdir().unwrap();
        let env = Env::sandbox(os, &d.path().join("home"));
        let paths = Paths::from_home(d.path().join("warden"));
        Fx { _d: d, env, paths }
    }

    const BIN: &str = "/opt/aivory-warden";

    fn pairs(f: &Fx) -> Vec<String> {
        PairingFile::new(f.paths.pairing_file())
            .list()
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect()
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn config_paths_per_os() {
        let h = Path::new("/h");
        let mut e = Env::sandbox(Os::Linux, h);
        let p = |e: &Env, id: &str| client(id).unwrap().config_path(e);
        assert_eq!(
            p(&e, "claude-desktop"),
            h.join(".config/Claude/claude_desktop_config.json")
        );
        assert_eq!(p(&e, "vscode"), h.join(".config/Code/User/mcp.json"));
        e.os = Os::Mac;
        assert_eq!(
            p(&e, "claude-desktop"),
            h.join("Library/Application Support/Claude/claude_desktop_config.json")
        );
        assert_eq!(
            p(&e, "vscode"),
            h.join("Library/Application Support/Code/User/mcp.json")
        );
        e.os = Os::Windows;
        e.appdata = Some(PathBuf::from("/ad"));
        assert_eq!(
            p(&e, "claude-desktop"),
            Path::new("/ad/Claude/claude_desktop_config.json")
        );
        assert_eq!(p(&e, "vscode"), Path::new("/ad/Code/User/mcp.json"));
        assert_eq!(p(&e, "codex"), h.join(".codex/config.toml"));
        assert_eq!(
            p(&e, "antigravity"),
            h.join(".gemini/config/mcp_config.json")
        );
    }

    #[test]
    fn detect_installed_first() {
        let f = fx(Os::Linux);
        std::fs::create_dir_all(f.env.home.join(".cursor")).unwrap();
        let l = list(&f.env);
        assert_eq!(l.len(), CLIENTS.len());
        assert_eq!(l[0].id, "cursor");
        assert!(l[0].installed && !l[0].connected);
        assert!(l[1..].iter().all(|s| !s.installed));
    }

    #[test]
    fn json_add_to_empty() {
        for id in [
            "cursor",
            "claude-desktop",
            "gemini",
            "antigravity",
            "windsurf",
            "vscode",
            "claude-code",
        ] {
            let f = fx(Os::Linux);
            let c = client(id).unwrap();
            let path = c.config_path(&f.env);
            assert_eq!(
                add(&f.env, &f.paths, id, Path::new(BIN)).unwrap(),
                Outcome::Added
            );
            let v = read_json(&path);
            let e = &v[json_key(c.format)][ENTRY];
            assert_eq!(e["command"], BIN);
            assert_eq!(e["args"], json!(["mcp"]));
            assert!(e["env"]["WARDEN_TOKEN"].as_str().unwrap().len() > 8);
            assert_eq!(e.get("type").is_some(), c.typed);
            assert_eq!(pairs(&f), vec![format!("mcp-{id}")]);
            assert!(c.connected(&f.env));
        }
    }

    #[test]
    fn json_add_keeps_other_servers_and_keys() {
        let f = fx(Os::Linux);
        let path = client("cursor").unwrap().config_path(&f.env);
        put(
            &path,
            r#"{"theme":"dark","mcpServers":{"other":{"command":"x"}}}"#,
        );
        add(&f.env, &f.paths, "cursor", Path::new(BIN)).unwrap();
        let v = read_json(&path);
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert!(v["mcpServers"][ENTRY].is_object());
        let bak = std::fs::read_to_string(format!("{}.bak", path.display())).unwrap();
        assert!(bak.contains("\"other\"") && !bak.contains(ENTRY));
    }

    #[test]
    fn second_add_is_noop() {
        let f = fx(Os::Linux);
        add(&f.env, &f.paths, "gemini", Path::new(BIN)).unwrap();
        let path = client("gemini").unwrap().config_path(&f.env);
        let before = std::fs::read(&path).unwrap();
        let n = pairs(&f).len();
        assert_eq!(
            add(&f.env, &f.paths, "gemini", Path::new(BIN)).unwrap(),
            Outcome::AlreadyConnected
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(pairs(&f).len(), n);
    }

    #[test]
    fn separate_token_per_client() {
        let f = fx(Os::Linux);
        add(&f.env, &f.paths, "gemini", Path::new(BIN)).unwrap();
        add(&f.env, &f.paths, "cursor", Path::new(BIN)).unwrap();
        assert_eq!(pairs(&f), vec!["mcp-gemini", "mcp-cursor"]);
        let tok = |id: &str| {
            let v = read_json(&client(id).unwrap().config_path(&f.env));
            v["mcpServers"][ENTRY]["env"]["WARDEN_TOKEN"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_ne!(tok("gemini"), tok("cursor"));
    }

    #[test]
    fn remove_deletes_only_our_entry_and_unpairs() {
        let f = fx(Os::Linux);
        let path = client("cursor").unwrap().config_path(&f.env);
        put(&path, r#"{"mcpServers":{"other":{"command":"x"}}}"#);
        add(&f.env, &f.paths, "cursor", Path::new(BIN)).unwrap();
        add(&f.env, &f.paths, "gemini", Path::new(BIN)).unwrap();
        assert_eq!(
            remove(&f.env, &f.paths, "cursor").unwrap(),
            Outcome::Removed
        );
        let v = read_json(&path);
        assert!(v["mcpServers"].get(ENTRY).is_none());
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(pairs(&f), vec!["mcp-gemini"]);
        assert_eq!(
            remove(&f.env, &f.paths, "cursor").unwrap(),
            Outcome::NotConnected
        );
    }

    #[test]
    fn toml_keeps_comments_and_other_servers() {
        let f = fx(Os::Linux);
        let path = client("codex").unwrap().config_path(&f.env);
        let old = "# my codex config\nmodel = \"x\" # inline\n\n[mcp_servers.other]\ncommand = \"y\" # keep\n";
        put(&path, old);
        assert_eq!(
            add(&f.env, &f.paths, "codex", Path::new(BIN)).unwrap(),
            Outcome::Added
        );
        let t = std::fs::read_to_string(&path).unwrap();
        assert!(t.contains("# my codex config") && t.contains("# inline") && t.contains("# keep"));
        assert!(t.contains("[mcp_servers.other]") && t.contains("[mcp_servers.aivory-warden]"));
        assert!(t.contains("args = [\"mcp\"]") && t.contains("WARDEN_TOKEN"));
        assert!(client("codex").unwrap().connected(&f.env));
        assert_eq!(
            std::fs::read_to_string(format!("{}.bak", path.display())).unwrap(),
            old
        );
        assert_eq!(
            add(&f.env, &f.paths, "codex", Path::new(BIN)).unwrap(),
            Outcome::AlreadyConnected
        );
        assert_eq!(remove(&f.env, &f.paths, "codex").unwrap(), Outcome::Removed);
        let t = std::fs::read_to_string(&path).unwrap();
        assert!(t.contains("# my codex config") && t.contains("# keep"));
        assert!(!t.contains("aivory-warden") && t.contains("[mcp_servers.other]"));
        assert!(pairs(&f).is_empty());
    }

    #[test]
    fn toml_add_to_empty() {
        let f = fx(Os::Windows);
        add(
            &f.env,
            &f.paths,
            "codex",
            Path::new("C:\\w\\aivory-warden.exe"),
        )
        .unwrap();
        let t = std::fs::read_to_string(client("codex").unwrap().config_path(&f.env)).unwrap();
        let d: toml_edit::DocumentMut = t.parse().unwrap();
        assert_eq!(
            d["mcp_servers"][ENTRY]["command"].as_str(),
            Some("C:\\w\\aivory-warden.exe")
        );
    }

    #[test]
    fn broken_config_is_not_changed() {
        let f = fx(Os::Linux);
        let path = client("vscode").unwrap().config_path(&f.env);
        put(&path, "// comment\n{\"servers\":{}}");
        assert!(add(&f.env, &f.paths, "vscode", Path::new(BIN)).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "// comment\n{\"servers\":{}}"
        );
        assert!(pairs(&f).is_empty(), "failed add must not leave a pairing");
    }

    #[test]
    fn unknown_client_is_error() {
        let f = fx(Os::Linux);
        assert!(add(&f.env, &f.paths, "nope", Path::new(BIN)).is_err());
    }
}
