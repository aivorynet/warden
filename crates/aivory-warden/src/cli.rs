//! The command line: verbs, prompts and the mode switch (CLI, daemon, MCP, native host).

use crate::paths::Paths;
use crate::sinkspec::{self, SshDefaults};
use crate::store::{self, PairingFile};
use crate::{daemon, duration, service};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use warden_coffee::{CoffeeStore, THANKS_TEXT};
use warden_core::ipc::{Capability, ItemDraft, ItemStatus, ItemSummary, Request, Response};
use warden_core::{
    Clock, ItemId, ItemKind, McpPolicy, ProviderKind, ProviderRef, Result, RotationPolicy,
    SecretValue, SinkSpec, SystemClock, WardenError,
};
use warden_engine::TOKEN_SECRET;
use warden_ipc::Client;
use warden_vault::{KdfParams, SecretKey, Vault, keychain};

/// Aivory Warden: rotate access tokens and use them without handling them.
#[derive(Debug, Parser)]
#[command(name = "awd", version, arg_required_else_help = true)]
struct Cli {
    /// Vault directory (for `init`, `daemon` and `exec`). Point it to a synced folder to share a vault.
    #[arg(long, global = true, value_name = "DIR")]
    vault: Option<PathBuf>,
    /// Use a fast key derivation. Debug builds only. Never use it with a real vault.
    #[arg(long, global = true, hide = true)]
    insecure_fast_kdf: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once at start
enum Cmd {
    /// Create a vault, print the Emergency Kit and register this device.
    Init(InitArgs),
    /// Unlock the vault in the daemon.
    Unlock,
    /// Lock the vault in the daemon and remove the cached key.
    Lock,
    /// Show the daemon state and the tokens.
    Status,
    /// Add a token.
    Add(AddArgs),
    /// List the tokens.
    List,
    /// Show the metadata of one token (never the value).
    Show {
        /// Name or id of the token.
        name: String,
    },
    /// Rotate one token or all tokens now.
    Rotate {
        /// Name or id of the token.
        name: Option<String>,
        /// Rotate every token.
        #[arg(long, conflicts_with = "name")]
        all: bool,
    },
    /// Change the rotation policy.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Read or change the global settings.
    Settings {
        #[command(subcommand)]
        cmd: SettingsCmd,
    },
    /// Delete a token.
    Rm {
        /// Name or id of the token.
        name: String,
        /// Do not ask.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// List the inbox, or accept or reject an entry.
    Inbox {
        #[command(subcommand)]
        cmd: Option<InboxCmd>,
    },
    /// Pair a client (MCP server, native host), or list the paired clients.
    Pair(PairArgs),
    /// Remove a paired client (use the id from `awd pair --list`).
    Unpair {
        /// Client id (at least 8 characters).
        id: String,
    },
    /// List the devices of the vault.
    Devices,
    /// Show the audit log.
    Audit {
        /// Only this token.
        name: Option<String>,
        /// Maximum number of entries.
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Run a command with a token in an environment variable.
    Exec(ExecArgs),
    /// Show the coffee state, or enter a receipt code.
    Coffee {
        /// Receipt code.
        #[arg(long)]
        receipt: Option<String>,
    },
    /// Install or remove the background service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Install or remove the Edge and Chrome native messaging host.
    Extension {
        #[command(subcommand)]
        cmd: ExtensionCmd,
    },
    /// Run the MCP server on stdio (agents start this).
    Mcp,
    /// Run the background daemon.
    Daemon,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Join an existing vault (for example a synced folder) as a new device.
    #[arg(long)]
    join: bool,
    /// Name of this device.
    #[arg(long)]
    device_name: Option<String>,
    /// Sign the coffee pledge without a prompt (scripts and tests).
    #[arg(long)]
    pledge: bool,
    /// Read the vault password from the first line of stdin.
    #[arg(long)]
    password_stdin: bool,
    /// Print the result as one JSON object (no Emergency Kit text).
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AddArgs {
    #[command(flatten)]
    item: ItemArgs,
    /// Read the secret from the first line of stdin.
    #[arg(long)]
    secret_stdin: bool,
}

#[derive(Debug, Args, Default, Clone)]
struct ItemArgs {
    /// Display name.
    #[arg(long)]
    name: Option<String>,
    /// Short name for token names (default: the name in lower case).
    #[arg(long)]
    slug: Option<String>,
    /// Provider.
    #[arg(long, value_enum)]
    provider: Option<ProviderArg>,
    /// Provider configuration as JSON.
    #[arg(long, conflicts_with = "config_file")]
    config: Option<String>,
    /// Provider configuration in a JSON file.
    #[arg(long)]
    config_file: Option<PathBuf>,
    /// End date of the token (YYYY-MM-DD).
    #[arg(long)]
    expires: Option<String>,
    /// Rotation interval, for example 30d.
    #[arg(long)]
    interval: Option<String>,
    /// Rotate this long before the end date, for example 7d.
    #[arg(long)]
    lead: Option<String>,
    /// Wait this long before the old token is revoked, for example 1d.
    #[arg(long)]
    grace: Option<String>,
    /// Automatic rotation.
    #[arg(long, value_enum)]
    auto: Option<OnOff>,
    /// A place that receives the token. Repeat the flag for more places.
    /// Forms: dotenv:PATH:KEY, json:PATH:/ptr, toml:PATH:a.b, yaml:PATH:a.b,
    /// ssh:user@host:/path:toml:a.b, env:NAME
    #[arg(long = "sink", value_name = "SPEC")]
    sinks: Vec<String>,
    /// Name of the admin token that creates this token (makes a derived token).
    #[arg(long)]
    parent: Option<String>,
    /// Host that MCP clients may send this token to. Repeat for more hosts.
    #[arg(long = "mcp-host", value_name = "HOST")]
    mcp_hosts: Vec<String>,
    /// Tag. Repeat for more tags.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// SSH private key for `ssh:` sinks (default: ~/.ssh/id_ed25519).
    #[arg(long)]
    ssh_identity: Option<PathBuf>,
    /// known_hosts file for `ssh:` sinks (default: ~/.ssh/known_hosts).
    #[arg(long)]
    ssh_known_hosts: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProviderArg {
    Gitlab,
    AwsIam,
    Cloudflare,
    Openai,
    Command,
    Manual,
}

impl ProviderArg {
    const ALL: [(&'static str, ProviderArg); 6] = [
        ("gitlab", ProviderArg::Gitlab),
        ("aws-iam", ProviderArg::AwsIam),
        ("cloudflare", ProviderArg::Cloudflare),
        ("openai", ProviderArg::Openai),
        ("command", ProviderArg::Command),
        ("manual", ProviderArg::Manual),
    ];

    fn kind(self) -> ProviderKind {
        match self {
            ProviderArg::Gitlab => ProviderKind::GitLab,
            ProviderArg::AwsIam => ProviderKind::AwsIam,
            ProviderArg::Cloudflare => ProviderKind::Cloudflare,
            ProviderArg::Openai => ProviderKind::OpenAi,
            ProviderArg::Command => ProviderKind::Command,
            ProviderArg::Manual => ProviderKind::Manual,
        }
    }

    fn from_hint(h: &str) -> Option<Self> {
        let h = h.to_ascii_lowercase();
        Self::ALL
            .iter()
            .find(|(n, _)| h.contains(n))
            .map(|(_, p)| *p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Debug, Subcommand)]
enum PolicyCmd {
    /// Set interval, lead time, grace time or automatic rotation.
    Set {
        /// Name or id of the token.
        name: String,
        /// Rotation interval, for example 14d.
        #[arg(long)]
        interval: Option<String>,
        /// Rotate this long before the end date, for example 7d.
        #[arg(long)]
        lead: Option<String>,
        /// Wait this long before the old token is revoked.
        #[arg(long)]
        grace: Option<String>,
        /// Automatic rotation.
        #[arg(long, value_enum)]
        auto: Option<OnOff>,
    },
}

#[derive(Debug, Subcommand)]
enum SettingsCmd {
    /// Show the settings.
    Show,
    /// Change one setting: default-interval, coffee-reminder, keychain-cache.
    Set {
        /// Setting name.
        key: String,
        /// New value (for example 30d, or on and off).
        value: String,
    },
}

#[derive(Debug, Subcommand)]
enum InboxCmd {
    /// Accept an entry as a new token. The flags are the same as for `add`.
    Accept(Box<AcceptArgs>),
    /// Reject an entry.
    Reject {
        /// Id (or the start of the id) of the entry.
        id: String,
    },
}

#[derive(Debug, Args)]
struct AcceptArgs {
    /// Id (or the start of the id) of the entry.
    id: String,
    #[command(flatten)]
    item: ItemArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CapArg {
    Mcp,
    McpAdmin,
    Inbox,
}

#[derive(Debug, Args)]
struct PairArgs {
    /// Name of the client.
    #[arg(required_unless_present = "list")]
    name: Option<String>,
    /// List the paired clients instead of pairing one.
    #[arg(long, conflicts_with_all = ["name", "save"])]
    list: bool,
    /// Capability: mcp, mcp-admin or inbox. Repeat for more.
    #[arg(long = "cap", value_enum, default_value = "mcp")]
    caps: Vec<CapArg>,
    /// Save the token as the default token of `awd mcp`.
    #[arg(long)]
    save: bool,
}

#[derive(Debug, Args)]
struct ExecArgs {
    /// Name or id of the token.
    name: String,
    /// Environment variable that receives the token (default: the slug in upper case).
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// Command and arguments (after `--`).
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum ServiceCmd {
    /// Install and start the service.
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Show the service state.
    Status,
}

#[derive(Debug, Subcommand)]
enum ExtensionCmd {
    /// Register the native messaging host for the extension.
    Install {
        /// Extension id (32 letters from a to p).
        #[arg(long)]
        id: String,
    },
    /// Remove the registration.
    Uninstall,
}

struct Ctx {
    paths: Paths,
    vault: Option<PathBuf>,
    fast_kdf: bool,
}

type Code = Result<u8>;

fn cfg_err(msg: impl Into<String>) -> WardenError {
    WardenError::Config(msg.into())
}

fn init_logging(daemon: bool) {
    let level = match std::env::var("WARDEN_LOG").as_deref() {
        Ok("debug") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        Ok("error") => tracing::Level::ERROR,
        Ok("warn") => tracing::Level::WARN,
        _ if daemon => tracing::Level::INFO,
        _ => tracing::Level::WARN,
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(level)
        .try_init();
}

/// Entry point for both binaries.
pub fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let native = argv
        .get(1)
        .is_some_and(|a| a.to_string_lossy().starts_with("chrome-extension://"));
    let result = (|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(WardenError::Io)?;
        let paths = Paths::discover()?;
        if native {
            init_logging(false);
            return rt.block_on(native_host(&paths));
        }
        let cli = Cli::parse_from(argv);
        let note_verb = matches!(cli.cmd, Cmd::Status | Cmd::List | Cmd::Rotate { .. });
        init_logging(matches!(cli.cmd, Cmd::Daemon));
        let ctx = Ctx {
            paths,
            vault: cli.vault,
            fast_kdf: cli.insecure_fast_kdf,
        };
        let code = rt.block_on(run(&ctx, cli.cmd))?;
        if note_verb {
            coffee_note(&ctx.paths);
        }
        Ok(code)
    })();
    match result {
        Ok(c) => ExitCode::from(c),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run(ctx: &Ctx, cmd: Cmd) -> Code {
    match cmd {
        Cmd::Init(a) => init(ctx, a).await,
        Cmd::Unlock => unlock(ctx).await,
        Cmd::Lock => simple(ctx, Request::Lock, "vault locked").await,
        Cmd::Status => status(ctx).await,
        Cmd::Add(a) => add(ctx, a).await,
        Cmd::List => list(ctx).await,
        Cmd::Show { name } => show(ctx, &name).await,
        Cmd::Rotate { name, all } => rotate(ctx, name, all).await,
        Cmd::Policy { cmd } => policy(ctx, cmd).await,
        Cmd::Settings { cmd } => settings(ctx, cmd).await,
        Cmd::Rm { name, yes } => rm(ctx, &name, yes).await,
        Cmd::Inbox { cmd } => inbox(ctx, cmd).await,
        Cmd::Pair(a) => pair(ctx, a).await,
        Cmd::Unpair { id } => unpair(ctx, &id).await,
        Cmd::Devices => devices(ctx).await,
        Cmd::Audit { name, limit } => audit(ctx, name, limit).await,
        Cmd::Exec(a) => exec(ctx, a),
        Cmd::Coffee { receipt } => coffee(ctx, receipt).await,
        Cmd::Service { cmd } => service_cmd(cmd),
        Cmd::Extension { cmd } => extension(ctx, cmd),
        Cmd::Mcp => mcp(ctx).await,
        Cmd::Daemon => {
            daemon::run(ctx.paths.clone(), ctx.vault.clone()).await?;
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------- client helpers

async fn connect(paths: &Paths) -> Result<Client> {
    let token = store::read_token(&paths.cli_token())
        .map_err(|_| cfg_err("no CLI token yet. Run `awd init` first"))?;
    Client::connect(paths.endpoint().as_deref(), Some(&token))
        .await
        .map_err(|e| {
            cfg_err(format!(
                "cannot reach the daemon ({e}). Start it with `awd daemon` or `awd service install`"
            ))
        })
}

/// Send a request. An error response becomes an `Err`.
async fn call(c: &mut Client, req: Request) -> Result<Response> {
    match c.call(req).await? {
        Response::Error { code, message } => Err(WardenError::Ipc(format!("{message} [{code}]"))),
        r => Ok(r),
    }
}

fn unexpected() -> WardenError {
    WardenError::Ipc("unexpected answer from the daemon".into())
}

async fn simple(ctx: &Ctx, req: Request, ok: &str) -> Code {
    let mut c = connect(&ctx.paths).await?;
    call(&mut c, req).await?;
    println!("\u{2713} {ok}");
    Ok(0)
}

async fn items(c: &mut Client) -> Result<Vec<ItemSummary>> {
    match call(c, Request::ListItems).await? {
        Response::Items { items } => Ok(items),
        _ => Err(unexpected()),
    }
}

async fn resolve(c: &mut Client, name: &str) -> Result<ItemSummary> {
    let all = items(c).await?;
    let exact: Vec<&ItemSummary> = all
        .iter()
        .filter(|i| i.name.eq_ignore_ascii_case(name) || i.id.to_string() == name)
        .collect();
    if let [one] = exact.as_slice() {
        return Ok((*one).clone());
    }
    let prefix: Vec<&ItemSummary> = all
        .iter()
        .filter(|i| name.len() >= 6 && i.id.to_string().starts_with(name))
        .collect();
    match prefix.as_slice() {
        [one] => Ok((*one).clone()),
        [] if exact.is_empty() => Err(WardenError::NotFound(format!("token `{name}`"))),
        _ => Err(cfg_err(format!("`{name}` matches more than one token"))),
    }
}

async fn get_item(c: &mut Client, id: ItemId) -> Result<warden_core::Item> {
    match call(c, Request::GetItem { item: id }).await? {
        Response::Item(i) => Ok(*i),
        _ => Err(unexpected()),
    }
}

// ---------------------------------------------------------------- output helpers

fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<w$}", w = widths[i]))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

fn rel(t: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    let Some(t) = t else { return "-".into() };
    let d = t - now;
    if d <= chrono::TimeDelta::zero() {
        "due".into()
    } else if d.num_days() >= 1 {
        format!("in {}d", d.num_days())
    } else if d.num_hours() >= 1 {
        format!("in {}h", d.num_hours())
    } else {
        format!("in {}m", d.num_minutes().max(1))
    }
}

fn provider_name(k: ProviderKind) -> &'static str {
    match k {
        ProviderKind::GitLab => "gitlab",
        ProviderKind::AwsIam => "aws-iam",
        ProviderKind::Cloudflare => "cloudflare",
        ProviderKind::OpenAi => "openai",
        ProviderKind::Command => "command",
        ProviderKind::Manual => "manual",
    }
}

fn item_status(s: &ItemSummary, now: DateTime<Utc>) -> &'static str {
    match s.status {
        ItemStatus::Failed => "failed",
        ItemStatus::Rotating => "rotating",
        _ if s.expires_at.is_some_and(|e| e <= now) => "expired",
        ItemStatus::Reminder => "reminder",
        _ if !s.auto_rotate => "manual",
        ItemStatus::Due => "due",
        ItemStatus::Healthy => "healthy",
    }
}

fn items_table(all: &[ItemSummary]) -> String {
    let now = SystemClock.now();
    let mut rows = vec![
        ["NAME", "PROVIDER", "STATUS", "NEXT", "EXPIRES", "PLACES"]
            .map(String::from)
            .to_vec(),
    ];
    for i in all {
        rows.push(vec![
            i.name.clone(),
            provider_name(i.provider).into(),
            item_status(i, now).into(),
            rel(i.next_rotation, now),
            i.expires_at
                .map_or("-".into(), |e| e.date_naive().to_string()),
            i.sink_count.to_string(),
        ]);
    }
    table(&rows)
}

fn sink_label(s: &SinkSpec) -> String {
    match s {
        SinkSpec::Dotenv { path, key } => format!("{} {key}", path.display()),
        SinkSpec::Json { path, pointer } => format!("{} {pointer}", path.display()),
        SinkSpec::Toml { path, key_path } | SinkSpec::Yaml { path, key_path } => {
            format!("{} {}", path.display(), key_path.join("."))
        }
        SinkSpec::Regex { path, .. } => format!("{} (regex)", path.display()),
        SinkSpec::Ssh {
            user,
            host,
            remote_path,
            ..
        } => format!("{user}@{host}:{remote_path}"),
        SinkSpec::EnvVar { name } => format!("env {name}"),
    }
}

fn dots(label: &str) -> String {
    let pad = 52usize.saturating_sub(label.chars().count()).max(3);
    format!("{label} {}", ".".repeat(pad))
}

// ---------------------------------------------------------------- prompts

fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

fn env_secret(var: &str) -> Option<SecretValue> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretValue::new)
}

fn prompt_secret(var: &str, prompt: &str, confirm: bool) -> Result<SecretValue> {
    if let Some(v) = env_secret(var) {
        return Ok(v);
    }
    if !interactive() {
        return Err(cfg_err(format!("no terminal. Set {var} for scripts")));
    }
    let first = rpassword::prompt_password(prompt).map_err(WardenError::Io)?;
    if first.is_empty() {
        return Err(cfg_err("empty input"));
    }
    if confirm {
        let again = rpassword::prompt_password("Repeat: ").map_err(WardenError::Io)?;
        if again != first {
            return Err(cfg_err("the two entries differ"));
        }
    }
    Ok(SecretValue::new(first))
}

fn ask(prompt: &str, default: Option<String>, allow_empty: bool) -> Result<String> {
    let mut i = dialoguer::Input::<String>::new()
        .with_prompt(prompt)
        .allow_empty(allow_empty);
    if let Some(d) = default {
        i = i.default(d);
    }
    i.interact_text().map_err(|e| cfg_err(e.to_string()))
}

// ---------------------------------------------------------------- init, unlock

fn local_vault_dir(ctx: &Ctx) -> Result<PathBuf> {
    match &ctx.vault {
        Some(p) => std::path::absolute(p).map_err(WardenError::Io),
        None => store::vault_dir(&ctx.paths),
    }
}

fn device_name_default() -> String {
    let name = gethostname::gethostname()
        .to_string_lossy()
        .trim()
        .to_owned();
    if name.is_empty() {
        "device".into()
    } else {
        name
    }
}

/// Read a secret from the first line of stdin.
fn stdin_secret() -> Result<SecretValue> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(WardenError::Io)?;
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(cfg_err("empty password on stdin"));
    }
    Ok(SecretValue::new(line))
}

fn ensure_cli_token(paths: &Paths) -> Result<()> {
    let pairing = PairingFile::new(paths.pairing_file());
    if pairing.token_file_valid(&paths.cli_token()) {
        return Ok(());
    }
    let t = pairing.add("cli", &[Capability::Full])?;
    store::write_token(&paths.cli_token(), &t)
}

fn emergency_kit(dir: &Path, device: &str, sk: &SecretKey) -> String {
    format!(
        "AIVORY WARDEN - EMERGENCY KIT\n\
         -----------------------------\n\
         Vault:       {}\n\
         Device:      {device}\n\
         Secret Key:  {sk}\n\
         \n\
         Keep this page in a safe place, on paper or in a password manager.\n\
         The Secret Key and your password together open the vault on a new device.\n\
         Warden does not store your password. Nobody can recover the vault without both.\n",
        dir.display()
    )
}

/// Show the coffee pledge and record the signature. Nothing is created before it is signed.
fn sign_pledge_flow(ctx: &Ctx, flag: bool, quiet: bool) -> Result<()> {
    let store = CoffeeStore::new(ctx.paths.settings_file());
    let mut st = store.load().map_err(|e| cfg_err(e.to_string()))?;
    if warden_coffee::is_pledged(&st) {
        return Ok(());
    }
    if !quiet {
        println!("The coffee pledge\n-----------------");
        println!("{}", warden_coffee::PLEDGE_TEXT);
        println!("Price: {}", warden_coffee::PRICE_LABEL);
        println!("{}\n", warden_coffee::HONEST_LINE);
    }
    if !flag {
        if !interactive() {
            return Err(cfg_err(
                "sign the pledge with --pledge when there is no terminal",
            ));
        }
        let a = ask("Type 'deal' to sign", None, true)?;
        if a.trim() != "deal" {
            return Err(cfg_err("pledge not signed. Nothing was created"));
        }
    }
    let user = ["USERNAME", "USER"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown".into());
    warden_coffee::sign_pledge(&mut st, &user, &SystemClock);
    store.save(&st).map_err(|e| cfg_err(e.to_string()))
}

async fn init(ctx: &Ctx, a: InitArgs) -> Code {
    let dir = local_vault_dir(ctx)?;
    std::fs::create_dir_all(&ctx.paths.config)?;
    std::fs::create_dir_all(&ctx.paths.data)?;
    let exists = dir.join("header.json").exists();
    if exists && !a.join {
        return Err(cfg_err(format!(
            "a vault exists in {}. Use `awd init --join` to add this device, or `awd unlock`",
            dir.display()
        )));
    }
    if !exists && a.join {
        return Err(cfg_err(format!("no vault in {}", dir.display())));
    }
    let fast = ctx.fast_kdf && cfg!(debug_assertions);
    if ctx.fast_kdf && !fast {
        eprintln!("warning: --insecure-fast-kdf is ignored in release builds");
    }
    sign_pledge_flow(ctx, a.pledge, a.json)?;
    let device = a.device_name.unwrap_or_else(device_name_default);
    let password = if a.password_stdin {
        stdin_secret()?
    } else {
        prompt_secret("WARDEN_PASSWORD", "Vault password: ", !a.join)?
    };
    if !fast && password.expose().chars().count() < 8 {
        return Err(cfg_err("the password needs at least 8 characters"));
    }
    let local = ctx.paths.device_dir();
    let (vault, sk) = if a.join {
        let sk_in = prompt_secret("WARDEN_SECRET_KEY", "Secret Key: ", false)?;
        let sk: SecretKey = sk_in.expose().parse()?;
        (
            Vault::join(&dir, password.expose(), &sk, &device, &local)?,
            sk,
        )
    } else {
        let kdf = if fast {
            KdfParams::new(64, 1, 1)
        } else {
            KdfParams::DEFAULT
        };
        Vault::create_with_params(&dir, password.expose(), None, &device, &local, kdf)?
    };
    std::fs::write(ctx.paths.device_id_file(), vault.device_id().to_string())?;
    let ticket = warden_coffee::ticket_no(
        &vault.device_id().to_string(),
        chrono::Datelike::year(&Utc::now()),
    );
    drop(vault);
    if ctx.vault.is_some() || dir != ctx.paths.default_vault() {
        store::set_vault_dir(&ctx.paths, &dir)?;
    }
    ensure_cli_token(&ctx.paths)?;
    if !a.json {
        print!("{}", emergency_kit(&dir, &device, &sk));
        println!("Coffee ticket: {ticket}");
    }
    let outcome: std::result::Result<(), String> = match connect(&ctx.paths).await {
        Ok(mut c) => {
            let req = Request::Unlock {
                password: password.clone(),
                secret_key: SecretValue::new(sk.to_string()),
            };
            call(&mut c, req)
                .await
                .map(|_| ())
                .map_err(|e| format!("The daemon did not unlock: {e}"))
        }
        Err(_) => Err(
            "Start the daemon with `awd daemon` (or `awd service install`), then run `awd unlock`."
                .into(),
        ),
    };
    if a.json {
        let out = serde_json::json!({
            "secret_key": sk.to_string(),
            "vault": dir.display().to_string(),
            "device": device,
            "ticket": ticket,
            "unlocked": outcome.is_ok(),
        });
        println!("{out}");
    } else {
        match outcome {
            Ok(()) => println!("\n\u{2713} this device is registered and the daemon is unlocked"),
            Err(m) => println!("\nThis device is registered. {m}"),
        }
    }
    Ok(0)
}

async fn unlock(ctx: &Ctx) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let password = prompt_secret("WARDEN_PASSWORD", "Vault password: ", false)?;
    let sk = prompt_secret("WARDEN_SECRET_KEY", "Secret Key: ", false)?;
    call(
        &mut c,
        Request::Unlock {
            password,
            secret_key: sk,
        },
    )
    .await?;
    println!("\u{2713} vault unlocked");
    Ok(0)
}

// ---------------------------------------------------------------- status, list, show

async fn status(ctx: &Ctx) -> Code {
    let mut c = match connect(&ctx.paths).await {
        Ok(c) => c,
        Err(e) => {
            println!("\u{25CB} daemon not reachable: {e}");
            return Ok(1);
        }
    };
    let Response::Status(s) = call(&mut c, Request::Status).await? else {
        return Err(unexpected());
    };
    let dev = s.device_id.to_string();
    let state = if s.locked {
        "vault locked"
    } else {
        "vault unlocked"
    };
    println!(
        "\u{25CF} daemon running \u{00B7} {state} \u{00B7} device {} \u{00B7} {} tokens{}",
        &dev[..8],
        s.item_count,
        if s.inbox_count > 0 {
            format!(" \u{00B7} {} in inbox", s.inbox_count)
        } else {
            String::new()
        }
    );
    if let Ok(Response::Coffee(i)) = call(&mut c, Request::CoffeeStatus).await {
        match i.paid_year {
            Some(y) => println!("coffee: paid {y}"),
            None => println!("coffee: not paid this year (ticket {})", i.ticket),
        }
    }
    if !s.locked {
        print!("{}", items_table(&items(&mut c).await?));
    }
    Ok(0)
}

async fn list(ctx: &Ctx) -> Code {
    let mut c = connect(&ctx.paths).await?;
    print!("{}", items_table(&items(&mut c).await?));
    Ok(0)
}

async fn show(ctx: &Ctx, name: &str) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let s = resolve(&mut c, name).await?;
    let i = get_item(&mut c, s.id).await?;
    let kind = match i.kind {
        ItemKind::Admin => "admin".to_owned(),
        ItemKind::Derived { parent } => format!("derived from {parent}"),
    };
    let date = |d: Option<DateTime<Utc>>| d.map_or("-".into(), |d| d.to_rfc3339());
    println!("name:        {}", i.name);
    println!("id:          {}", i.id);
    println!("slug:        {}", i.slug);
    println!("kind:        {kind}");
    println!("provider:    {}", provider_name(i.provider.kind));
    println!(
        "token id:    {}",
        i.provider_token_id.as_deref().unwrap_or("-")
    );
    println!("expires:     {}", date(i.expires_at));
    println!("created:     {}", date(Some(i.created_at)));
    println!("rotated:     {}", date(i.rotated_at));
    println!("next:        {}", date(s.next_rotation));
    println!(
        "policy:      auto {} \u{00B7} interval {} \u{00B7} lead {} \u{00B7} grace {}",
        if i.policy.auto_rotate { "on" } else { "off" },
        i.policy.interval.map_or("default".into(), duration::format),
        duration::format(i.policy.lead_time),
        duration::format(i.policy.grace),
    );
    println!("mcp hosts:   {}", i.mcp.allowed_hosts.join(", "));
    println!("tags:        {}", i.tags.join(", "));
    println!("places:");
    for s in &i.sinks {
        println!("  {}", sink_label(s));
    }
    Ok(0)
}

// ---------------------------------------------------------------- add

fn slugify(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    s.trim_matches('-').to_owned()
}

fn parse_expires(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| t.and_utc())
        .ok_or_else(|| cfg_err(format!("bad date `{s}` (use YYYY-MM-DD)")))
}

fn ssh_defaults(a: &ItemArgs) -> SshDefaults {
    let ssh_dir = directories::BaseDirs::new()
        .map(|b| b.home_dir().join(".ssh"))
        .unwrap_or_else(|| PathBuf::from(".ssh"));
    SshDefaults {
        identity_file: a
            .ssh_identity
            .clone()
            .unwrap_or_else(|| ssh_dir.join("id_ed25519")),
        known_hosts: a
            .ssh_known_hosts
            .clone()
            .unwrap_or_else(|| ssh_dir.join("known_hosts")),
    }
}

fn apply_policy(
    p: &mut RotationPolicy,
    interval: &Option<String>,
    lead: &Option<String>,
    grace: &Option<String>,
    auto: Option<OnOff>,
) -> Result<()> {
    if let Some(v) = interval {
        let d = duration::parse(v)?;
        if d.is_zero() {
            return Err(cfg_err("interval must be more than 0"));
        }
        p.interval = Some(d);
    }
    if let Some(v) = lead {
        p.lead_time = duration::parse(v)?;
    }
    if let Some(v) = grace {
        p.grace = duration::parse(v)?;
    }
    if let Some(a) = auto {
        p.auto_rotate = a == OnOff::On;
    }
    Ok(())
}

/// Build the item draft from flags. Missing values are asked for when a terminal exists.
async fn build_draft(
    c: &mut Client,
    mut a: ItemArgs,
    hint_name: Option<String>,
    hint_provider: Option<ProviderArg>,
    hint_expires: Option<DateTime<Utc>>,
) -> Result<ItemDraft> {
    let tty = interactive();
    let name = match a.name.take().or(hint_name.clone()) {
        Some(n) if !tty || a.name.is_some() || hint_name.is_none() => n,
        Some(n) => ask("Name", Some(n), false)?,
        None if tty => ask("Name", None, false)?,
        None => return Err(cfg_err("missing --name")),
    };
    let provider = match a.provider.or(hint_provider) {
        Some(p) => p,
        None if tty => {
            let names: Vec<&str> = ProviderArg::ALL.iter().map(|(n, _)| *n).collect();
            let i = dialoguer::Select::new()
                .with_prompt("Provider")
                .items(&names)
                .default(0)
                .interact()
                .map_err(|e| cfg_err(e.to_string()))?;
            ProviderArg::ALL[i].1
        }
        None => return Err(cfg_err("missing --provider")),
    };
    let slug = a.slug.take().unwrap_or_else(|| slugify(&name));
    let config = match (&a.config, &a.config_file) {
        (Some(s), _) => serde_json::from_str(s)?,
        (None, Some(f)) => serde_json::from_slice(&std::fs::read(f)?)?,
        (None, None) if tty && matches!(provider, ProviderArg::Command | ProviderArg::AwsIam) => {
            let s = ask("Provider config as JSON (empty for none)", None, true)?;
            if s.trim().is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str(&s)?
            }
        }
        (None, None) => serde_json::json!({}),
    };
    if !config.is_object() {
        return Err(cfg_err("the provider config must be a JSON object"));
    }
    let expires_at = match &a.expires {
        Some(s) => Some(parse_expires(s)?),
        None if tty && hint_expires.is_none() => {
            let s = ask("End date YYYY-MM-DD (empty for none)", None, true)?;
            if s.trim().is_empty() {
                None
            } else {
                Some(parse_expires(s.trim())?)
            }
        }
        None => hint_expires,
    };
    let ssh = ssh_defaults(&a);
    let mut sink_specs = a.sinks.clone();
    if sink_specs.is_empty() && tty {
        loop {
            let s = ask(
                "Place for the token (kind:path:key, empty to finish)",
                None,
                true,
            )?;
            if s.trim().is_empty() {
                break;
            }
            sink_specs.push(s.trim().to_owned());
        }
    }
    let sinks = sink_specs
        .iter()
        .map(|s| sinkspec::parse(s, &ssh))
        .collect::<Result<Vec<_>>>()?;
    let kind = match &a.parent {
        Some(p) => ItemKind::Derived {
            parent: resolve(c, p).await?.id,
        },
        None => ItemKind::Admin,
    };
    let mut policy = RotationPolicy::default();
    apply_policy(&mut policy, &a.interval, &a.lead, &a.grace, a.auto)?;
    let mcp = McpPolicy {
        allowed_hosts: a.mcp_hosts.clone(),
        ..McpPolicy::default()
    };
    Ok(ItemDraft {
        name,
        slug,
        kind,
        provider: ProviderRef {
            kind: provider.kind(),
            config,
        },
        expires_at,
        policy,
        sinks,
        mcp,
        tags: a.tags.clone(),
    })
}

fn read_secret_stdin() -> Result<SecretValue> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let v = line.trim_end_matches(['\r', '\n']);
    if v.is_empty() {
        return Err(cfg_err("the secret on stdin is empty"));
    }
    Ok(SecretValue::new(v))
}

async fn add(ctx: &Ctx, a: AddArgs) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let derived = a.item.parent.is_some();
    let draft = build_draft(&mut c, a.item, None, None, None).await?;
    let secret = if derived {
        SecretValue::new("")
    } else if a.secret_stdin {
        read_secret_stdin()?
    } else {
        prompt_secret("WARDEN_ITEM_SECRET", "Secret value (hidden): ", false)?
    };
    let name = draft.name.clone();
    match call(&mut c, Request::AddItem { draft, secret }).await? {
        Response::Added { item } => {
            println!("\u{2713} added {name} ({item})");
            Ok(0)
        }
        _ => Err(unexpected()),
    }
}

// ---------------------------------------------------------------- rotate, policy, settings, rm

async fn rotate(ctx: &Ctx, name: Option<String>, all: bool) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let targets = if all {
        items(&mut c).await?
    } else {
        let n = name.ok_or_else(|| cfg_err("give a token name or use --all"))?;
        vec![resolve(&mut c, &n).await?]
    };
    let mut failed = 0u8;
    for t in targets {
        let item = get_item(&mut c, t.id).await?;
        match call(&mut c, Request::RotateNow { item: t.id }).await {
            Ok(_) => {
                let class = provider_name(item.provider.kind);
                println!("{}ok", dots(&format!("\u{2192} roll token at {class}")));
                println!("{}ok", dots("\u{2192} store new value in vault"));
                for s in &item.sinks {
                    println!(
                        "{}ok verified",
                        dots(&format!("\u{2192} write {}", sink_label(s)))
                    );
                }
                let next = items(&mut c)
                    .await?
                    .into_iter()
                    .find(|i| i.id == t.id)
                    .and_then(|i| i.next_rotation);
                println!(
                    "\u{2713} {} rotated \u{00B7} next rotation {}",
                    t.name,
                    next.map_or("-".into(), |n| n.format("%d %b %Y").to_string())
                );
            }
            Err(e) => {
                println!("\u{2717} {}: {e}", t.name);
                failed = 1;
            }
        }
    }
    Ok(failed)
}

async fn policy(ctx: &Ctx, cmd: PolicyCmd) -> Code {
    let PolicyCmd::Set {
        name,
        interval,
        lead,
        grace,
        auto,
    } = cmd;
    if interval.is_none() && lead.is_none() && grace.is_none() && auto.is_none() {
        return Err(cfg_err(
            "give at least one of --interval, --lead, --grace, --auto",
        ));
    }
    let mut c = connect(&ctx.paths).await?;
    let s = resolve(&mut c, &name).await?;
    let mut p = get_item(&mut c, s.id).await?.policy;
    apply_policy(&mut p, &interval, &lead, &grace, auto)?;
    call(
        &mut c,
        Request::UpdatePolicy {
            item: s.id,
            policy: p,
        },
    )
    .await?;
    let next = items(&mut c)
        .await?
        .into_iter()
        .find(|i| i.id == s.id)
        .and_then(|i| i.next_rotation);
    println!(
        "\u{2713} policy saved \u{00B7} next rotation {}",
        next.map_or("-".into(), |n| n.format("%d %b %Y %H:%M").to_string())
    );
    Ok(0)
}

fn parse_on_off(v: &str) -> Result<bool> {
    match v {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        _ => Err(cfg_err("use on or off")),
    }
}

async fn settings(ctx: &Ctx, cmd: SettingsCmd) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let Response::Settings(mut s) = call(&mut c, Request::GetSettings).await? else {
        return Err(unexpected());
    };
    match cmd {
        SettingsCmd::Show => {}
        SettingsCmd::Set { key, value } => {
            match key.as_str() {
                "default-interval" => s.default_interval = duration::parse(&value)?,
                "coffee-reminder" => s.coffee_reminder = parse_on_off(&value)?,
                "keychain-cache" => s.keychain_cache = parse_on_off(&value)?,
                _ => return Err(cfg_err(format!("unknown setting `{key}`"))),
            }
            call(&mut c, Request::SetSettings { settings: s }).await?;
            println!("\u{2713} setting saved");
        }
    }
    let onoff = |b: bool| if b { "on" } else { "off" };
    println!("default-interval  {}", duration::format(s.default_interval));
    println!("coffee-reminder   {}", onoff(s.coffee_reminder));
    println!("keychain-cache    {}", onoff(s.keychain_cache));
    Ok(0)
}

async fn rm(ctx: &Ctx, name: &str, yes: bool) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let s = resolve(&mut c, name).await?;
    if !yes {
        if !interactive() {
            return Err(cfg_err("use --yes to delete without a terminal"));
        }
        let ok = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Delete {}? Warden does not revoke it at the provider.",
                s.name
            ))
            .default(false)
            .interact()
            .map_err(|e| cfg_err(e.to_string()))?;
        if !ok {
            println!("cancelled");
            return Ok(1);
        }
    }
    call(&mut c, Request::DeleteItem { item: s.id }).await?;
    println!("\u{2713} {} deleted", s.name);
    Ok(0)
}

// ---------------------------------------------------------------- inbox, pair, audit

async fn inbox_entries(c: &mut Client) -> Result<Vec<warden_core::ipc::InboxEntry>> {
    match call(c, Request::InboxList).await? {
        Response::Inbox { inbox } => Ok(inbox),
        _ => Err(unexpected()),
    }
}

async fn inbox_find(c: &mut Client, id: &str) -> Result<warden_core::ipc::InboxEntry> {
    let all = inbox_entries(c).await?;
    let hits: Vec<_> = all
        .into_iter()
        .filter(|e| e.id.to_string().starts_with(id))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(WardenError::NotFound(format!("inbox entry `{id}`"))),
        _ => Err(cfg_err("the id matches more than one entry")),
    }
}

async fn inbox(ctx: &Ctx, cmd: Option<InboxCmd>) -> Code {
    let mut c = connect(&ctx.paths).await?;
    match cmd {
        None => {
            let all = inbox_entries(&mut c).await?;
            if all.is_empty() {
                println!("inbox is empty");
                return Ok(0);
            }
            let mut rows = vec![
                ["ID", "ORIGIN", "LABEL", "HINT", "CAPTURED"]
                    .map(String::from)
                    .to_vec(),
            ];
            for e in all {
                rows.push(vec![
                    e.id.to_string()[..8].to_owned(),
                    e.origin,
                    e.label,
                    e.provider_hint.unwrap_or_else(|| "-".into()),
                    e.captured_at.format("%Y-%m-%d %H:%M").to_string(),
                ]);
            }
            print!("{}", table(&rows));
        }
        Some(InboxCmd::Reject { id }) => {
            let e = inbox_find(&mut c, &id).await?;
            call(&mut c, Request::InboxReject { id: e.id }).await?;
            println!("\u{2713} rejected {}", e.label);
        }
        Some(InboxCmd::Accept(a)) => {
            let AcceptArgs { id, item } = *a;
            let e = inbox_find(&mut c, &id).await?;
            let hint = e.provider_hint.as_deref().and_then(ProviderArg::from_hint);
            let draft =
                build_draft(&mut c, item, Some(e.label.clone()), hint, e.expires_at).await?;
            let name = draft.name.clone();
            match call(&mut c, Request::InboxAccept { id: e.id, draft }).await? {
                Response::Added { item } => println!("\u{2713} added {name} ({item})"),
                _ => return Err(unexpected()),
            }
        }
    }
    Ok(0)
}

async fn pair(ctx: &Ctx, a: PairArgs) -> Code {
    let mut c = connect(&ctx.paths).await?;
    if a.list {
        let Response::Clients { clients } = call(&mut c, Request::ListClients).await? else {
            return Err(unexpected());
        };
        let mut rows = vec![
            ["ID", "NAME", "CAPABILITIES", "PAIRED"]
                .map(String::from)
                .to_vec(),
        ];
        for k in clients {
            rows.push(vec![
                k.id,
                k.name,
                k.capabilities
                    .iter()
                    .map(|c| format!("{c:?}").to_lowercase())
                    .collect::<Vec<_>>()
                    .join(","),
                k.paired_at.date_naive().to_string(),
            ]);
        }
        print!("{}", table(&rows));
        return Ok(0);
    }
    let name = a.name.clone().unwrap_or_default();
    let mut caps: Vec<Capability> = a
        .caps
        .iter()
        .map(|c| match c {
            CapArg::Mcp => Capability::McpUse,
            CapArg::McpAdmin => Capability::McpAdmin,
            CapArg::Inbox => Capability::InboxWrite,
        })
        .collect();
    caps.dedup();
    let resp = call(
        &mut c,
        Request::Pair {
            name: name.clone(),
            capabilities: caps,
        },
    )
    .await?;
    let Response::Paired { token, .. } = resp else {
        return Err(unexpected());
    };
    println!("Pairing token for `{name}` (shown once):");
    println!("{}", token.expose());
    if a.save {
        let t = warden_core::ClientToken::parse(token.expose())?;
        store::write_token(&ctx.paths.mcp_token(), &t)?;
        println!("Saved as the default token of `awd mcp`.");
    } else {
        println!("Give it to the client as the env var WARDEN_TOKEN, or pair again with --save.");
    }
    Ok(0)
}

async fn unpair(ctx: &Ctx, id: &str) -> Code {
    let mut c = connect(&ctx.paths).await?;
    call(&mut c, Request::Unpair { id: id.to_owned() }).await?;
    println!("\u{2713} client unpaired");
    Ok(0)
}

async fn devices(ctx: &Ctx) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let Response::Devices { devices } = call(&mut c, Request::ListDevices).await? else {
        return Err(unexpected());
    };
    let mut rows = vec![
        ["ID", "NAME", "ROTATES", "LAST SEEN"]
            .map(String::from)
            .to_vec(),
    ];
    for d in devices {
        rows.push(vec![
            d.id.to_string(),
            d.name,
            d.is_rotator_for.to_string(),
            d.last_seen
                .map_or("-".into(), |t| t.format("%Y-%m-%d %H:%M").to_string()),
        ]);
    }
    print!("{}", table(&rows));
    Ok(0)
}

async fn audit(ctx: &Ctx, name: Option<String>, limit: u32) -> Code {
    let mut c = connect(&ctx.paths).await?;
    let item = match name {
        Some(n) => Some(resolve(&mut c, &n).await?.id),
        None => None,
    };
    let Response::Audit { audit } = call(&mut c, Request::AuditList { item, limit }).await? else {
        return Err(unexpected());
    };
    let mut rows = vec![["TIME", "ACTION", "DETAIL"].map(String::from).to_vec()];
    for e in audit {
        rows.push(vec![
            e.at.format("%Y-%m-%d %H:%M:%S").to_string(),
            e.action,
            e.detail,
        ]);
    }
    print!("{}", table(&rows));
    Ok(0)
}

// ---------------------------------------------------------------- exec (local vault access)

fn open_local_vault(ctx: &Ctx) -> Result<Vault> {
    let dir = local_vault_dir(ctx)?;
    let local = ctx.paths.device_dir();
    let no_keychain = std::env::var_os("WARDEN_NO_KEYCHAIN").is_some_and(|v| !v.is_empty());
    if !no_keychain
        && let Some(vid) = std::fs::read(dir.join("header.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| serde_json::from_value(v.get("vault_id")?.clone()).ok())
        && let Ok(Some(key)) = keychain::load(&vid)
    {
        return Vault::open_with_key(&dir, &key, &local);
    }
    let pw = prompt_secret("WARDEN_PASSWORD", "Vault password: ", false)?;
    let sk = prompt_secret("WARDEN_SECRET_KEY", "Secret Key: ", false)?;
    let sk: SecretKey = sk.expose().parse()?;
    Vault::open(&dir, pw.expose(), &sk, &local)
}

fn exec(ctx: &Ctx, a: ExecArgs) -> Code {
    let vault = open_local_vault(ctx)?;
    let item = vault
        .items()
        .into_iter()
        .find(|i| i.name.eq_ignore_ascii_case(&a.name) || i.id.to_string() == a.name)
        .ok_or_else(|| WardenError::NotFound(format!("token `{}`", a.name)))?
        .clone();
    let secret = vault.secret(&item.id, TOKEN_SECRET)?;
    drop(vault);
    let var = a
        .env
        .unwrap_or_else(|| item.slug.to_ascii_uppercase().replace('-', "_"));
    let status = std::process::Command::new(&a.cmd[0])
        .args(&a.cmd[1..])
        .env(&var, secret.expose())
        .status()
        .map_err(|e| cfg_err(format!("cannot start `{}`: {e}", a.cmd[0])))?;
    Ok(status.code().map_or(1, |c| u8::try_from(c).unwrap_or(1)))
}

// ---------------------------------------------------------------- coffee

async fn coffee(ctx: &Ctx, receipt: Option<String>) -> Code {
    let mut c = connect(&ctx.paths).await?;
    if let Some(code) = receipt {
        call(&mut c, Request::CoffeeReceipt { code }).await?;
        println!("\u{2713} {THANKS_TEXT}");
        return Ok(0);
    }
    let Response::Coffee(i) = call(&mut c, Request::CoffeeStatus).await? else {
        return Err(unexpected());
    };
    if let Some(y) = i.paid_year {
        println!("\u{2615} coffee paid for {y}. Ticket {}.", i.ticket);
        println!("{THANKS_TEXT}");
        return Ok(0);
    }
    println!("\u{2615} no receipt for this year. Ticket {}.", i.ticket);
    println!("Price: {}. Link: {}", i.price_label, i.link);
    if !interactive() {
        return Ok(0);
    }
    if let Err(e) = open::that(&i.link) {
        println!("Cannot open the browser: {e}. Open the link by hand.");
    }
    let code = ask("Receipt code (empty to skip)", None, true)?;
    if code.trim().is_empty() {
        return Ok(0);
    }
    call(&mut c, Request::CoffeeReceipt { code }).await?;
    println!("\u{2713} {THANKS_TEXT}");
    Ok(0)
}

/// Print the weekly coffee note on stderr, when stderr is a terminal and the note is due.
fn coffee_note(paths: &Paths) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let Ok(settings) = store::load_settings(paths) else {
        return;
    };
    let store = CoffeeStore::new(paths.settings_file());
    let Ok(mut st) = store.load() else { return };
    let note = warden_coffee::take_note(
        &mut st,
        warden_coffee::Moment::Weekly,
        settings.coffee_reminder,
        &SystemClock,
    );
    if let Some(n) = note {
        eprintln!("\u{2615} {} {}", n.title, n.body);
        let _ = store.save(&st);
    }
}

// ---------------------------------------------------------------- service, extension

fn service_cmd(cmd: ServiceCmd) -> Code {
    match cmd {
        ServiceCmd::Install => {
            let exe = std::env::current_exe()?;
            service::install(&exe)?;
            println!("\u{2713} service installed and started");
            Ok(0)
        }
        ServiceCmd::Uninstall => {
            service::uninstall()?;
            println!("\u{2713} service removed");
            Ok(0)
        }
        ServiceCmd::Status => {
            let (active, text) = service::status()?;
            println!(
                "{} service {}{}",
                if active { "\u{25CF}" } else { "\u{25CB}" },
                if active {
                    "installed"
                } else {
                    "not installed or not active"
                },
                if text.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", text.lines().next().unwrap_or(""))
                }
            );
            Ok(u8::from(!active))
        }
    }
}

fn extension(ctx: &Ctx, cmd: ExtensionCmd) -> Code {
    match cmd {
        ExtensionCmd::Install { id } => {
            if !warden_native_host::valid_extension_id(&id) {
                return Err(cfg_err("the extension id must have 32 letters from a to p"));
            }
            std::fs::create_dir_all(&ctx.paths.config)?;
            let pairing = PairingFile::new(ctx.paths.pairing_file());
            if !pairing.token_file_valid(&ctx.paths.native_host_token()) {
                let t = pairing.add("native-host", &[Capability::InboxWrite])?;
                store::write_token(&ctx.paths.native_host_token(), &t)?;
            }
            let exe = std::env::current_exe()?;
            let files = warden_native_host::register(&exe, &id)?;
            println!("\u{2713} native host registered for extension {id}");
            for f in files {
                println!("  {}", f.display());
            }
            Ok(0)
        }
        ExtensionCmd::Uninstall => {
            warden_native_host::unregister()?;
            println!("\u{2713} native host registration removed");
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------- mcp, native host

async fn mcp(ctx: &Ctx) -> Code {
    let token = match env_secret("WARDEN_TOKEN") {
        Some(t) => t.expose().to_owned(),
        None => store::read_token(&ctx.paths.mcp_token())
            .map_err(|_| cfg_err("no MCP token. Run `awd pair mcp --save`, or set WARDEN_TOKEN"))?,
    };
    let client = Client::connect(ctx.paths.endpoint().as_deref(), Some(&token)).await?;
    warden_mcp::serve_stdio(client).await?;
    Ok(0)
}

async fn native_host(paths: &Paths) -> Code {
    let endpoint = paths.endpoint();
    let token_file = paths.native_host_token();
    let connect = move || {
        let endpoint = endpoint.clone();
        let token_file = token_file.clone();
        async move { warden_native_host::connect_with_token(endpoint, token_file).await }
    };
    warden_native_host::run(tokio::io::stdin(), tokio::io::stdout(), connect)
        .await
        .map_err(|e| WardenError::Ipc(e.to_string()))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_lists_all_verbs() {
        let help = Cli::command().render_long_help().to_string();
        for verb in [
            "init",
            "unlock",
            "lock",
            "status",
            "add",
            "list",
            "show",
            "rotate",
            "policy",
            "settings",
            "rm",
            "inbox",
            "pair",
            "unpair",
            "devices",
            "audit",
            "exec",
            "coffee",
            "service",
            "extension",
            "mcp",
            "daemon",
        ] {
            assert!(help.contains(verb), "missing verb {verb}");
        }
    }

    #[test]
    fn slugs() {
        assert_eq!(slugify("GitLab Admin!"), "gitlab-admin");
    }

    #[test]
    fn relative_times() {
        let now = SystemClock.now();
        assert_eq!(rel(None, now), "-");
        assert_eq!(rel(Some(now - chrono::TimeDelta::hours(1)), now), "due");
        assert_eq!(
            rel(
                Some(now + chrono::TimeDelta::days(12) + chrono::TimeDelta::hours(1)),
                now
            ),
            "in 12d"
        );
    }

    #[test]
    fn table_aligns_columns() {
        let t = table(&[
            vec!["A".into(), "B".into()],
            vec!["long".into(), "x".into()],
        ]);
        assert_eq!(t, "A     B\nlong  x\n");
    }

    #[test]
    fn kit_shows_secret_key_once() {
        let sk = SecretKey::generate();
        let kit = emergency_kit(Path::new("/v"), "dev", &sk);
        assert!(kit.contains(&sk.to_string()));
    }
}
