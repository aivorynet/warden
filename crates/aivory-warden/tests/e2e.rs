//! End-to-end test: daemon as a child process, CLI verbs as child processes.
//!
//! All paths live below one temp dir (`WARDEN_HOME`). The keychain and the desktop
//! notifications are off. The provider is a script that logs every call.

use aivory_warden::Paths;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use warden_core::ipc::{Request, Response};
use warden_ipc::Client;

const EXE: &str = env!("CARGO_BIN_EXE_aivory-warden");
const PASSWORD: &str = "e2e-password-1";

struct Env {
    home: PathBuf,
    work: PathBuf,
}

impl Env {
    fn awd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(EXE);
        c.args(args)
            .env("WARDEN_HOME", &self.home)
            .env("WARDEN_NO_KEYCHAIN", "1")
            .env("WARDEN_NO_NOTIFY", "1")
            .env("WARDEN_TICK_MS", "300")
            .env("WARDEN_PASSWORD", PASSWORD)
            .stdin(Stdio::null());
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.awd(args).output().expect("run awd")
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert!(
            o.status.success(),
            "awd {args:?} failed: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
}

struct DaemonGuard(Child);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_daemon(env: &Env) -> DaemonGuard {
    let mut child = env
        .awd(&["daemon"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("start daemon");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("listening")
                && let Some(t) = tx.take()
            {
                let _ = t.send(());
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("daemon did not start");
    DaemonGuard(child)
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("timeout: {what}");
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Write the provider script and return the provider config as JSON.
fn provider_config(work: &Path) -> serde_json::Value {
    let dir = work.to_string_lossy().into_owned();
    let (script_name, script, runner): (&str, &str, Vec<&str>) = if cfg!(windows) {
        (
            "provider.ps1",
            r#"param([string]$mode, [string]$dir)
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$counter = Join-Path $dir 'counter.txt'
$log = Join-Path $dir 'provider.log'
if ($mode -eq 'rotate') {
  $n = 1
  if (Test-Path $counter) { $n = [int](Get-Content $counter) + 1 }
  Set-Content -Path $counter -Value $n
  Add-Content -Path $log -Value "rotate tok-$n"
  Write-Output (@{ value = "newtoken-$n"; id = "tok-$n" } | ConvertTo-Json -Compress)
} else {
  Add-Content -Path $log -Value "revoke $($in.token_id)"
}
"#,
            vec![
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ],
        )
    } else {
        (
            "provider.sh",
            r#"mode="$1"; dir="$2"
input=$(cat)
if [ "$mode" = rotate ]; then
  n=1
  [ -f "$dir/counter.txt" ] && n=$(( $(cat "$dir/counter.txt") + 1 ))
  echo "$n" > "$dir/counter.txt"
  echo "rotate tok-$n" >> "$dir/provider.log"
  printf '{"value":"newtoken-%s","id":"tok-%s"}' "$n" "$n"
else
  tid=$(printf '%s' "$input" | sed -n 's/.*"token_id":"\([^"]*\)".*/\1/p')
  echo "revoke $tid" >> "$dir/provider.log"
fi
"#,
            vec!["sh"],
        )
    };
    let script_path = work.join(script_name);
    std::fs::write(&script_path, script).unwrap();
    let sp = script_path.to_string_lossy().into_owned();
    let argv = |mode: &str| {
        let mut v: Vec<String> = runner.iter().map(|s| (*s).to_owned()).collect();
        v.extend([sp.clone(), mode.to_owned(), dir.clone()]);
        v
    };
    serde_json::json!({ "rotate": argv("rotate"), "revoke": argv("revoke"), "class": "overlap" })
}

#[test]
fn init_add_rotate_schedule_and_capabilities() {
    let tmp = tempfile::tempdir().unwrap();
    let env = Env {
        home: tmp.path().join("home"),
        work: tmp.path().join("work"),
    };
    std::fs::create_dir_all(&env.work).unwrap();
    let _daemon = start_daemon(&env);

    // init: vault, Emergency Kit, device registration, daemon unlock.
    let kit = env.ok(&[
        "init",
        "--pledge",
        "--insecure-fast-kdf",
        "--device-name",
        "e2e-device",
    ]);
    let secret_key = kit
        .lines()
        .find_map(|l| l.strip_prefix("Secret Key:"))
        .map(|s| s.trim().to_owned())
        .expect("Emergency Kit has a Secret Key");
    assert!(secret_key.starts_with("A3-"), "kit: {kit}");
    assert!(kit.contains("daemon is unlocked"), "kit: {kit}");
    let st = env.ok(&["status"]);
    assert!(st.contains("vault unlocked"), "{st}");
    assert!(
        st.contains("coffee: not paid this year (ticket AIVW-"),
        "{st}"
    );
    let settings = read(&env.home.join("config").join("settings.json"));
    assert!(settings.contains("pledge_signed_at"), "{settings}");
    assert!(kit.contains("Coffee ticket: AIVW-"), "{kit}");

    // add: Command provider, dotenv + json sinks, no grace.
    let cfg_file = env.work.join("provider.json");
    std::fs::write(&cfg_file, provider_config(&env.work).to_string()).unwrap();
    let dotenv = env.work.join("app.env");
    let json = env.work.join("app.json");
    std::fs::write(&dotenv, "# keep me\nOTHER=1\nAPI_TOKEN=seed-secret\n").unwrap();
    std::fs::write(&json, r#"{"a":{"b":"seed-secret"}}"#).unwrap();
    let dotenv_spec = format!("dotenv:{}:API_TOKEN", dotenv.display());
    let json_spec = format!("json:{}:/a/b", json.display());
    let mut add = env.awd(&[
        "add",
        "--name",
        "demo-admin",
        "--provider",
        "command",
        "--config-file",
        cfg_file.to_str().unwrap(),
        "--grace",
        "0s",
        "--mcp-host",
        "api.example.com",
        "--sink",
        &dotenv_spec,
        "--sink",
        &json_spec,
        "--secret-stdin",
    ]);
    add.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = add.spawn().unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"seed-secret\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let list = env.ok(&["list"]);
    assert!(
        list.contains("demo-admin") && list.contains("command"),
        "{list}"
    );

    // rotate: both sinks hold the new value. The dotenv comment stays.
    let r = env.ok(&["rotate", "demo-admin"]);
    assert!(r.contains("rotated"), "{r}");
    assert!(
        read(&dotenv).contains("API_TOKEN=newtoken-1"),
        "{}",
        read(&dotenv)
    );
    assert!(read(&dotenv).contains("# keep me"));
    assert!(read(&json).contains("newtoken-1"), "{}", read(&json));

    // second rotation: the daemon revokes the old token (grace 0) at its next pass.
    env.ok(&["rotate", "demo-admin"]);
    assert!(read(&dotenv).contains("API_TOKEN=newtoken-2"));
    assert!(read(&json).contains("newtoken-2"));
    let log = env.work.join("provider.log");
    wait_for("old token revoked", 20, || {
        read(&log).contains("revoke tok-1")
    });
    assert!(!read(&log).contains("revoke tok-2"), "{}", read(&log));

    // exec: the token reaches the child as an env var.
    env.ok(&["policy", "set", "demo-admin", "--auto", "off"]);
    let mut exec_env = env.awd(&["exec", "demo-admin", "--env", "E2E_TOK", "--"]);
    if cfg!(windows) {
        exec_env.args(["cmd", "/C", "echo %E2E_TOK%"]);
    } else {
        exec_env.args(["sh", "-c", "echo $E2E_TOK"]);
    }
    exec_env.env("WARDEN_SECRET_KEY", &secret_key);
    let o = exec_env.output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("newtoken-2"));

    // the daemon rotates on its own with a short interval.
    env.ok(&[
        "policy",
        "set",
        "demo-admin",
        "--interval",
        "2s",
        "--auto",
        "on",
    ]);
    let counter = env.work.join("counter.txt");
    wait_for("scheduled rotation", 40, || {
        read(&counter).trim().parse::<u32>().unwrap_or(0) >= 3
    });
    assert!(read(&dotenv).contains("API_TOKEN=newtoken-"));
    env.ok(&["policy", "set", "demo-admin", "--auto", "off"]);

    // pair --cap mcp: an MCP client may list but not delete.
    let out = env.ok(&["pair", "agent", "--cap", "mcp"]);
    let token = out
        .lines()
        .find(|l| l.starts_with("aivw_"))
        .expect("token printed")
        .trim()
        .to_owned();
    let endpoint = Paths::from_home(env.home.clone()).endpoint();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c = Client::connect(endpoint.as_deref(), Some(&token))
            .await
            .expect("mcp client connects");
        let Response::Items { items } = c.call(Request::ListItems).await.unwrap() else {
            panic!("no item list");
        };
        assert_eq!(items.len(), 1);
        let resp = c
            .call(Request::DeleteItem { item: items[0].id })
            .await
            .unwrap();
        match resp {
            Response::Error { code, .. } => assert_eq!(code, "forbidden"),
            other => panic!("DeleteItem was not refused: {other:?}"),
        }
        let resp = c.call(Request::Lock).await.unwrap();
        assert!(matches!(resp, Response::Error { .. }));
    });

    // the token is stored only as a hash, and no secret appears in the CLI output.
    assert!(!read(&env.home.join("config").join("pairing.json")).contains(&token));
    for args in [&["list"][..], &["show", "demo-admin"], &["audit"]] {
        let o = env.ok(args);
        assert!(
            !o.contains("newtoken-") && !o.contains("seed-secret"),
            "{o}"
        );
    }

    // lock, then a locked daemon refuses item requests.
    env.ok(&["lock"]);
    assert!(env.ok(&["status"]).contains("vault locked"));
    assert!(!env.run(&["list"]).status.success());
}

#[test]
fn second_daemon_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let env = Env {
        home: tmp.path().join("home"),
        work: tmp.path().to_path_buf(),
    };
    let _d = start_daemon(&env);
    let o = env.run(&["daemon"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("another daemon"));
}
