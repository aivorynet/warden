//! End-to-end test of the main user story with the real binary: store an admin token once,
//! then Warden creates, rotates and revokes the derived tokens by itself.
//!
//! GitLab and AWS (IAM + STS) are HTTP mocks. All values are synthetic fixtures.

use aivory_warden::Paths;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const EXE: &str = env!("CARGO_BIN_EXE_aivory-warden");
const PASSWORD: &str = "e2e-password-1";

struct Env {
    home: PathBuf,
    secret_key: Option<String>,
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
        if let Some(k) = &self.secret_key {
            c.env("WARDEN_SECRET_KEY", k);
        }
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

    /// Run `add` with a secret on stdin.
    fn add_with_secret(&self, args: &[&str], secret: &str) {
        let mut c = self.awd(args);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{secret}\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
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

/// One request that a mock saw: method, path and body.
type Seen = (String, String, String);

fn seen(rt: &tokio::runtime::Runtime, s: &MockServer) -> Vec<Seen> {
    rt.block_on(s.received_requests())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            (
                r.method.to_string(),
                r.url.path().to_owned(),
                String::from_utf8_lossy(&r.body).into_owned(),
            )
        })
        .collect()
}

fn count(v: &[Seen], m: &str, p: &str) -> usize {
    v.iter().filter(|(vm, vp, _)| vm == m && vp == p).count()
}

/// GitLab mock: self rotate, project access token create and revoke.
async fn gitlab_mock() -> MockServer {
    let s = MockServer::start().await;
    let admin = Arc::new(AtomicUsize::new(0));
    let proj = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/api/v4/personal_access_tokens/self/rotate"))
        .respond_with(move |_: &Request| {
            let n = admin.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 100 + n,
                "token": format!("glpat-admin-new-{n}"),
                "expires_at": "2027-01-31",
            }))
        })
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/access_tokens"))
        .respond_with(move |_: &Request| {
            let n = proj.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 200 + n,
                "token": format!("glpat-proj-{n}"),
                "expires_at": "2027-01-31",
            }))
        })
        .mount(&s)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/projects/42/access_tokens/\d+$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/personal_access_tokens/self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"id": 101, "scopes": ["api"], "expires_at": "2027-01-31"}),
        ))
        .mount(&s)
        .await;
    s
}

/// AWS mock: IAM and STS on one URL. It keeps the list of keys of the user `bob`.
async fn aws_mock() -> MockServer {
    let s = MockServer::start().await;
    let keys = Arc::new(Mutex::new(vec!["AKIAOLD".to_owned()]));
    let n = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(move |r: &Request| {
            let body = String::from_utf8_lossy(&r.body).into_owned();
            let xml = |b: String| ResponseTemplate::new(200).set_body_string(b);
            if body.contains("Action=GetCallerIdentity") {
                xml("<GetCallerIdentityResponse><GetCallerIdentityResult>\
                     <Arn>arn:aws:iam::123456789012:user/bob</Arn>\
                     </GetCallerIdentityResult></GetCallerIdentityResponse>"
                    .into())
            } else if body.contains("Action=ListAccessKeys") {
                let m: String = keys
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|k| {
                        format!(
                            "<member><AccessKeyId>{k}</AccessKeyId><Status>Active</Status>\
                             <CreateDate>2020-01-01T00:00:00Z</CreateDate></member>"
                        )
                    })
                    .collect();
                xml(format!(
                    "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>{m}\
                     </AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>"
                ))
            } else if body.contains("Action=CreateAccessKey") {
                let id = format!("AKIANEW{}", n.fetch_add(1, Ordering::SeqCst) + 1);
                keys.lock().unwrap().push(id.clone());
                xml(format!(
                    "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey>\
                     <AccessKeyId>{id}</AccessKeyId><SecretAccessKey>secret-{id}</SecretAccessKey>\
                     </AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>"
                ))
            } else if body.contains("Action=DeleteAccessKey") {
                keys.lock()
                    .unwrap()
                    .retain(|k| !body.contains(&format!("AccessKeyId={k}")));
                xml("<DeleteAccessKeyResponse/>".into())
            } else {
                xml("<ok/>".into())
            }
        })
        .mount(&s)
        .await;
    s
}

#[test]
fn admin_token_once_then_warden_creates_rotates_and_revokes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let gl = rt.block_on(gitlab_mock());
    let aws = rt.block_on(aws_mock());

    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut env1 = Env {
        home: tmp.path().join("home1"),
        secret_key: None,
    };
    let _d1 = start_daemon(&env1);
    let kit = env1.ok(&[
        "init",
        "--pledge",
        "--insecure-fast-kdf",
        "--device-name",
        "dev1",
    ]);
    let secret_key = kit
        .lines()
        .find_map(|l| l.strip_prefix("Secret Key:"))
        .map(|s| s.trim().to_owned())
        .expect("Emergency Kit has a Secret Key");
    env1.secret_key = Some(secret_key.clone());

    // Seed files for the sinks.
    let gl_env = work.join("gitlab.env");
    let proj_env = work.join("proj.env");
    let proj_toml = work.join("proj.toml");
    let aws_toml = work.join("aws.toml");
    std::fs::write(&gl_env, "# keep me\nGITLAB_TOKEN=seed\n").unwrap();
    std::fs::write(&proj_env, "PROJ_TOKEN=seed\n").unwrap();
    std::fs::write(&proj_toml, "[ci]\ntoken = \"seed\"\n").unwrap();
    std::fs::write(&aws_toml, "[aws]\ncredentials = \"seed\"\n").unwrap();

    // The admin tokens: the user enters the value once.
    let gl_cfg = serde_json::json!({"base_url": gl.uri(), "project_id": "42", "allow_insecure_loopback": true}).to_string();
    env1.add_with_secret(
        &[
            "add",
            "--name",
            "gladmin",
            "--provider",
            "gitlab",
            "--provider-config",
            &gl_cfg,
            "--auto",
            "off",
            "--sink",
            &format!("dotenv:{}:GITLAB_TOKEN", gl_env.display()),
            "--secret-stdin",
        ],
        "glpat-admin-seed",
    );
    let aws_cfg =
        serde_json::json!({"base_url": aws.uri(), "allow_insecure_loopback": true}).to_string();
    let aws_seed =
        serde_json::json!({"access_key_id": "AKIAOLD", "secret_access_key": "secret-old"})
            .to_string();
    env1.add_with_secret(
        &[
            "add",
            "--name",
            "awsadmin",
            "--provider",
            "aws-iam",
            "--provider-config",
            &aws_cfg,
            "--auto",
            "off",
            "--grace",
            "0s",
            "--sink",
            &format!("toml:{}:aws.credentials", aws_toml.display()),
            "--secret-stdin",
        ],
        &aws_seed,
    );

    // The derived token: Warden creates it at GitLab. The user gives no value.
    let out = env1.ok(&[
        "add",
        "--name",
        "projci",
        "--derived-from",
        "gladmin",
        "--provider-config",
        r#"{"project_id":"42","scopes":["read_api"]}"#,
        "--auto",
        "off",
        "--sink",
        &format!("dotenv:{}:PROJ_TOKEN", proj_env.display()),
        "--sink",
        &format!("toml:{}:ci.token", proj_toml.display()),
    ]);
    assert!(out.contains("created projci"), "{out}");
    assert!(read(&proj_env).contains("PROJ_TOKEN=glpat-proj-1"));
    assert!(read(&proj_toml).contains("glpat-proj-1"));
    // The admin token cannot go while a derived token uses it.
    let o = env1.run(&["rm", "gladmin", "--yes"]);
    assert!(!o.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(text.contains("projci"), "{text}");
    let s = seen(&rt, &gl);
    let (_, _, body) = s
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/api/v4/projects/42/access_tokens")
        .expect("project token created");
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(v["name"].as_str().unwrap().starts_with("aivw_projci_"));
    assert_eq!(v["scopes"][0], "read_api");

    // Rotate everything.
    let r = env1.ok(&["rotate", "--all"]);
    assert!(!r.contains('\u{2717}'), "{r}");
    assert!(read(&gl_env).contains("GITLAB_TOKEN=glpat-admin-new-1"));
    assert!(read(&gl_env).contains("# keep me"));
    assert!(read(&proj_env).contains("PROJ_TOKEN=glpat-proj-2"));
    assert!(read(&proj_toml).contains("glpat-proj-2"));
    assert!(read(&aws_toml).contains("AKIANEW1"), "{}", read(&aws_toml));
    let s = seen(&rt, &gl);
    let (_, _, rot) = s
        .iter()
        .find(|(_, p, _)| p == "/api/v4/personal_access_tokens/self/rotate")
        .expect("admin self-rotated");
    let v: serde_json::Value = serde_json::from_str(rot).unwrap();
    assert!(v["expires_at"].as_str().is_some_and(|d| d.len() == 10));
    wait_for("old derived token revoked", 20, || {
        count(
            &seen(&rt, &gl),
            "DELETE",
            "/api/v4/projects/42/access_tokens/201",
        ) == 1
    });
    wait_for("old AWS key deleted", 20, || {
        seen(&rt, &aws)
            .iter()
            .any(|(_, _, b)| b.contains("Action=DeleteAccessKey") && b.contains("AKIAOLD"))
    });
    assert_eq!(
        count(
            &seen(&rt, &gl),
            "DELETE",
            "/api/v4/projects/42/access_tokens/202"
        ),
        0
    );

    // No secret appears in the CLI output.
    for args in [&["list"][..], &["show", "projci"], &["audit"]] {
        let o = env1.ok(args);
        assert!(
            !o.contains("glpat-") && !o.contains("AKIANEW") && !o.contains("secret-"),
            "{o}"
        );
    }

    // A second device joins the same vault.
    let vault_dir = Paths::from_home(env1.home.clone()).default_vault();
    let env2 = Env {
        home: tmp.path().join("home2"),
        secret_key: Some(secret_key),
    };
    let _d2 = start_daemon(&env2);
    env2.ok(&[
        "join",
        "--vault",
        vault_dir.to_str().unwrap(),
        "--pledge",
        "--insecure-fast-kdf",
        "--device-name",
        "dev2",
    ]);
    let rotations = |rt: &tokio::runtime::Runtime| {
        count(
            &seen(rt, &gl),
            "POST",
            "/api/v4/personal_access_tokens/self/rotate",
        )
    };
    assert_eq!(rotations(&rt), 1);
    // It does not own the items: rotation is refused and the provider sees nothing.
    let o = env2.run(&["rotate", "gladmin"]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("not the rotator"),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(rotations(&rt), 1);

    // Handover moves the role.
    let mut devices = String::new();
    wait_for("dev2 in the device list of dev1", 20, || {
        devices = env1.ok(&["devices"]);
        devices.contains("dev2")
    });
    let dev2 = devices
        .lines()
        .find(|l| l.contains("dev2"))
        .and_then(|l| l.split_whitespace().next())
        .expect("dev2 listed")
        .to_owned();
    env1.ok(&["handover", "gladmin", "--to", &dev2]);
    wait_for("dev2 rotates after the handover", 20, || {
        env2.run(&["rotate", "gladmin"]).status.success()
    });
    assert_eq!(rotations(&rt), 2);
    assert!(read(&gl_env).contains("GITLAB_TOKEN=glpat-admin-new-2"));
    assert!(!env1.run(&["rotate", "gladmin"]).status.success());
    // The other items stay with dev1.
    assert!(!env2.run(&["rotate", "awsadmin"]).status.success());
    env1.ok(&["handover", "--all", "--to", "dev2"]);
    wait_for("dev2 rotates the AWS key", 20, || {
        env2.run(&["rotate", "awsadmin"]).status.success()
    });
    assert!(read(&aws_toml).contains("AKIANEW2"), "{}", read(&aws_toml));
}
