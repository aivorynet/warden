//! Command provider: runs user scripts. The secret goes to stdin, never to argv.

use crate::http::{TIMEOUT, unsupported};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

/// Provider that runs user scripts.
///
/// Config: `verify`, `rotate`, `create`, `revoke` (argv arrays; an element `{name}` is
/// replaced by the token name), `class` (`overlap` default, or `atomic_swap`).
///
/// Stdin of each script is one JSON object: `secret`, `name`, `token_id`, `scopes`,
/// `expires_at`. Stdout of `rotate` and `create` is JSON `{value, id, expires_at}`.
/// Stdout of `verify` is JSON `{id, expires_at, scopes}`. `revoke` output is ignored.
#[derive(Debug)]
pub struct CommandProvider {
    verify: Option<Vec<String>>,
    rotate: Option<Vec<String>>,
    create: Option<Vec<String>>,
    revoke: Option<Vec<String>>,
    class: RotationClass,
}

#[derive(Deserialize)]
struct Output {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    scopes: Vec<String>,
}

fn argv(c: &Value, key: &str) -> Result<Option<Vec<String>>> {
    let Some(v) = c.get(key).filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let bad = || WardenError::Config(format!("`{key}` must be a non-empty array of strings"));
    let a: Vec<String> = serde_json::from_value(v.clone()).map_err(|_| bad())?;
    if a.is_empty() {
        return Err(bad());
    }
    Ok(Some(a))
}

impl CommandProvider {
    /// Build from provider config.
    pub fn from_config(c: &Value) -> Result<Self> {
        let class = match c.get("class").and_then(|v| v.as_str()) {
            None | Some("overlap") => RotationClass::Overlap,
            Some("atomic_swap") => RotationClass::AtomicSwap,
            Some(o) => return Err(WardenError::Config(format!("unknown class `{o}`"))),
        };
        Ok(Self {
            verify: argv(c, "verify")?,
            rotate: argv(c, "rotate")?,
            create: argv(c, "create")?,
            revoke: argv(c, "revoke")?,
            class,
        })
    }
}

async fn run(cmd: &[String], name: &str, input: Value) -> Result<String> {
    let args: Vec<String> = cmd[1..].iter().map(|a| a.replace("{name}", name)).collect();
    let mut child = Command::new(&cmd[0])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| WardenError::Provider(format!("cannot start command: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let payload = serde_json::to_vec(&input)?;
    // Write stdin while stdout and stderr drain, so a chatty script cannot block.
    let feed = async move {
        // A script may exit before it reads stdin. Ignore a broken pipe.
        let _ = stdin.write_all(&payload).await;
        drop(stdin);
    };
    let work = async {
        let (_, out) = tokio::join!(feed, child.wait_with_output());
        out
    };
    let out = tokio::time::timeout(TIMEOUT, work)
        .await
        .map_err(|_| WardenError::Provider("command timed out".into()))?
        .map_err(|e| WardenError::Provider(format!("command failed: {e}")))?;
    if !out.status.success() {
        let err: String = String::from_utf8_lossy(&out.stderr)
            .chars()
            .take(200)
            .collect();
        return Err(WardenError::Provider(format!(
            "command exited with {}: {}",
            out.status.code().unwrap_or(-1),
            err.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse(out: &str) -> Result<Output> {
    serde_json::from_str(out.trim())
        .map_err(|e| WardenError::Provider(format!("command output is not valid JSON: {e}")))
}

fn issued(o: Output) -> Result<IssuedToken> {
    Ok(IssuedToken {
        value: SecretValue::new(
            o.value
                .ok_or_else(|| WardenError::Provider("command output has no `value`".into()))?,
        ),
        provider_token_id: o
            .id
            .ok_or_else(|| WardenError::Provider("command output has no `id`".into()))?,
        expires_at: o.expires_at,
    })
}

#[async_trait]
impl Provider for CommandProvider {
    fn class(&self) -> RotationClass {
        self.class
    }

    fn capabilities(&self) -> ProviderCaps {
        ProviderCaps {
            self_rotate: self.rotate.is_some(),
            create_derived: self.create.is_some(),
            revoke: self.revoke.is_some(),
            naming: self.rotate.is_some() || self.create.is_some(),
        }
    }

    async fn verify(&self, cred: &SecretValue) -> Result<TokenInfo> {
        let Some(cmd) = &self.verify else {
            return unsupported("command provider: no `verify` script");
        };
        let o = parse(&run(cmd, "", json!({ "secret": cred.expose() })).await?)?;
        Ok(TokenInfo {
            provider_token_id: o.id.unwrap_or_default(),
            expires_at: o.expires_at,
            scopes: o.scopes,
        })
    }

    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        let Some(cmd) = &self.rotate else {
            return unsupported("command provider: no `rotate` script");
        };
        let input = json!({
            "secret": cred.expose(), "name": req.token_name,
            "token_id": req.provider_token_id, "expires_at": req.expires_at,
        });
        issued(parse(&run(cmd, &req.token_name, input).await?)?)
    }

    async fn create_derived(
        &self,
        admin: &SecretValue,
        req: &CreateRequest,
    ) -> Result<IssuedToken> {
        let Some(cmd) = &self.create else {
            return unsupported("command provider: no `create` script");
        };
        let input = json!({
            "secret": admin.expose(), "name": req.token_name,
            "scopes": req.scopes, "expires_at": req.expires_at,
        });
        issued(parse(&run(cmd, &req.token_name, input).await?)?)
    }

    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()> {
        let Some(cmd) = &self.revoke else {
            return unsupported("command provider: no `revoke` script");
        };
        run(
            cmd,
            "",
            json!({ "secret": admin.expose(), "token_id": provider_token_id }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testutil::{create_req, rotate_req};

    /// Script that prints `body` when stdin has `s3cret`, else prints a failure id.
    fn script(body_ok: &str) -> Vec<String> {
        #[cfg(unix)]
        let v = vec![
            "sh".to_string(),
            "-c".into(),
            format!(
                "if grep -q s3cret; then echo '{body_ok}'; else echo '{{\"id\":\"nosecret\"}}'; fi"
            ),
        ];
        #[cfg(windows)]
        let v = {
            // No double quotes: Windows argv quoting would mangle them.
            let ps = body_ok
                .replace('"', "")
                .trim_matches(|c| c == '{' || c == '}')
                .split(',')
                .map(|kv| {
                    let (k, val) = kv.split_once(':').unwrap();
                    format!("{k}='{val}'")
                })
                .collect::<Vec<_>>()
                .join(";");
            vec![
                "powershell".to_string(),
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "if ([Console]::In.ReadToEnd() -match 's3cret') {{ @{{{ps}}} | ConvertTo-Json -Compress }} else {{ @{{id='nosecret'}} | ConvertTo-Json -Compress }}"
                ),
            ]
        };
        v
    }

    fn provider(ok: &str) -> CommandProvider {
        let s = script(ok);
        CommandProvider::from_config(&json!({
            "verify": s, "rotate": s, "create": s, "revoke": s
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn secret_on_stdin_and_output_parsed() {
        let p = provider(r#"{"value":"newval","id":"tok9"}"#);
        let c = SecretValue::new("s3cret");
        let t = p.rotate_self(&c, &rotate_req(Some("old"))).await.unwrap();
        assert_eq!(t.value.expose(), "newval");
        assert_eq!(t.provider_token_id, "tok9");
        let t = p
            .create_derived(&c, &create_req("aivw_demo_20261124"))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "tok9");
        assert_eq!(p.verify(&c).await.unwrap().provider_token_id, "tok9");
        p.revoke(&c, "tok9").await.unwrap();
        // Without the secret on stdin the script reports a different id.
        let other = p.verify(&SecretValue::new("other")).await.unwrap();
        assert_eq!(other.provider_token_id, "nosecret");
    }

    #[tokio::test]
    async fn failing_command_and_missing_script() {
        #[cfg(unix)]
        let bad = vec!["sh".to_string(), "-c".into(), "exit 3".into()];
        #[cfg(windows)]
        let bad = vec!["cmd".to_string(), "/C".into(), "exit 3".into()];
        let p = CommandProvider::from_config(&json!({ "revoke": bad })).unwrap();
        let c = SecretValue::new("x");
        assert!(matches!(
            p.revoke(&c, "1").await,
            Err(WardenError::Provider(m)) if m.contains("exited with 3")
        ));
        assert!(matches!(
            p.verify(&c).await,
            Err(WardenError::ProviderUnsupported(_))
        ));
        assert!(!p.capabilities().self_rotate && p.capabilities().revoke);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn chatty_script_does_not_stall() {
        let chatty = vec![
            "sh".to_string(),
            "-c".into(),
            "head -c 400000 /dev/zero | tr '\0' a; head -c 400000 /dev/zero | tr '\0' b >&2; cat >/dev/null"
                .into(),
        ];
        let p = CommandProvider::from_config(&json!({ "revoke": chatty })).unwrap();
        let big = SecretValue::new("x".repeat(1_000_000));
        let t = std::time::Instant::now();
        p.revoke(&big, "1").await.unwrap();
        assert!(t.elapsed() < std::time::Duration::from_secs(10));
    }
}
