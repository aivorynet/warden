//! The stdio MCP server. It forwards each tool call to the daemon over IPC.

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use warden_core::ipc::{ItemSummary, Request, Response};
use warden_core::{Item, ItemId, WardenError};
use warden_ipc::Client;

const DAY: u64 = 24 * 60 * 60;

const INSTRUCTIONS: &str = "Aivory Warden manages secrets for you. It never returns a secret \
value. Use http_request to call an API with a secret. The daemon adds the secret to the request \
and removes it from the answer.";

/// Arguments of `http_request`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HttpRequestArgs {
    /// Name of the secret (see `list_secrets`).
    pub secret: String,
    /// HTTP method, for example GET or POST.
    pub method: String,
    /// HTTPS URL. The host must be in the allowed hosts of the secret.
    pub url: String,
    /// Extra request headers. Do not set the secret header, Authorization or Cookie.
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    /// Request body (text).
    #[serde(default)]
    pub body: Option<String>,
}

/// Arguments of tools that take only a secret name.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SecretArgs {
    /// Name of the secret (see `list_secrets`).
    pub secret: String,
}

/// Arguments of `set_policy`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetPolicyArgs {
    /// Name of the secret (see `list_secrets`).
    pub secret: String,
    /// Turn automatic rotation on or off.
    #[serde(default)]
    pub auto_rotate: Option<bool>,
    /// Rotation interval in days.
    #[serde(default)]
    pub interval_days: Option<u32>,
    /// Rotate this many days before the end date.
    #[serde(default)]
    pub lead_days: Option<u32>,
}

/// The MCP server state. One daemon connection, shared by all tool calls.
#[derive(Debug, Clone)]
pub struct WardenMcp {
    client: Arc<Mutex<Client>>,
    tool_router: ToolRouter<Self>,
}

fn describe_error(code: &str, message: &str) -> String {
    let hint = match code {
        "needs_confirmation" | "confirmation_required" => {
            " Action needed: the user must confirm this in the Warden desktop app."
        }
        "rate_limited" | "rate_limit" => {
            " Rotation is limited to 1 per secret per hour. Try again later."
        }
        "forbidden" => " This client has no permission for this action.",
        "locked" => " The vault is locked. The user must unlock it.",
        _ => "",
    };
    format!("{code}: {message}.{hint}").replace("..", ".")
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn iso(t: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    t.map_or(Value::Null, |t| Value::String(t.to_rfc3339()))
}

fn status_of(s: &ItemSummary) -> &'static str {
    match s.expires_at {
        None => "no_expiry",
        Some(e) => {
            let left = e - chrono::Utc::now();
            if left <= chrono::Duration::zero() {
                "expired"
            } else if left < chrono::Duration::days(7) {
                "expiring_soon"
            } else {
                "ok"
            }
        }
    }
}

impl WardenMcp {
    /// Create the server around a connected IPC client.
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            tool_router: Self::tool_router(),
        }
    }

    async fn call(&self, req: Request) -> Result<Response, String> {
        let mut c = self.client.lock().await;
        c.call(req).await.map_err(|e| match e {
            WardenError::Ipc(m) => format!("daemon connection failed: {m}"),
            other => format!("daemon call failed: {other}"),
        })
    }

    async fn list(&self) -> Result<Vec<ItemSummary>, String> {
        match self.call(Request::ListItems).await? {
            Response::Items { items } => Ok(items),
            Response::Error { code, message } => Err(describe_error(&code, &message)),
            _ => Err("unexpected answer from the daemon".into()),
        }
    }

    async fn get(&self, id: ItemId) -> Result<Item, String> {
        match self.call(Request::GetItem { item: id }).await? {
            Response::Item(i) => Ok(*i),
            Response::Error { code, message } => Err(describe_error(&code, &message)),
            _ => Err("unexpected answer from the daemon".into()),
        }
    }

    async fn resolve(&self, name: &str) -> Result<ItemId, String> {
        let items = self.list().await?;
        let exact: Vec<_> = items
            .iter()
            .filter(|i| i.name == name || i.id.to_string() == name)
            .collect();
        let found = if exact.is_empty() {
            items
                .iter()
                .filter(|i| i.name.eq_ignore_ascii_case(name))
                .collect()
        } else {
            exact
        };
        match found.as_slice() {
            [one] => Ok(one.id),
            [] => Err(format!(
                "no secret named `{name}`. Call list_secrets to see the names."
            )),
            _ => Err(format!("the name `{name}` is not unique")),
        }
    }
}

fn policy_json(item: &Item) -> Value {
    let days = |d: Duration| d.as_secs() as f64 / DAY as f64;
    json!({
        "secret": item.name,
        "auto_rotate": item.policy.auto_rotate,
        "interval_days": item.policy.interval.map(days),
        "lead_days": days(item.policy.lead_time),
        "grace_days": days(item.policy.grace),
        "allowed_hosts": item.mcp.allowed_hosts,
        "header_name": item.mcp.header_name,
        "run_with_secret": item.mcp.run_with_secret,
    })
}

#[tool_router]
impl WardenMcp {
    /// List the secrets that Warden manages. Metadata only.
    #[tool(
        description = "List the secrets that Warden manages: name, provider, status, next rotation and allowed hosts. Secret values are never returned."
    )]
    async fn list_secrets(&self) -> Result<String, String> {
        let items = self.list().await?;
        let mut out = Vec::new();
        for s in &items {
            let hosts = match self.get(s.id).await {
                Ok(i) => i.mcp.allowed_hosts,
                Err(_) => Vec::new(),
            };
            out.push(json!({
                "name": s.name,
                "provider": s.provider,
                "status": status_of(s),
                "expires_at": iso(s.expires_at),
                "next_rotation": iso(s.next_rotation),
                "auto_rotate": s.auto_rotate,
                "allowed_hosts": hosts,
            }));
        }
        Ok(pretty(&Value::Array(out)))
    }

    /// Send an HTTP request with a secret injected by the daemon.
    #[tool(
        description = "Send an HTTPS request with a secret. The daemon adds the secret to the request header and removes it from the answer, so the value is never returned. The host must be in the allowed hosts of the secret. No redirects are followed. Returns status, headers and body."
    )]
    async fn http_request(
        &self,
        Parameters(a): Parameters<HttpRequestArgs>,
    ) -> Result<String, String> {
        let item = self.resolve(&a.secret).await?;
        let req = Request::McpHttpRequest {
            item,
            method: a.method,
            url: a.url,
            headers: a.headers.unwrap_or_default(),
            body: a.body,
        };
        match self.call(req).await? {
            Response::McpHttpResponse {
                status,
                headers,
                body,
            } => Ok(pretty(
                &json!({ "status": status, "headers": headers, "body": body }),
            )),
            Response::Error { code, message } => Err(describe_error(&code, &message)),
            _ => Err("unexpected answer from the daemon".into()),
        }
    }

    /// Ask for a rotation of a secret.
    #[tool(
        description = "Request an immediate rotation of a secret. Limit: 1 per secret per hour. Some secrets need the user to confirm in the desktop app. The new value is never returned."
    )]
    async fn request_rotation(
        &self,
        Parameters(a): Parameters<SecretArgs>,
    ) -> Result<String, String> {
        let item = self.resolve(&a.secret).await?;
        match self.call(Request::RotateNow { item }).await? {
            Response::Ok => Ok(format!("Rotation of `{}` started.", a.secret)),
            Response::Error { code, message } => Err(describe_error(&code, &message)),
            other => Ok(format!(
                "Rotation of `{}` accepted ({}).",
                a.secret,
                kind(&other)
            )),
        }
    }

    /// Read the policy of a secret.
    #[tool(
        description = "Show the rotation policy and the allowed hosts of a secret. Secret values are never returned."
    )]
    async fn get_policy(&self, Parameters(a): Parameters<SecretArgs>) -> Result<String, String> {
        let id = self.resolve(&a.secret).await?;
        Ok(pretty(&policy_json(&self.get(id).await?)))
    }

    /// Change the rotation policy of a secret.
    #[tool(
        description = "Change the rotation policy of a secret (auto_rotate, interval_days, lead_days). Needs the mcp-admin permission. Turning rotation off needs confirmation in the desktop app. Secret values are never returned."
    )]
    async fn set_policy(&self, Parameters(a): Parameters<SetPolicyArgs>) -> Result<String, String> {
        let id = self.resolve(&a.secret).await?;
        let mut policy = self.get(id).await?.policy;
        if let Some(v) = a.auto_rotate {
            policy.auto_rotate = v;
        }
        if let Some(d) = a.interval_days {
            if d == 0 {
                return Err("interval_days must be 1 or more".into());
            }
            policy.interval = Some(Duration::from_secs(u64::from(d) * DAY));
        }
        if let Some(d) = a.lead_days {
            policy.lead_time = Duration::from_secs(u64::from(d) * DAY);
        }
        match self
            .call(Request::UpdatePolicy { item: id, policy })
            .await?
        {
            Response::Error { code, message } => Err(describe_error(&code, &message)),
            _ => Ok(pretty(&policy_json(&self.get(id).await?))),
        }
    }
}

fn kind(r: &Response) -> &'static str {
    match r {
        Response::Ok => "ok",
        _ => "response",
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WardenMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

/// Serve MCP over any reader and writer pair until the peer closes it.
pub async fn serve_io<R, W>(client: Client, reader: R, writer: W) -> warden_core::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let running = WardenMcp::new(client)
        .serve((reader, writer))
        .await
        .map_err(|e| WardenError::Ipc(format!("mcp start failed: {e}")))?;
    running
        .waiting()
        .await
        .map_err(|e| WardenError::Ipc(format!("mcp stopped: {e}")))?;
    Ok(())
}

/// Run the MCP server on stdin and stdout.
///
/// The function writes MCP frames to stdout and nothing else. It writes logs to stderr only
/// when the `WARDEN_LOG` variable is set (`error`, `warn`, `info`, `debug` or `trace`).
pub async fn serve_stdio(client: Client) -> warden_core::Result<()> {
    if let Ok(level) = std::env::var("WARDEN_LOG") {
        let level = level.parse().unwrap_or(tracing::Level::INFO);
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(level)
            .with_ansi(false)
            .try_init();
    }
    serve_io(client, tokio::io::stdin(), tokio::io::stdout()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolRequestParams;
    use warden_core::ipc::Capability;
    use warden_core::{
        ClientToken, DeviceId, ItemKind, McpPolicy, ProviderKind, ProviderRef, RotationPolicy,
    };
    use warden_ipc::{Handler, PairingStore, Server, Session};

    const SECRET: &str = "aivw_fixture_TOPSECRET_value_123";

    struct Store(String);
    #[async_trait::async_trait]
    impl PairingStore for Store {
        async fn lookup(&self, token: &ClientToken) -> Option<Vec<Capability>> {
            (token.expose() == self.0).then(|| vec![Capability::McpAdmin])
        }
    }

    /// Fake daemon. It holds a secret in memory and never sends it.
    struct Fake {
        id: ItemId,
        _secret: String,
    }

    impl Fake {
        fn item(&self) -> Item {
            Item {
                id: self.id,
                name: "gitlab-ci".into(),
                slug: "gitlab-ci".into(),
                kind: ItemKind::Admin,
                provider: ProviderRef {
                    kind: ProviderKind::GitLab,
                    config: json!({}),
                },
                provider_token_id: None,
                expires_at: None,
                created_at: chrono::Utc::now(),
                rotated_at: None,
                policy: RotationPolicy::default(),
                sinks: vec![],
                mcp: McpPolicy {
                    allowed_hosts: vec!["gitlab.com".into()],
                    ..McpPolicy::default()
                },
                rotator_device: DeviceId::new(),
                tags: vec![],
            }
        }
    }

    #[async_trait::async_trait]
    impl Handler for Fake {
        async fn handle(&self, _s: &Session, req: Request) -> Response {
            match req {
                Request::ListItems => Response::Items {
                    items: vec![ItemSummary {
                        id: self.id,
                        name: "gitlab-ci".into(),
                        provider: ProviderKind::GitLab,
                        kind: ItemKind::Admin,
                        expires_at: None,
                        next_rotation: None,
                        sink_count: 1,
                        auto_rotate: true,
                        status: Default::default(),
                        last_error: None,
                        next_retry: None,
                    }],
                },
                Request::GetItem { .. } => Response::Item(Box::new(self.item())),
                Request::RotateNow { .. } => Response::Error {
                    code: "needs_confirmation".into(),
                    message: "confirm in the desktop app".into(),
                },
                _ => Response::Ok,
            }
        }
    }

    #[tokio::test]
    async fn lists_tools_and_calls_list_secrets() {
        let token = ClientToken::generate().expose().to_string();
        #[cfg(unix)]
        let (path, _dir) = {
            let d = tempfile::tempdir().unwrap();
            (d.path().join("w.sock"), d)
        };
        #[cfg(windows)]
        let path = std::path::PathBuf::from(format!(
            r"\\.\pipe\aivory-warden-mcp-test-{}",
            std::process::id()
        ));
        let server = Server::bind(Some(&path))
            .unwrap()
            .with_pairing_store(Arc::new(Store(token.clone())));
        let handler = Arc::new(Fake {
            id: ItemId::new(),
            _secret: SECRET.into(),
        });
        tokio::spawn(server.serve(handler));

        let client = Client::connect(Some(&path), Some(&token)).await.unwrap();
        let (cw, sr) = tokio::io::duplex(65536);
        let (sw, cr) = tokio::io::duplex(65536);
        tokio::spawn(serve_io(client, sr, sw));

        let mcp = ().serve((cr, cw)).await.unwrap();
        let tools = mcp.list_all_tools().await.unwrap();
        let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "get_policy",
                "http_request",
                "list_secrets",
                "request_rotation",
                "set_policy"
            ]
        );
        assert!(!serde_json::to_string(&tools).unwrap().contains(SECRET));

        let r = mcp
            .call_tool(CallToolRequestParams::new("list_secrets"))
            .await
            .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("gitlab-ci") && text.contains("gitlab.com"));
        assert!(!text.contains(SECRET));

        let r = mcp
            .call_tool(
                CallToolRequestParams::new("request_rotation")
                    .with_arguments(json!({"secret": "gitlab-ci"}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("needs_confirmation") && text.contains("desktop app"));
        assert!(!text.contains(SECRET));
    }
}
