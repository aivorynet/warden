//! Shared HTTP helpers: client, status mapping, header redaction, config access.

use reqwest::{Client, RequestBuilder, Response, StatusCode, header::HeaderMap};
use serde::de::DeserializeOwned;
use std::time::Duration;
use warden_core::{Result, WardenError};

/// Request timeout for every provider call.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP client with a base URL.
pub(crate) struct Http {
    pub(crate) client: Client,
    pub(crate) base: String,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").field("base", &self.base).finish()
    }
}

impl Http {
    pub(crate) fn new(base: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| WardenError::Config(format!("http client: {e}")))?;
        Ok(Self {
            client,
            base: base.into().trim_end_matches('/').to_string(),
        })
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Send a request and map the HTTP status to a `WardenError`.
    pub(crate) async fn send(&self, rb: RequestBuilder) -> Result<Response> {
        self.send_with(rb, false).await
    }

    /// Like `send`; when `throttle_in_body` is set, a body with a throttling code counts as 429.
    pub(crate) async fn send_with(
        &self,
        rb: RequestBuilder,
        throttle_in_body: bool,
    ) -> Result<Response> {
        let req = rb.build().map_err(net_err)?;
        tracing::debug!(
            method = %req.method(),
            url = %req.url(),
            headers = %fmt_headers(req.headers()),
            "provider request"
        );
        let resp = self.client.execute(req).await.map_err(net_err)?;
        map_status(resp, throttle_in_body).await
    }
}

/// Convert a transport error. The message never holds the URL.
pub(crate) fn net_err(e: reqwest::Error) -> WardenError {
    let e = e.without_url();
    if e.is_timeout() {
        WardenError::Provider("retryable: request timed out".into())
    } else {
        WardenError::Provider(format!("retryable: request failed: {e}"))
    }
}

fn snippet(body: &str) -> String {
    body.chars().take(200).collect()
}

async fn map_status(resp: Response, throttle_in_body: bool) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let body = resp.text().await.unwrap_or_default();
    Err(match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            WardenError::ProviderAuth(format!("HTTP {}: {}", status.as_u16(), snippet(&body)))
        }
        StatusCode::TOO_MANY_REQUESTS => WardenError::ProviderRateLimited { retry_after },
        _ if throttle_in_body
            && (body.contains("<Code>Throttling")
                || body.contains("<Code>RequestLimitExceeded")) =>
        {
            WardenError::ProviderRateLimited { retry_after }
        }
        s if s.is_server_error() => WardenError::Provider(format!(
            "retryable: HTTP {}: {}",
            s.as_u16(),
            snippet(&body)
        )),
        s => WardenError::Provider(format!("HTTP {}: {}", s.as_u16(), snippet(&body))),
    })
}

/// Parse a JSON response body.
pub(crate) async fn json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    resp.json::<T>()
        .await
        .map_err(|e| WardenError::Provider(format!("bad response body: {}", e.without_url())))
}

/// Format headers for debug output. Secret-bearing headers are redacted.
pub(crate) fn fmt_headers(h: &HeaderMap) -> String {
    const SECRET: [&str; 6] = [
        "authorization",
        "private-token",
        "x-amz-security-token",
        "proxy-authorization",
        "cookie",
        "x-auth-key",
    ];
    h.iter()
        .map(|(k, v)| {
            if SECRET.contains(&k.as_str()) {
                format!("{k}: [REDACTED]")
            } else {
                format!("{k}: {}", v.to_str().unwrap_or("?"))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read an optional string config key.
pub(crate) fn cfg_str(c: &serde_json::Value, key: &str) -> Option<String> {
    c.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Reject a token name without the `aivw_` prefix.
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.starts_with(warden_core::naming::PREFIX) {
        Ok(())
    } else {
        Err(WardenError::Config(format!(
            "token name must start with `{}`",
            warden_core::naming::PREFIX
        )))
    }
}

/// Error for an operation that a provider does not support.
pub(crate) fn unsupported<T>(what: &str) -> Result<T> {
    Err(WardenError::ProviderUnsupported(what.to_string()))
}

#[cfg(test)]
pub(crate) mod testutil {
    use warden_core::{CreateRequest, ItemId, RotateRequest};

    /// Test id.
    pub fn item_id() -> ItemId {
        ItemId::new()
    }

    pub fn rotate_req(id: Option<&str>) -> RotateRequest {
        RotateRequest {
            item_id: item_id(),
            token_name: "aivw_demo_20261124".into(),
            provider_token_id: id.map(str::to_string),
            config: serde_json::json!({}),
            expires_at: None,
        }
    }

    pub fn create_req(name: &str) -> CreateRequest {
        CreateRequest {
            item_id: item_id(),
            token_name: name.into(),
            config: serde_json::json!({}),
            scopes: vec!["read_api".into()],
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_headers() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc".parse().unwrap());
        h.insert("private-token", "glpat-xyz".parse().unwrap());
        h.insert("accept", "json".parse().unwrap());
        let s = fmt_headers(&h);
        assert!(!s.contains("abc") && !s.contains("glpat-xyz"));
        assert!(s.contains("accept: json"));
    }
}
