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
    /// Build a client. `base` must be https. A loopback http URL is allowed only in tests
    /// or when `allow_insecure_loopback` is set.
    pub(crate) fn new(base: impl Into<String>, allow_insecure_loopback: bool) -> Result<Self> {
        let base: String = base.into();
        check_base(&base, allow_insecure_loopback)?;
        let client = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| WardenError::Config(format!("http client: {e}")))?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
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

/// Maximum size of a provider response body.
pub(crate) const MAX_BODY: usize = 1024 * 1024;

fn check_base(base: &str, allow_loopback: bool) -> Result<()> {
    let u =
        reqwest::Url::parse(base).map_err(|e| WardenError::Config(format!("bad base_url: {e}")))?;
    match u.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = u.host_str().is_some_and(|h| {
                let h = h.trim_start_matches('[').trim_end_matches(']');
                h.eq_ignore_ascii_case("localhost")
                    || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
            });
            if loopback && (cfg!(test) || allow_loopback) {
                Ok(())
            } else {
                Err(WardenError::Config(
                    "base_url must use https (http loopback needs `allow_insecure_loopback`)"
                        .into(),
                ))
            }
        }
        s => Err(WardenError::Config(format!(
            "base_url scheme `{s}` not allowed"
        ))),
    }
}

/// Read a response body with a size cap.
pub(crate) async fn read_capped(mut resp: Response) -> Result<Vec<u8>> {
    let too_big = || WardenError::Provider("response body too large".into());
    if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(net_err)? {
        if buf.len() + chunk.len() > MAX_BODY {
            return Err(too_big());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a response body as text with a size cap.
pub(crate) async fn text_capped(resp: Response) -> Result<String> {
    Ok(String::from_utf8_lossy(&read_capped(resp).await?).into_owned())
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
    let body = text_capped(resp).await.unwrap_or_default();
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
    let bytes = read_capped(resp).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| WardenError::Provider(format!("bad response body: {e}")))
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

/// Read the optional `allow_insecure_loopback` config flag.
pub(crate) fn cfg_loopback(c: &serde_json::Value) -> bool {
    c.get("allow_insecure_loopback")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
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

    #[test]
    fn refuses_plain_http_for_remote_hosts() {
        assert!(Http::new("http://example.com/api", true).is_err());
        assert!(Http::new("http://10.0.0.1/api", true).is_err());
        assert!(Http::new("ftp://localhost", true).is_err());
        assert!(Http::new("https://example.com/api", false).is_ok());
        assert!(Http::new("http://127.0.0.1:8080", true).is_ok());
    }

    #[tokio::test]
    async fn caps_response_size() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; MAX_BODY + 1]))
            .mount(&s)
            .await;
        let h = Http::new(s.uri(), true).unwrap();
        let r = h.send(h.client.get(h.url("/"))).await.unwrap();
        assert!(read_capped(r).await.is_err());
    }
}
