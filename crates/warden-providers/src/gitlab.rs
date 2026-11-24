//! GitLab provider: personal access token self-rotate, project access tokens.

use crate::http::{Http, cfg_str, check_name, json};
use async_trait::async_trait;
use chrono::{DateTime, Days, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

const DEFAULT_BASE: &str = "https://gitlab.com/api/v4";
const DEFAULT_EXPIRY_DAYS: u64 = 30;

/// GitLab provider.
///
/// Config: `base_url` (API root, default `https://gitlab.com/api/v4`), `project_id`
/// (id or path, needed for `create_derived` and `revoke`), `access_level` (default 40),
/// `expiry_days` (default 30, used when the request has no end date).
#[derive(Debug)]
pub struct GitLab {
    http: Http,
    project_id: Option<String>,
    access_level: u32,
    expiry_days: u64,
}

#[derive(Deserialize)]
struct TokenBody {
    id: u64,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

fn parse_date(s: &Option<String>) -> Option<DateTime<Utc>> {
    let d = NaiveDate::parse_from_str(s.as_deref()?, "%Y-%m-%d").ok()?;
    Some(d.and_hms_opt(0, 0, 0)?.and_utc())
}

impl GitLab {
    /// Build from provider config.
    pub fn from_config(c: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            http: Http::new(cfg_str(c, "base_url").unwrap_or_else(|| DEFAULT_BASE.into()))?,
            project_id: cfg_str(c, "project_id"),
            access_level: c.get("access_level").and_then(|v| v.as_u64()).unwrap_or(40) as u32,
            expiry_days: c
                .get("expiry_days")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_EXPIRY_DAYS),
        })
    }

    fn project(&self) -> Result<String> {
        let p = self
            .project_id
            .clone()
            .ok_or_else(|| WardenError::Config("missing config key `project_id`".into()))?;
        Ok(p.replace('/', "%2F"))
    }

    fn end_date(&self, wanted: Option<DateTime<Utc>>) -> String {
        let d = wanted
            .map(|t| t.date_naive())
            .unwrap_or_else(|| Utc::now().date_naive() + Days::new(self.expiry_days));
        d.format("%Y-%m-%d").to_string()
    }
}

#[async_trait]
impl Provider for GitLab {
    fn class(&self) -> RotationClass {
        RotationClass::AtomicSwap
    }

    fn capabilities(&self) -> ProviderCaps {
        ProviderCaps {
            self_rotate: true,
            create_derived: true,
            revoke: true,
            naming: true,
        }
    }

    async fn verify(&self, cred: &SecretValue) -> Result<TokenInfo> {
        let rb = self
            .http
            .client
            .get(self.http.url("/personal_access_tokens/self"))
            .header("PRIVATE-TOKEN", cred.expose());
        let b: TokenBody = json(self.http.send(rb).await?).await?;
        Ok(TokenInfo {
            provider_token_id: b.id.to_string(),
            expires_at: parse_date(&b.expires_at),
            scopes: b.scopes,
        })
    }

    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        let rb = self
            .http
            .client
            .post(self.http.url("/personal_access_tokens/self/rotate"))
            .header("PRIVATE-TOKEN", cred.expose())
            .json(&json!({ "expires_at": self.end_date(req.expires_at) }));
        let b: TokenBody = json(self.http.send(rb).await?).await?;
        issued(b)
    }

    async fn create_derived(
        &self,
        admin: &SecretValue,
        req: &CreateRequest,
    ) -> Result<IssuedToken> {
        check_name(&req.token_name)?;
        let project = self.project()?;
        let level = req
            .config
            .get("access_level")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(self.access_level);
        let rb = self
            .http
            .client
            .post(self.http.url(&format!("/projects/{project}/access_tokens")))
            .header("PRIVATE-TOKEN", admin.expose())
            .json(&json!({
                "name": req.token_name,
                "scopes": req.scopes,
                "expires_at": self.end_date(req.expires_at),
                "access_level": level,
            }));
        let b: TokenBody = json(self.http.send(rb).await?).await?;
        issued(b)
    }

    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()> {
        let project = self.project()?;
        let rb = self
            .http
            .client
            .delete(self.http.url(&format!(
                "/projects/{project}/access_tokens/{provider_token_id}"
            )))
            .header("PRIVATE-TOKEN", admin.expose());
        self.http.send(rb).await?;
        Ok(())
    }
}

fn issued(b: TokenBody) -> Result<IssuedToken> {
    let value = b
        .token
        .clone()
        .ok_or_else(|| WardenError::Provider("response has no token value".into()))?;
    Ok(IssuedToken {
        value: SecretValue::new(value),
        provider_token_id: b.id.to_string(),
        expires_at: parse_date(&b.expires_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testutil::{create_req, rotate_req};
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn gl(server: &MockServer) -> GitLab {
        GitLab::from_config(&json!({"base_url": server.uri(), "project_id": "42"})).unwrap()
    }
    fn cred() -> SecretValue {
        SecretValue::new("glpat-test")
    }

    #[tokio::test]
    async fn verify_ok() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/personal_access_tokens/self"))
            .and(header("PRIVATE-TOKEN", "glpat-test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": 7, "scopes": ["api"], "expires_at": "2027-01-31"})),
            )
            .mount(&s)
            .await;
        let i = gl(&s).verify(&cred()).await.unwrap();
        assert_eq!(i.provider_token_id, "7");
        assert_eq!(i.scopes, vec!["api"]);
        assert_eq!(i.expires_at.unwrap().date_naive().to_string(), "2027-01-31");
    }

    #[tokio::test]
    async fn rotate_sets_expires_at() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/personal_access_tokens/self/rotate"))
            .and(wiremock::matchers::body_string_contains("expires_at"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"id": 8, "token": "glpat-new", "expires_at": "2026-12-24"}),
                ),
            )
            .mount(&s)
            .await;
        let t = gl(&s)
            .rotate_self(&cred(), &rotate_req(None))
            .await
            .unwrap();
        assert_eq!(t.value.expose(), "glpat-new");
        assert_eq!(t.provider_token_id, "8");
        assert!(t.expires_at.is_some());
    }

    #[tokio::test]
    async fn create_uses_aivw_name() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/projects/42/access_tokens"))
            .and(body_partial_json(
                json!({"name": "aivw_demo_20261124", "scopes": ["read_api"], "access_level": 40}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                json!({"id": 9, "token": "glpat-derived", "expires_at": "2026-12-24"}),
            ))
            .mount(&s)
            .await;
        let t = gl(&s)
            .create_derived(&cred(), &create_req("aivw_demo_20261124"))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "9");
        let bad = gl(&s).create_derived(&cred(), &create_req("demo")).await;
        assert!(matches!(bad, Err(WardenError::Config(_))));
    }

    #[tokio::test]
    async fn revoke_ok() {
        let s = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/projects/42/access_tokens/9"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        gl(&s).revoke(&cred(), "9").await.unwrap();
    }

    async fn status(code: u16, retry: Option<&str>) -> WardenError {
        let s = MockServer::start().await;
        let mut r = ResponseTemplate::new(code);
        if let Some(v) = retry {
            r = r.insert_header("Retry-After", v);
        }
        Mock::given(method("GET")).respond_with(r).mount(&s).await;
        gl(&s).verify(&cred()).await.unwrap_err()
    }

    #[tokio::test]
    async fn error_mapping() {
        assert!(matches!(
            status(401, None).await,
            WardenError::ProviderAuth(_)
        ));
        assert!(matches!(
            status(403, None).await,
            WardenError::ProviderAuth(_)
        ));
        match status(429, Some("17")).await {
            WardenError::ProviderRateLimited { retry_after } => {
                assert_eq!(retry_after, Some(std::time::Duration::from_secs(17)));
            }
            e => panic!("{e:?}"),
        }
        match status(503, None).await {
            WardenError::Provider(m) => assert!(m.starts_with("retryable")),
            e => panic!("{e:?}"),
        }
    }
}
