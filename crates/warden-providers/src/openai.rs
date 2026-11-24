//! OpenAI provider: admin API keys and project service accounts.

use crate::http::{Http, cfg_str, check_name, json};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

const DEFAULT_BASE: &str = "https://api.openai.com/v1";
const MAX_EXPIRY_SECS: i64 = 31_536_000;

/// OpenAI provider.
///
/// Config: `base_url` (default `https://api.openai.com/v1`), `project_id` (for
/// `create_derived`), `admin_key_id` (reported by `verify`).
///
/// Token ids: an admin key has its plain id. A service account has the id
/// `<project_id>/<service_account_id>`; `revoke` deletes the service account.
#[derive(Debug)]
pub struct OpenAi {
    http: Http,
    project_id: Option<String>,
    admin_key_id: Option<String>,
}

#[derive(Deserialize)]
struct AdminKey {
    id: String,
    value: String,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct ApiKey {
    id: String,
    value: String,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct ServiceAccount {
    id: String,
    api_key: Option<ApiKey>,
}

fn ts(t: Option<i64>) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(t?, 0)
}

fn body(name: &str, expires_at: Option<DateTime<Utc>>) -> Value {
    let mut b = json!({ "name": name });
    if let Some(e) = expires_at {
        let secs = (e - Utc::now()).num_seconds().clamp(1, MAX_EXPIRY_SECS);
        b["expires_in_seconds"] = json!(secs);
    }
    b
}

impl OpenAi {
    /// Build from provider config.
    pub fn from_config(c: &Value) -> Result<Self> {
        Ok(Self {
            http: Http::new(cfg_str(c, "base_url").unwrap_or_else(|| DEFAULT_BASE.into()))?,
            project_id: cfg_str(c, "project_id"),
            admin_key_id: cfg_str(c, "admin_key_id"),
        })
    }
}

#[async_trait]
impl Provider for OpenAi {
    fn class(&self) -> RotationClass {
        RotationClass::Overlap
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
        // The list endpoint answers 200 only for a valid admin key.
        let rb = self
            .http
            .client
            .get(self.http.url("/organization/admin_api_keys?limit=1"))
            .bearer_auth(cred.expose());
        self.http.send(rb).await?;
        Ok(TokenInfo {
            provider_token_id: self.admin_key_id.clone().unwrap_or_default(),
            expires_at: None,
            scopes: vec![],
        })
    }

    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        check_name(&req.token_name)?;
        let rb = self
            .http
            .client
            .post(self.http.url("/organization/admin_api_keys"))
            .bearer_auth(cred.expose())
            .json(&body(&req.token_name, req.expires_at));
        let k: AdminKey = json(self.http.send(rb).await?).await?;
        Ok(IssuedToken {
            value: SecretValue::new(k.value),
            provider_token_id: k.id,
            expires_at: ts(k.expires_at),
        })
    }

    async fn create_derived(
        &self,
        admin: &SecretValue,
        req: &CreateRequest,
    ) -> Result<IssuedToken> {
        check_name(&req.token_name)?;
        let project = self
            .project_id
            .clone()
            .ok_or_else(|| WardenError::Config("missing config key `project_id`".into()))?;
        let rb = self
            .http
            .client
            .post(self.http.url(&format!(
                "/organization/projects/{project}/service_accounts"
            )))
            .bearer_auth(admin.expose())
            .json(&body(&req.token_name, req.expires_at));
        let sa: ServiceAccount = json(self.http.send(rb).await?).await?;
        let key = sa
            .api_key
            .ok_or_else(|| WardenError::Provider("response has no api_key".into()))?;
        let _ = key.id;
        Ok(IssuedToken {
            value: SecretValue::new(key.value),
            provider_token_id: format!("{project}/{}", sa.id),
            expires_at: ts(key.expires_at),
        })
    }

    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()> {
        let path = match provider_token_id.split_once('/') {
            Some((project, sa)) => {
                format!("/organization/projects/{project}/service_accounts/{sa}")
            }
            None => format!("/organization/admin_api_keys/{provider_token_id}"),
        };
        let rb = self
            .http
            .client
            .delete(self.http.url(&path))
            .bearer_auth(admin.expose());
        self.http.send(rb).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testutil::{create_req, rotate_req};
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn oa(s: &MockServer) -> OpenAi {
        OpenAi::from_config(&json!({"base_url": s.uri(), "project_id": "proj_1"})).unwrap()
    }
    fn cred() -> SecretValue {
        SecretValue::new("sk-admin-old")
    }

    #[tokio::test]
    async fn verify_ok() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/organization/admin_api_keys"))
            .and(header("authorization", "Bearer sk-admin-old"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": []})),
            )
            .mount(&s)
            .await;
        oa(&s).verify(&cred()).await.unwrap();
    }

    #[tokio::test]
    async fn rotate_creates_admin_key() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/organization/admin_api_keys"))
            .and(body_partial_json(json!({"name": "aivw_demo_20261124"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"id": "key_2", "value": "sk-admin-new", "expires_at": null}),
                ),
            )
            .mount(&s)
            .await;
        let t = oa(&s)
            .rotate_self(&cred(), &rotate_req(Some("key_1")))
            .await
            .unwrap();
        assert_eq!(t.value.expose(), "sk-admin-new");
        assert_eq!(t.provider_token_id, "key_2");
    }

    #[tokio::test]
    async fn create_service_account_and_revoke() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/organization/projects/proj_1/service_accounts"))
            .and(body_partial_json(json!({"name": "aivw_demo_20261124"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "svc_1", "name": "aivw_demo_20261124",
                "api_key": {"id": "k1", "value": "sk-svc", "expires_at": 1893456000}
            })))
            .mount(&s)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/organization/projects/proj_1/service_accounts/svc_1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": "svc_1", "deleted": true})),
            )
            .mount(&s)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/organization/admin_api_keys/key_1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": "key_1", "deleted": true})),
            )
            .mount(&s)
            .await;
        let p = oa(&s);
        let t = p
            .create_derived(&cred(), &create_req("aivw_demo_20261124"))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "proj_1/svc_1");
        assert!(t.expires_at.is_some());
        p.revoke(&cred(), &t.provider_token_id).await.unwrap();
        p.revoke(&cred(), "key_1").await.unwrap();
        let bad = p.create_derived(&cred(), &create_req("demo")).await;
        assert!(matches!(bad, Err(WardenError::Config(_))));
    }

    async fn status(code: u16, retry: Option<&str>) -> WardenError {
        let s = MockServer::start().await;
        let mut r = ResponseTemplate::new(code);
        if let Some(v) = retry {
            r = r.insert_header("Retry-After", v);
        }
        Mock::given(method("GET")).respond_with(r).mount(&s).await;
        oa(&s).verify(&cred()).await.unwrap_err()
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
        assert!(matches!(
            status(429, Some("9")).await,
            WardenError::ProviderRateLimited {
                retry_after: Some(d)
            } if d.as_secs() == 9
        ));
        assert!(matches!(status(502, None).await, WardenError::Provider(_)));
    }
}
