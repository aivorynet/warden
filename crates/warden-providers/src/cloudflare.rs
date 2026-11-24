//! Cloudflare provider: user API tokens (verify, roll, create, delete).

use crate::http::{Http, cfg_str, check_name, json};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare provider for user-owned API tokens.
///
/// Config: `base_url` (default `https://api.cloudflare.com/client/v4`), `policies`
/// (JSON array of token policies, needed for `create_derived`).
#[derive(Debug)]
pub struct Cloudflare {
    http: Http,
    policies: Option<Value>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct VerifyResult {
    id: String,
    status: String,
    #[serde(default)]
    expires_on: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct CreateResult {
    id: String,
    value: String,
    #[serde(default)]
    expires_on: Option<DateTime<Utc>>,
}

fn result<T>(e: Envelope<T>) -> Result<T> {
    match (e.success, e.result) {
        (true, Some(r)) => Ok(r),
        _ => Err(WardenError::Provider("cloudflare reported failure".into())),
    }
}

impl Cloudflare {
    /// Build from provider config.
    pub fn from_config(c: &Value) -> Result<Self> {
        Ok(Self {
            http: Http::new(cfg_str(c, "base_url").unwrap_or_else(|| DEFAULT_BASE.into()))?,
            policies: c.get("policies").filter(|p| p.is_array()).cloned(),
        })
    }

    async fn verify_inner(&self, cred: &SecretValue) -> Result<VerifyResult> {
        let rb = self
            .http
            .client
            .get(self.http.url("/user/tokens/verify"))
            .bearer_auth(cred.expose());
        let r = result(json::<Envelope<VerifyResult>>(self.http.send(rb).await?).await?)?;
        if r.status != "active" {
            return Err(WardenError::ProviderAuth(format!(
                "token status is {}",
                r.status
            )));
        }
        Ok(r)
    }
}

#[async_trait]
impl Provider for Cloudflare {
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
        let r = self.verify_inner(cred).await?;
        Ok(TokenInfo {
            provider_token_id: r.id,
            expires_at: r.expires_on,
            scopes: vec![],
        })
    }

    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        let id = match &req.provider_token_id {
            Some(id) => id.clone(),
            None => self.verify_inner(cred).await?.id,
        };
        let rb = self
            .http
            .client
            .put(self.http.url(&format!("/user/tokens/{id}/value")))
            .bearer_auth(cred.expose())
            .json(&json!({}));
        let new: String = result(json::<Envelope<String>>(self.http.send(rb).await?).await?)?;
        let new = SecretValue::new(new);
        // Verify the new value and read the end date. The roll keeps the token id.
        let v = self.verify_inner(&new).await?;
        Ok(IssuedToken {
            value: new,
            provider_token_id: id,
            expires_at: v.expires_on,
        })
    }

    async fn create_derived(
        &self,
        admin: &SecretValue,
        req: &CreateRequest,
    ) -> Result<IssuedToken> {
        check_name(&req.token_name)?;
        let policies = self
            .policies
            .clone()
            .or_else(|| req.config.get("policies").filter(|p| p.is_array()).cloned())
            .ok_or_else(|| WardenError::Config("missing config key `policies`".into()))?;
        let mut body = json!({ "name": req.token_name, "policies": policies });
        if let Some(e) = req.expires_at {
            body["expires_on"] = json!(e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
        let rb = self
            .http
            .client
            .post(self.http.url("/user/tokens"))
            .bearer_auth(admin.expose())
            .json(&body);
        let r = result(json::<Envelope<CreateResult>>(self.http.send(rb).await?).await?)?;
        Ok(IssuedToken {
            value: SecretValue::new(r.value),
            provider_token_id: r.id,
            expires_at: r.expires_on,
        })
    }

    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()> {
        let rb = self
            .http
            .client
            .delete(self.http.url(&format!("/user/tokens/{provider_token_id}")))
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

    fn cf(s: &MockServer) -> Cloudflare {
        Cloudflare::from_config(&json!({
            "base_url": s.uri(),
            "policies": [{"effect": "allow", "permission_groups": [{"id": "x"}], "resources": {}}]
        }))
        .unwrap()
    }
    fn cred() -> SecretValue {
        SecretValue::new("cf-old")
    }
    fn verify_body(id: &str) -> Value {
        json!({"success": true, "result": {"id": id, "status": "active", "expires_on": "2027-01-01T00:00:00Z"}})
    }

    #[tokio::test]
    async fn verify_ok() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/tokens/verify"))
            .and(header("authorization", "Bearer cf-old"))
            .respond_with(ResponseTemplate::new(200).set_body_json(verify_body("tok1")))
            .mount(&s)
            .await;
        let i = cf(&s).verify(&cred()).await.unwrap();
        assert_eq!(i.provider_token_id, "tok1");
        assert!(i.expires_at.is_some());
    }

    #[tokio::test]
    async fn rotate_rolls_and_verifies() {
        let s = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/user/tokens/tok1/value"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"success": true, "result": "cf-new"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/tokens/verify"))
            .and(header("authorization", "Bearer cf-new"))
            .respond_with(ResponseTemplate::new(200).set_body_json(verify_body("tok1")))
            .mount(&s)
            .await;
        let t = cf(&s)
            .rotate_self(&cred(), &rotate_req(Some("tok1")))
            .await
            .unwrap();
        assert_eq!(t.value.expose(), "cf-new");
        assert_eq!(t.provider_token_id, "tok1");
    }

    #[tokio::test]
    async fn create_uses_aivw_name() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/user/tokens"))
            .and(body_partial_json(json!({"name": "aivw_demo_20261124"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"success": true, "result": {"id": "t2", "value": "cf-derived"}}),
            ))
            .mount(&s)
            .await;
        let t = cf(&s)
            .create_derived(&cred(), &create_req("aivw_demo_20261124"))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "t2");
        let bad = cf(&s).create_derived(&cred(), &create_req("demo")).await;
        assert!(matches!(bad, Err(WardenError::Config(_))));
    }

    #[tokio::test]
    async fn revoke_ok() {
        let s = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/user/tokens/t2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"success": true, "result": {"id": "t2"}})),
            )
            .mount(&s)
            .await;
        cf(&s).revoke(&cred(), "t2").await.unwrap();
    }

    async fn status(code: u16, retry: Option<&str>) -> WardenError {
        let s = MockServer::start().await;
        let mut r = ResponseTemplate::new(code);
        if let Some(v) = retry {
            r = r.insert_header("Retry-After", v);
        }
        Mock::given(method("GET")).respond_with(r).mount(&s).await;
        cf(&s).verify(&cred()).await.unwrap_err()
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
            status(429, Some("5")).await,
            WardenError::ProviderRateLimited {
                retry_after: Some(d)
            } if d.as_secs() == 5
        ));
        assert!(matches!(status(500, None).await, WardenError::Provider(_)));
    }
}
