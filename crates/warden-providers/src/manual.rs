//! Manual provider: reminder only. Nothing is automated.

use crate::http::{cfg_str, unsupported};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

/// Manual provider. `verify` returns the stored expiry; all else is unsupported.
///
/// Config: `expires_at` (RFC 3339), `provider_token_id` (both optional).
#[derive(Debug, Default)]
pub struct Manual {
    expires_at: Option<DateTime<Utc>>,
    token_id: String,
}

impl Manual {
    /// Build from provider config.
    pub fn from_config(c: &serde_json::Value) -> Result<Self> {
        let expires_at = match cfg_str(c, "expires_at") {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| WardenError::Config(format!("bad `expires_at`: {e}")))?
                    .with_timezone(&Utc),
            ),
            None => None,
        };
        Ok(Self {
            expires_at,
            token_id: cfg_str(c, "provider_token_id").unwrap_or_default(),
        })
    }
}

#[async_trait]
impl Provider for Manual {
    fn class(&self) -> RotationClass {
        RotationClass::Overlap
    }

    fn capabilities(&self) -> ProviderCaps {
        ProviderCaps {
            self_rotate: false,
            create_derived: false,
            revoke: false,
            naming: false,
        }
    }

    async fn verify(&self, _cred: &SecretValue) -> Result<TokenInfo> {
        Ok(TokenInfo {
            provider_token_id: self.token_id.clone(),
            expires_at: self.expires_at,
            scopes: vec![],
        })
    }

    async fn rotate_self(&self, _: &SecretValue, _: &RotateRequest) -> Result<IssuedToken> {
        unsupported("manual provider: rotate_self (reminder only)")
    }

    async fn create_derived(&self, _: &SecretValue, _: &CreateRequest) -> Result<IssuedToken> {
        unsupported("manual provider: create_derived (reminder only)")
    }

    async fn revoke(&self, _: &SecretValue, _: &str) -> Result<()> {
        unsupported("manual provider: revoke (reminder only)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testutil::{create_req, rotate_req};
    use serde_json::json;

    #[tokio::test]
    async fn only_verify_works() {
        let p = Manual::from_config(&json!({"expires_at": "2027-03-01T00:00:00Z"})).unwrap();
        let c = SecretValue::new("x");
        let i = p.verify(&c).await.unwrap();
        assert_eq!(
            i.expires_at.unwrap().to_rfc3339(),
            "2027-03-01T00:00:00+00:00"
        );
        assert!(matches!(
            p.rotate_self(&c, &rotate_req(None)).await,
            Err(WardenError::ProviderUnsupported(_))
        ));
        assert!(matches!(
            p.create_derived(&c, &create_req("aivw_x")).await,
            Err(WardenError::ProviderUnsupported(_))
        ));
        assert!(matches!(
            p.revoke(&c, "1").await,
            Err(WardenError::ProviderUnsupported(_))
        ));
        let caps = p.capabilities();
        assert!(!(caps.self_rotate || caps.create_derived || caps.revoke || caps.naming));
    }
}
