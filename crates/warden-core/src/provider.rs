//! The `Provider` trait and its request and result types.

use crate::{ItemId, Result, SecretValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How a provider rotates a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationClass {
    /// Create new, write sinks, verify, wait for grace, revoke old.
    Overlap,
    /// The old value dies when the new one is issued. Journal first, retry forward.
    AtomicSwap,
}

/// What a provider supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCaps {
    /// Admin token can rotate itself.
    pub self_rotate: bool,
    /// Provider can create derived tokens.
    pub create_derived: bool,
    /// Provider can revoke tokens.
    pub revoke: bool,
    /// Provider has a name field, so the `aivw_` name applies.
    pub naming: bool,
}

/// A token that a provider issued.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    /// The new secret value.
    pub value: SecretValue,
    /// Id of the token at the provider.
    pub provider_token_id: String,
    /// End date of the token.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Facts about a token that the provider reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Id of the token at the provider.
    pub provider_token_id: String,
    /// End date of the token.
    pub expires_at: Option<DateTime<Utc>>,
    /// Scopes of the token.
    pub scopes: Vec<String>,
}

/// Input of `rotate_self`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotateRequest {
    /// The item that rotates.
    pub item_id: ItemId,
    /// Name for the new token (`aivw_<slug>_<yyyymmdd>`), if the provider supports names.
    pub token_name: String,
    /// Id of the current token at the provider.
    pub provider_token_id: Option<String>,
    /// Provider configuration of the item.
    pub config: serde_json::Value,
    /// Wanted end date of the new token.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Input of `create_derived`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// The derived item.
    pub item_id: ItemId,
    /// Name for the new token (`aivw_<slug>_<yyyymmdd>`).
    pub token_name: String,
    /// Provider configuration of the derived item.
    pub config: serde_json::Value,
    /// Wanted scopes.
    pub scopes: Vec<String>,
    /// Wanted end date.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A token provider (GitLab, AWS IAM, ...).
#[async_trait]
pub trait Provider: Send + Sync {
    /// Rotation class of this provider.
    fn class(&self) -> RotationClass;
    /// What the provider supports.
    fn capabilities(&self) -> ProviderCaps;
    /// Check a credential and return its facts.
    async fn verify(&self, cred: &SecretValue) -> Result<TokenInfo>;
    /// Rotate a credential with itself.
    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken>;
    /// Create a derived token with an admin credential.
    async fn create_derived(&self, admin: &SecretValue, req: &CreateRequest)
    -> Result<IssuedToken>;
    /// Revoke a token with an admin credential.
    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WardenError;

    struct Mock;

    #[async_trait]
    impl Provider for Mock {
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
        async fn verify(&self, _: &SecretValue) -> Result<TokenInfo> {
            Err(WardenError::ProviderUnsupported("verify".into()))
        }
        async fn rotate_self(&self, _: &SecretValue, _: &RotateRequest) -> Result<IssuedToken> {
            Err(WardenError::ProviderUnsupported("rotate".into()))
        }
        async fn create_derived(&self, _: &SecretValue, _: &CreateRequest) -> Result<IssuedToken> {
            Err(WardenError::ProviderUnsupported("create".into()))
        }
        async fn revoke(&self, _: &SecretValue, _: &str) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn usable_as_trait_object() {
        let p: Box<dyn Provider> = Box::new(Mock);
        assert_eq!(p.class(), RotationClass::Overlap);
        assert!(p.verify(&SecretValue::new("x")).await.is_err());
        assert!(p.revoke(&SecretValue::new("x"), "id").await.is_ok());
    }
}
