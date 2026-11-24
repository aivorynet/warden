//! The vault item model.

use crate::{DeviceId, ItemId, McpPolicy, RotationPolicy, SinkSpec};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Kind of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemKind {
    /// An admin credential that the user stores.
    Admin,
    /// A token that Warden creates with a parent admin item.
    Derived {
        /// The admin item that creates this token.
        parent: ItemId,
    },
}

/// Provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// GitLab.
    GitLab,
    /// AWS IAM.
    AwsIam,
    /// Cloudflare.
    Cloudflare,
    /// OpenAI.
    OpenAi,
    /// A user script.
    Command,
    /// Reminder only.
    Manual,
}

/// Provider type and its configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderRef {
    /// Provider type.
    pub kind: ProviderKind,
    /// Provider-specific configuration (base URL, project id, ...). Never a secret.
    pub config: serde_json::Value,
}

/// A token that Warden manages. The secret value is not part of the item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// Item id.
    pub id: ItemId,
    /// Display name.
    pub name: String,
    /// Short name for token names (`aivw_<slug>_<date>`).
    pub slug: String,
    /// Admin or derived.
    pub kind: ItemKind,
    /// Provider of the token.
    pub provider: ProviderRef,
    /// Id of the current token at the provider.
    pub provider_token_id: Option<String>,
    /// End date of the current token.
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation time of the item.
    pub created_at: DateTime<Utc>,
    /// Time of the last rotation.
    pub rotated_at: Option<DateTime<Utc>>,
    /// Rotation policy.
    pub policy: RotationPolicy,
    /// Places that receive the token.
    pub sinks: Vec<SinkSpec>,
    /// MCP use policy.
    pub mcp: McpPolicy,
    /// The one device that rotates this token.
    pub rotator_device: DeviceId,
    /// Free tags.
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_serde() {
        let k = ItemKind::Derived {
            parent: ItemId::new(),
        };
        let v = serde_json::to_value(k).unwrap();
        assert_eq!(v["type"], "derived");
        assert_eq!(serde_json::from_value::<ItemKind>(v).unwrap(), k);
        assert_eq!(
            serde_json::to_value(ProviderKind::AwsIam).unwrap(),
            "aws_iam"
        );
    }
}
