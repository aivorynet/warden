//! IPC wire types between the daemon and its clients.
//!
//! There is no request that returns a stored secret value. The only secret in a response
//! is the pairing token in [`Response::Paired`], which the client needs once.

use crate::secret::expose;
use crate::{
    DeviceId, InboxId, Item, ItemId, McpPolicy, ProviderRef, RotationPolicy, SecretValue, Settings,
    SinkSpec, item::ItemKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a paired client may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// CLI and desktop app: everything.
    Full,
    /// MCP server: list metadata, HTTP requests with a secret, rotation requests.
    McpUse,
    /// MCP server: `McpUse` plus policy changes.
    McpAdmin,
    /// Native messaging host: add to the inbox only.
    InboxWrite,
}

impl Capability {
    /// Return true when a client with this capability may send `req`.
    pub fn allows(self, req: &Request) -> bool {
        use Request::*;
        match self {
            Capability::Full => true,
            Capability::McpUse => matches!(
                req,
                Status | ListItems | GetItem { .. } | RotateNow { .. } | McpHttpRequest { .. }
            ),
            Capability::McpAdmin => {
                Capability::McpUse.allows(req) || matches!(req, UpdatePolicy { .. })
            }
            Capability::InboxWrite => matches!(req, InboxAdd { .. }),
        }
    }
}

/// Item data that the user enters, without the secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemDraft {
    /// Display name.
    pub name: String,
    /// Slug for token names.
    pub slug: String,
    /// Admin or derived.
    pub kind: ItemKind,
    /// Provider and configuration.
    pub provider: ProviderRef,
    /// End date of the token.
    pub expires_at: Option<DateTime<Utc>>,
    /// Rotation policy.
    pub policy: RotationPolicy,
    /// Sinks.
    pub sinks: Vec<SinkSpec>,
    /// MCP policy.
    pub mcp: McpPolicy,
    /// Tags.
    pub tags: Vec<String>,
}

/// Short view of an item for lists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemSummary {
    /// Item id.
    pub id: ItemId,
    /// Display name.
    pub name: String,
    /// Provider type.
    pub provider: crate::ProviderKind,
    /// Admin or derived.
    pub kind: ItemKind,
    /// End date of the token.
    pub expires_at: Option<DateTime<Utc>>,
    /// Next planned rotation.
    pub next_rotation: Option<DateTime<Utc>>,
    /// Number of sinks.
    pub sink_count: usize,
    /// Auto-rotate on or off.
    pub auto_rotate: bool,
}

/// State of the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Daemon version.
    pub version: String,
    /// The vault is locked.
    pub locked: bool,
    /// This device.
    pub device_id: DeviceId,
    /// Number of items (0 when locked).
    pub item_count: usize,
    /// Number of pending inbox entries.
    pub inbox_count: usize,
}

/// A token that waits in the inbox (no value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Entry id.
    pub id: InboxId,
    /// Origin of the page that the token came from.
    pub origin: String,
    /// Label that the user or the page gave.
    pub label: String,
    /// Time of capture.
    pub captured_at: DateTime<Utc>,
}

/// Coffee reminder state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoffeeInfo {
    /// Year of the valid receipt, if any.
    pub paid_year: Option<i32>,
    /// A reminder is due now.
    pub reminder_due: bool,
    /// Link to pay.
    pub link: String,
}

/// One audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Time.
    pub at: DateTime<Utc>,
    /// Device that wrote the entry.
    pub device: DeviceId,
    /// Item concerned, if any.
    pub item: Option<ItemId>,
    /// Action name.
    pub action: String,
    /// Detail text. Never a secret.
    pub detail: String,
}

/// Request from a client to the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Daemon status.
    Status,
    /// List items.
    ListItems,
    /// Get one item (metadata only).
    GetItem {
        /// Item id.
        item: ItemId,
    },
    /// Add an item with its first secret value.
    AddItem {
        /// Item data.
        draft: ItemDraft,
        /// The admin token or key.
        #[serde(serialize_with = "expose::serialize")]
        secret: SecretValue,
    },
    /// Change the rotation policy of an item.
    UpdatePolicy {
        /// Item id.
        item: ItemId,
        /// New policy.
        policy: RotationPolicy,
    },
    /// Rotate an item now.
    RotateNow {
        /// Item id.
        item: ItemId,
    },
    /// Delete an item.
    DeleteItem {
        /// Item id.
        item: ItemId,
    },
    /// Unlock the vault.
    Unlock {
        /// Vault password.
        #[serde(serialize_with = "expose::serialize")]
        password: SecretValue,
        /// Secret Key.
        #[serde(serialize_with = "expose::serialize")]
        secret_key: SecretValue,
    },
    /// Lock the vault.
    Lock,
    /// List pending inbox entries.
    InboxList,
    /// Add a captured token to the inbox.
    InboxAdd {
        /// Origin of the page.
        origin: String,
        /// Label.
        label: String,
        /// The captured value.
        #[serde(serialize_with = "expose::serialize")]
        value: SecretValue,
    },
    /// Accept an inbox entry as a new item.
    InboxAccept {
        /// Entry id.
        id: InboxId,
        /// Item data. The inbox value becomes the secret.
        draft: ItemDraft,
    },
    /// Reject an inbox entry.
    InboxReject {
        /// Entry id.
        id: InboxId,
    },
    /// Pair a new client.
    Pair {
        /// Client name.
        name: String,
        /// Requested capabilities.
        capabilities: Vec<Capability>,
    },
    /// HTTP request with the secret of an item injected by the daemon.
    McpHttpRequest {
        /// Item whose secret goes into the header.
        item: ItemId,
        /// HTTP method.
        method: String,
        /// URL (HTTPS only).
        url: String,
        /// Extra headers.
        headers: BTreeMap<String, String>,
        /// Request body.
        body: Option<String>,
    },
    /// Read the settings.
    GetSettings,
    /// Change the settings.
    SetSettings {
        /// New settings.
        settings: Settings,
    },
    /// Read the coffee reminder state.
    CoffeeStatus,
    /// Enter a coffee receipt code.
    CoffeeReceipt {
        /// Receipt code.
        code: String,
    },
    /// List audit entries.
    AuditList {
        /// Only entries of this item.
        item: Option<ItemId>,
        /// Maximum number of entries.
        limit: u32,
    },
}

/// Response from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Success without data.
    Ok,
    /// Failure.
    Error {
        /// Error kind, for example `locked`, `forbidden`, `not_found`.
        code: String,
        /// Human-readable message. Never a secret.
        message: String,
    },
    /// Daemon status.
    Status(StatusInfo),
    /// Item list.
    Items {
        /// The items.
        items: Vec<ItemSummary>,
    },
    /// One item.
    Item(Box<Item>),
    /// An item was added.
    Added {
        /// Id of the new item.
        item: ItemId,
    },
    /// Settings.
    Settings(Settings),
    /// Inbox list.
    Inbox {
        /// The entries.
        inbox: Vec<InboxEntry>,
    },
    /// An inbox entry was added.
    InboxAdded {
        /// Id of the new entry.
        id: InboxId,
    },
    /// A client was paired. The token is the only secret that a response carries.
    Paired {
        /// Granted capabilities.
        capabilities: Vec<Capability>,
        /// The pairing token (`aivw_...`).
        #[serde(serialize_with = "expose::serialize")]
        token: SecretValue,
    },
    /// Result of an HTTP request.
    McpHttpResponse {
        /// HTTP status code.
        status: u16,
        /// Response headers.
        headers: BTreeMap<String, String>,
        /// Response body (redacted).
        body: String,
    },
    /// Coffee reminder state.
    Coffee(CoffeeInfo),
    /// Audit entries.
    Audit {
        /// The entries.
        audit: Vec<AuditEntry>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_carries_secret_on_the_wire_only() {
        let req = Request::Unlock {
            password: SecretValue::new("pw"),
            secret_key: SecretValue::new("sk"),
        };
        assert!(!format!("{req:?}").contains("pw\""));
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains(r#""type":"unlock""#));
        let back: Request = serde_json::from_str(&j).unwrap();
        match back {
            Request::Unlock { password, .. } => assert_eq!(password.expose(), "pw"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unit_variants_serialize() {
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"type":"status"}"#
        );
        let r: Response = serde_json::from_str(r#"{"type":"ok"}"#).unwrap();
        assert!(matches!(r, Response::Ok));
    }

    #[test]
    fn capabilities() {
        let add = Request::InboxAdd {
            origin: "o".into(),
            label: "l".into(),
            value: SecretValue::new("v"),
        };
        assert!(Capability::InboxWrite.allows(&add));
        assert!(!Capability::InboxWrite.allows(&Request::ListItems));
        assert!(!Capability::McpUse.allows(&Request::Lock));
        assert!(!Capability::McpUse.allows(&Request::DeleteItem {
            item: ItemId::new()
        }));
        assert!(Capability::McpAdmin.allows(&Request::UpdatePolicy {
            item: ItemId::new(),
            policy: RotationPolicy::default()
        }));
        assert!(Capability::Full.allows(&Request::Lock));
    }
}
