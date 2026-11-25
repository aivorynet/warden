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
            Capability::InboxWrite => matches!(req, InboxAdd { .. } | InboxList),
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

/// Health of an item as the engine reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    /// Nothing needs attention.
    #[default]
    Healthy,
    /// A rotation is due now.
    Due,
    /// A rotation runs now.
    Rotating,
    /// The last rotation attempt failed. See `last_error`.
    Failed,
    /// The provider is manual. Warden only reminds.
    Reminder,
}

/// A paired client, without its token or hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Short id for `Unpair`.
    pub id: String,
    /// Client name.
    pub name: String,
    /// Granted capabilities.
    pub capabilities: Vec<Capability>,
    /// Time of pairing.
    pub paired_at: DateTime<Utc>,
}

/// A device in the vault device registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device id.
    pub id: DeviceId,
    /// Display name.
    pub name: String,
    /// Number of items that this device rotates.
    pub is_rotator_for: u32,
    /// Time of the last change that this device wrote to the vault, if any.
    pub last_seen: Option<DateTime<Utc>>,
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
    /// Health from the engine state.
    #[serde(default)]
    pub status: ItemStatus,
    /// Error of the last failed attempt. Never a secret.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Next retry after a failure.
    #[serde(default)]
    pub next_retry: Option<DateTime<Utc>>,
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
    /// Provider guess from the page.
    #[serde(default)]
    pub provider_hint: Option<String>,
    /// End date that the user entered.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Coffee reminder state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoffeeInfo {
    /// Year that the user confirmed as paid, if any.
    pub paid_year: Option<i32>,
    /// A reminder is due now.
    pub reminder_due: bool,
    /// Link to pay: the bare donation link.
    pub link: String,
    /// The user signed the coffee pledge.
    #[serde(default)]
    pub pledged: bool,
    /// Ticket number of this install, for example `AIVW-2026-1234`.
    #[serde(default)]
    pub ticket: String,
    /// Price label shown next to the coffee button.
    #[serde(default)]
    pub price_label: String,
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
    /// Create a derived item. The daemon creates the first token at the provider with the
    /// admin item named in `draft.kind`, stores it and writes the sinks. `Full` only.
    CreateDerived {
        /// Item data. `draft.kind` must be `Derived`.
        draft: ItemDraft,
    },
    /// Move the rotator role of one item (or of every item) to another device. `Full` only.
    Handover {
        /// Item id. `None` moves every item.
        #[serde(default)]
        item: Option<ItemId>,
        /// Device that rotates from now on.
        to: DeviceId,
    },
    /// Change the rotation policy of an item.
    UpdatePolicy {
        /// Item id.
        item: ItemId,
        /// New policy.
        policy: RotationPolicy,
    },
    /// Change the name, the sinks, the MCP policy or the tags of an item. Never a secret.
    UpdateItem {
        /// Item id.
        item: ItemId,
        /// New display name.
        #[serde(default)]
        name: Option<String>,
        /// New sinks (replace the old list).
        #[serde(default)]
        sinks: Option<Vec<SinkSpec>>,
        /// New MCP policy.
        #[serde(default)]
        mcp: Option<McpPolicy>,
        /// New tags.
        #[serde(default)]
        tags: Option<Vec<String>>,
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
    ///
    /// With `Settings::quick_unlock` on, the cached key stays (soft lock). With it off, the
    /// daemon removes the cached key.
    Lock,
    /// Lock the vault and remove the cached key, whatever `Settings::quick_unlock` says.
    LockForget,
    /// Unlock the vault with the key from the cache of the daemon.
    ///
    /// The client runs the OS user check first. No key travels over IPC. The daemon refuses
    /// when `Settings::quick_unlock` is off or no cached key exists.
    UnlockQuick,
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
        /// Provider guess from the page (for example `gitlab`).
        #[serde(default)]
        provider_hint: Option<String>,
        /// End date that the user entered.
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
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
    /// Mark the current year as paid and return the coffee state.
    ///
    /// The daemon trusts the user (honor system). Capability: `Full` only.
    CoffeeMarkPaid,
    /// Record the signed coffee pledge.
    SignPledge {
        /// Name of the user who signs.
        user: String,
    },
    /// List the paired clients.
    ListClients,
    /// Remove a paired client. A `Full` client cannot be removed.
    Unpair {
        /// Client id from `ListClients` (at least 8 characters).
        id: String,
    },
    /// List the devices of the vault.
    ListDevices,
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
    /// Paired clients.
    Clients {
        /// The clients.
        clients: Vec<ClientInfo>,
    },
    /// Devices of the vault.
    Devices {
        /// The devices.
        devices: Vec<DeviceInfo>,
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
            provider_hint: None,
            expires_at: None,
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
        assert!(Capability::Full.allows(&Request::UnlockQuick));
        assert!(Capability::Full.allows(&Request::LockForget));
        let unpair = Request::Unpair { id: "x".into() };
        let update = Request::UpdateItem {
            item: ItemId::new(),
            name: None,
            sinks: None,
            mcp: None,
            tags: None,
        };
        for cap in [
            Capability::McpUse,
            Capability::McpAdmin,
            Capability::InboxWrite,
        ] {
            assert!(!cap.allows(&Request::ListClients));
            assert!(!cap.allows(&Request::ListDevices));
            assert!(!cap.allows(&unpair));
            assert!(!cap.allows(&update));
            assert!(!cap.allows(&Request::SignPledge { user: "u".into() }));
            assert!(!cap.allows(&Request::CoffeeMarkPaid));
            assert!(!cap.allows(&Request::UnlockQuick));
            assert!(!cap.allows(&Request::LockForget));
        }
        assert!(Capability::Full.allows(&unpair));
        assert!(Capability::Full.allows(&Request::CoffeeMarkPaid));
        let handover = Request::Handover {
            item: None,
            to: DeviceId::new(),
        };
        for cap in [
            Capability::McpUse,
            Capability::McpAdmin,
            Capability::InboxWrite,
        ] {
            assert!(!cap.allows(&handover));
        }
        assert!(Capability::Full.allows(&handover));
    }

    #[test]
    fn old_summary_without_status_still_parses() {
        let j = r#"{"id":"0193f2c4-8e1a-7b3d-9a52-4c6e1f0d0001","name":"n","provider":"manual","kind":{"type":"admin"},"expires_at":null,"next_rotation":null,"sink_count":0,"auto_rotate":false}"#;
        let s: ItemSummary = serde_json::from_str(j).unwrap();
        assert_eq!(s.status, ItemStatus::Healthy);
    }
}
