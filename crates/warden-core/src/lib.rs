//! Core types, traits and wire types of Aivory Warden.

pub mod clock;
pub mod error;
pub mod ids;
pub mod ipc;
pub mod item;
pub mod mcp;
pub mod naming;
pub mod policy;
pub mod provider;
pub mod secret;
pub mod sink;

pub use clock::{Clock, FixedClock, SystemClock};
pub use error::{Result, WardenError};
pub use ids::{DeviceId, InboxId, ItemId, VaultId};
pub use item::{Item, ItemKind, ProviderKind, ProviderRef};
pub use mcp::McpPolicy;
pub use naming::{ClientToken, provider_token_name};
pub use policy::{RotationPolicy, Settings, next_rotation};
pub use provider::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, RotateRequest, RotationClass, TokenInfo,
};
pub use secret::SecretValue;
pub use sink::{RemoteFormat, Sink, SinkSpec};
