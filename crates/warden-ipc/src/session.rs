//! Session state.

use warden_core::ClientToken;
use warden_core::ipc::{Capability, Request};

/// Lookup of pairing tokens. The daemon implements this trait on top of its vault.
#[async_trait::async_trait]
pub trait PairingStore: Send + Sync {
    /// Return the capabilities of a paired client, or `None` when the token is unknown or revoked.
    async fn lookup(&self, token: &ClientToken) -> Option<Vec<Capability>>;
}

/// A store that knows no token. It is the default of a server without a store.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyStore;

#[async_trait::async_trait]
impl PairingStore for EmptyStore {
    async fn lookup(&self, _token: &ClientToken) -> Option<Vec<Capability>> {
        None
    }
}

/// An authenticated connection, as the handler sees it.
#[derive(Debug, Clone)]
pub struct Session {
    capabilities: Vec<Capability>,
}

impl Session {
    pub(crate) fn paired(capabilities: Vec<Capability>) -> Self {
        Self { capabilities }
    }

    /// Capabilities that the token carries.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Return true when this session may send `req`.
    ///
    /// The session needs a capability for which `Capability::allows` is true.
    pub fn allows(&self, req: &Request) -> bool {
        self.capabilities.iter().any(|c| c.allows(req))
    }
}
