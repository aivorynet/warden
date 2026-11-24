//! Session state and the pairing window.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warden_core::ClientToken;
use warden_core::ipc::{Capability, Request};

/// Default length of the pairing window.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(120);

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
    bootstrap: bool,
}

impl Session {
    pub(crate) fn paired(capabilities: Vec<Capability>) -> Self {
        Self {
            capabilities,
            bootstrap: false,
        }
    }

    pub(crate) fn bootstrap() -> Self {
        Self {
            capabilities: Vec::new(),
            bootstrap: true,
        }
    }

    /// Capabilities that the token carries. Empty for a bootstrap session.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Return true for a pairing bootstrap session (no token, pairing window was open).
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap
    }

    /// Return true when this session may send `req`.
    ///
    /// A bootstrap session may send only `Pair`. A paired session needs a capability for which
    /// `Capability::allows` is true.
    pub fn allows(&self, req: &Request) -> bool {
        if self.bootstrap {
            return matches!(req, Request::Pair { .. });
        }
        self.capabilities.iter().any(|c| c.allows(req))
    }
}

/// The pairing window: a flag with a deadline.
///
/// The daemon (or a `Full` client through `Client::set_pairing_mode`) opens the window. A client
/// without a token may connect while it is open and send one `Pair` request. That request closes
/// the window, so one window pairs one client.
#[derive(Debug, Clone, Default)]
pub struct PairingMode(Arc<Mutex<Option<Instant>>>);

impl PairingMode {
    /// Open the window for `ttl`.
    pub fn enable(&self, ttl: Duration) {
        *self.0.lock().expect("pairing lock") = Some(Instant::now() + ttl);
    }

    /// Close the window.
    pub fn disable(&self) {
        *self.0.lock().expect("pairing lock") = None;
    }

    /// Return true while the window is open.
    pub fn is_active(&self) -> bool {
        matches!(*self.0.lock().expect("pairing lock"), Some(t) if t > Instant::now())
    }

    /// Close the window and return true if it was open. Atomic: only one caller gets true.
    pub(crate) fn take(&self) -> bool {
        let mut g = self.0.lock().expect("pairing lock");
        let open = matches!(*g, Some(t) if t > Instant::now());
        *g = None;
        open
    }
}
