//! The OS user check for quick unlock.
//!
//! A client (the desktop app or the CLI) calls a [`Verifier`] before it sends
//! `Request::UnlockQuick`. The check is a gate and not encryption: the vault key stays in the
//! OS keychain cache. The daemon never sees the result of the check.
//!
//! - Windows: `UserConsentVerifier` (Windows Hello face, fingerprint or PIN). It needs Windows 11.
//! - macOS: `LocalAuthentication` with `LAPolicyDeviceOwnerAuthentication` (Touch ID or password).
//! - Linux: `pkcheck` with the polkit action `net.aivory.warden.unlock`.

mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows_hello;

pub use linux::{ACTION_ID, POLICY_PATH, PkcheckVerifier};

/// Why a check did not pass. Every variant leaves the vault locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The user cancelled or did not pass the check.
    Cancelled,
    /// The OS check does not exist or cannot run on this device.
    Unavailable(String),
    /// The OS check failed for another reason.
    Failed(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Cancelled => f.write_str("the system check was cancelled"),
            VerifyError::Unavailable(m) => write!(f, "the system check is not available: {m}"),
            VerifyError::Failed(m) => write!(f, "the system check failed: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// An OS user check.
pub trait Verifier: Send + Sync + std::fmt::Debug {
    /// Name of the check for a button label, for example `Windows Hello`.
    fn label(&self) -> &'static str;

    /// Return true when the check can run on this device.
    fn available(&self) -> bool;

    /// Ask the user. This call blocks until the user answers.
    ///
    /// `window` is the native window handle of the caller (an HWND on Windows), if it has one.
    /// `reason` is the text that the OS shows.
    fn verify(&self, window: Option<isize>, reason: &str) -> Result<(), VerifyError>;
}

/// Return the verifier of this platform.
pub fn platform() -> Box<dyn Verifier> {
    #[cfg(windows)]
    {
        Box::new(windows_hello::HelloVerifier)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::TouchIdVerifier)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Box::new(PkcheckVerifier::system())
    }
}

/// Return the window handle of the console that runs this process, if one exists.
///
/// It is the handle that the CLI gives to the Windows check. Other platforms return `None`.
pub fn console_window() -> Option<isize> {
    #[cfg(windows)]
    {
        windows_hello::console_window()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Run the check and call `then` only when the check passes.
///
/// A cancelled or failed check returns the error and does not call `then`.
pub fn gate<T>(
    verifier: &dyn Verifier,
    window: Option<isize>,
    reason: &str,
    then: impl FnOnce() -> T,
) -> Result<T, VerifyError> {
    verifier.verify(window, reason)?;
    Ok(then())
}

/// A verifier with a fixed answer, for tests.
#[derive(Debug, Clone)]
pub struct FakeVerifier {
    /// Value of [`Verifier::available`].
    pub available: bool,
    /// Value of [`Verifier::verify`].
    pub outcome: Result<(), VerifyError>,
}

impl FakeVerifier {
    /// A fake that passes.
    pub fn passing() -> Self {
        Self {
            available: true,
            outcome: Ok(()),
        }
    }

    /// A fake that fails with `err`.
    pub fn failing(err: VerifyError) -> Self {
        Self {
            available: true,
            outcome: Err(err),
        }
    }
}

impl Verifier for FakeVerifier {
    fn label(&self) -> &'static str {
        "fake check"
    }

    fn available(&self) -> bool {
        self.available
    }

    fn verify(&self, _window: Option<isize>, _reason: &str) -> Result<(), VerifyError> {
        self.outcome.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_runs_then_only_after_a_pass() {
        let mut called = false;
        let r = gate(&FakeVerifier::passing(), None, "r", || called = true);
        assert!(r.is_ok() && called);
        for e in [
            VerifyError::Cancelled,
            VerifyError::Failed("x".into()),
            VerifyError::Unavailable("x".into()),
        ] {
            let mut called = false;
            let r = gate(&FakeVerifier::failing(e.clone()), None, "r", || {
                called = true
            });
            assert_eq!(r, Err(e));
            assert!(!called);
        }
    }
}
