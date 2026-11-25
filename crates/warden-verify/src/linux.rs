//! Linux check: `pkcheck` against the polkit action `net.aivory.warden.unlock`.
//!
//! polkit asks its authentication agent, which reaches PAM. A PAM stack with `howdy` (face) or
//! `fprintd` (fingerprint) therefore works. The code uses only `std`, so it compiles on every
//! platform and the tests run everywhere.

use crate::{Verifier, VerifyError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The polkit action id.
pub const ACTION_ID: &str = "net.aivory.warden.unlock";

/// Where the .deb installs the policy file.
pub const POLICY_PATH: &str = "/usr/share/polkit-1/actions/net.aivory.warden.unlock.policy";

/// The polkit check.
#[derive(Debug, Clone)]
pub struct PkcheckVerifier {
    pkcheck: Option<PathBuf>,
    policy: PathBuf,
}

impl PkcheckVerifier {
    /// Use `pkcheck` from `PATH` and the installed policy file.
    pub fn system() -> Self {
        Self {
            pkcheck: find_in_path("pkcheck"),
            policy: PathBuf::from(POLICY_PATH),
        }
    }

    /// Use a given `pkcheck` binary and policy file (for tests).
    pub fn with_paths(pkcheck: Option<PathBuf>, policy: PathBuf) -> Self {
        Self { pkcheck, policy }
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(&exe))
            .find(|f| f.is_file())
    })
}

/// Map the exit code of `pkcheck`. Only 0 means that the user is authorized.
fn map_exit(code: Option<i32>) -> Result<(), VerifyError> {
    match code {
        Some(0) => Ok(()),
        // 1: not authorized, or the user dismissed the dialog. 2: no agent could ask.
        Some(1) => Err(VerifyError::Cancelled),
        Some(2) => Err(VerifyError::Unavailable(
            "no polkit authentication agent is running".into(),
        )),
        Some(n) => Err(VerifyError::Failed(format!("pkcheck exit code {n}"))),
        None => Err(VerifyError::Failed("pkcheck ended by a signal".into())),
    }
}

impl Verifier for PkcheckVerifier {
    fn label(&self) -> &'static str {
        "system login"
    }

    fn available(&self) -> bool {
        self.pkcheck.is_some() && Path::new(&self.policy).is_file()
    }

    fn verify(&self, _window: Option<isize>, _reason: &str) -> Result<(), VerifyError> {
        let Some(bin) = &self.pkcheck else {
            return Err(VerifyError::Unavailable("pkcheck is not installed".into()));
        };
        if !self.policy.is_file() {
            return Err(VerifyError::Unavailable(
                "the polkit policy is missing".into(),
            ));
        }
        let status = Command::new(bin)
            .args(["--action-id", ACTION_ID])
            .args(["--process", &std::process::id().to_string()])
            .arg("--allow-user-interaction")
            .stdin(Stdio::null())
            .status()
            .map_err(|e| VerifyError::Failed(e.to_string()))?;
        map_exit(status.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exit_zero_passes() {
        assert!(map_exit(Some(0)).is_ok());
        assert_eq!(map_exit(Some(1)), Err(VerifyError::Cancelled));
        assert!(matches!(
            map_exit(Some(2)),
            Err(VerifyError::Unavailable(_))
        ));
        assert!(matches!(map_exit(Some(3)), Err(VerifyError::Failed(_))));
        assert!(matches!(map_exit(None), Err(VerifyError::Failed(_))));
    }

    #[test]
    fn missing_pkcheck_or_policy_is_unavailable() {
        let d = tempfile::tempdir().unwrap();
        let policy = d.path().join("p.policy");
        let v = PkcheckVerifier::with_paths(None, policy.clone());
        assert!(!v.available());
        assert!(matches!(
            v.verify(None, "r"),
            Err(VerifyError::Unavailable(_))
        ));
        std::fs::write(&policy, "x").unwrap();
        let exe = d.path().join("pkcheck");
        std::fs::write(&exe, "x").unwrap();
        assert!(PkcheckVerifier::with_paths(Some(exe), policy.clone()).available());
        assert!(!PkcheckVerifier::with_paths(None, policy).available());
    }
}
