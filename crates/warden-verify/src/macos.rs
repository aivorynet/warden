//! macOS check: `LAContext evaluatePolicy` with `LAPolicyDeviceOwnerAuthentication`
//! (Touch ID, Apple Watch or the account password).
//!
//! Not run on a Mac yet: the code is only compiled with `cargo check --target aarch64-apple-darwin`.
#![allow(unsafe_code)]

use crate::{Verifier, VerifyError};
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use std::sync::mpsc;

/// The Touch ID check.
#[derive(Debug, Clone, Copy)]
pub struct TouchIdVerifier;

impl Verifier for TouchIdVerifier {
    fn label(&self) -> &'static str {
        "Touch ID"
    }

    fn available(&self) -> bool {
        // SAFETY: `LAContext::new` and `canEvaluatePolicy:error:` follow the documented API
        // contract and are called with valid arguments.
        unsafe {
            LAContext::new()
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
                .is_ok()
        }
    }

    fn verify(&self, _window: Option<isize>, reason: &str) -> Result<(), VerifyError> {
        let (tx, rx) = mpsc::channel::<Result<(), VerifyError>>();
        let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let result = if ok.as_bool() {
                Ok(())
            } else if err.is_null() {
                Err(VerifyError::Failed("no error object".into()))
            } else {
                // SAFETY: the system passes a valid NSError pointer for the call of the block.
                let code = unsafe { (*err).code() };
                if code == LAError::UserCancel.0
                    || code == LAError::SystemCancel.0
                    || code == LAError::AppCancel.0
                {
                    Err(VerifyError::Cancelled)
                } else {
                    Err(VerifyError::Failed(format!("LAError {code}")))
                }
            };
            let _ = tx.send(result);
        });
        let reason = NSString::from_str(reason);
        // SAFETY: the reply block only owns a `Sender`, which is `Send`, so the block is
        // sendable as the method requires. The block lives until the call returns and the
        // system copies it for the later reply.
        unsafe {
            LAContext::new().evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &reason,
                &reply,
            );
        }
        rx.recv()
            .unwrap_or_else(|_| Err(VerifyError::Failed("no reply from the system".into())))
    }
}
