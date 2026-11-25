//! Windows check: `UserConsentVerifier` (Windows Hello face, fingerprint or PIN).
//!
//! A Win32 desktop process cannot use `RequestVerificationAsync`: it needs the window interop
//! `IUserConsentVerifierInterop::RequestVerificationForWindowAsync(HWND, message, riid, out)`
//! (header `userconsentverifierinterop.h`, Windows 11 build 22000 or later, see Microsoft Learn).
//! The window is the Tauri window of the desktop app or the console window of the CLI.
#![allow(unsafe_code)]

use crate::{Verifier, VerifyError};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::{
    IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, IsWindowVisible};
use windows::core::HSTRING;
use windows_future::IAsyncOperation;

/// The Windows Hello check.
#[derive(Debug, Clone, Copy)]
pub struct HelloVerifier;

/// Join the multithreaded apartment of the calling thread. An error means that the thread
/// already has an apartment, which is fine.
fn init_apartment() {
    // SAFETY: `RoInitialize` has no pointer argument. A failure (for example the thread is
    // already in a single-threaded apartment) is ignored on purpose, WinRT still works.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
}

/// Return the console window, or the foreground window when the console window is hidden
/// (ConPTY terminals such as Windows Terminal). `None` when there is no window.
pub fn console_window() -> Option<isize> {
    // SAFETY: both calls take no pointer and only read OS state.
    unsafe {
        let console = GetConsoleWindow();
        if !console.0.is_null() && IsWindowVisible(console).as_bool() {
            return Some(console.0 as isize);
        }
        let fg = GetForegroundWindow();
        (!fg.0.is_null()).then_some(fg.0 as isize)
    }
}

impl Verifier for HelloVerifier {
    fn label(&self) -> &'static str {
        "Windows Hello"
    }

    fn available(&self) -> bool {
        init_apartment();
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .is_ok_and(|a| a == UserConsentVerifierAvailability::Available)
    }

    fn verify(&self, window: Option<isize>, reason: &str) -> Result<(), VerifyError> {
        let Some(hwnd) = window.filter(|h| *h != 0) else {
            return Err(VerifyError::Unavailable(
                "no window to attach the prompt to".into(),
            ));
        };
        init_apartment();
        let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|e| VerifyError::Unavailable(e.to_string()))?;
        // SAFETY: `hwnd` is a window handle of this process that the caller gave us. The
        // message is a valid HSTRING that outlives the call. The out interface type is the
        // `IAsyncOperation<UserConsentVerificationResult>` that the interop call documents.
        let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
            interop.RequestVerificationForWindowAsync(
                HWND(hwnd as *mut core::ffi::c_void),
                &HSTRING::from(reason),
            )
        }
        .map_err(|e| VerifyError::Failed(e.to_string()))?;
        match op.join().map_err(|e| VerifyError::Failed(e.to_string()))? {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => Err(VerifyError::Cancelled),
            UserConsentVerificationResult::DeviceNotPresent
            | UserConsentVerificationResult::NotConfiguredForUser
            | UserConsentVerificationResult::DisabledByPolicy => Err(VerifyError::Unavailable(
                "Windows Hello is not set up".into(),
            )),
            other => Err(VerifyError::Failed(format!("{other:?}"))),
        }
    }
}
