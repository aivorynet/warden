//! The only module with `unsafe`: broadcast of `WM_SETTINGCHANGE` after an environment change.

use windows_sys::Win32::Foundation::{LPARAM, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};

/// Tell running programs that `HKCU\Environment` changed. Blocks up to 2 seconds per hung window.
pub fn notify_environment_changed() {
    let wide: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result: usize = 0;
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that lives until the call
    // returns. `SendMessageTimeoutW` reads it only during the call (the message is
    // synchronous). `result` is a valid writable `usize`. `HWND_BROADCAST` is the
    // documented broadcast handle.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0 as WPARAM,
            wide.as_ptr() as LPARAM,
            SMTO_ABORTIFHUNG,
            2000,
            &mut result,
        );
    }
}
