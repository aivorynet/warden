//! Copy the DACL of a file to another file (Windows). Unsafe code lives here and in
//! `broadcast` only.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// Frees the security descriptor that `GetNamedSecurityInfoW` allocates.
struct LocalGuard(PSECURITY_DESCRIPTOR);

impl Drop for LocalGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from `GetNamedSecurityInfoW`, which documents that
            // the caller frees it with `LocalFree`. The guard frees it once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Set the DACL of `to` to the DACL of `from`, including inherited entries. The copy is
/// protected, so the folder ACL does not merge into it again.
pub fn copy_dacl(from: &Path, to: &Path) -> io::Result<()> {
    let (from_w, to_w) = (wide(from), wide(to));
    let mut dacl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `from_w` is a valid NUL-terminated UTF-16 string that lives past the call.
    // The out pointers refer to valid local variables. The owner, group and SACL outputs
    // are null, which the API allows when the matching information flag is not set.
    let r = unsafe {
        GetNamedSecurityInfoW(
            from_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    check(r)?;
    let _guard = LocalGuard(sd);
    // SAFETY: `to_w` is a valid NUL-terminated UTF-16 string. `dacl` points into the
    // descriptor `sd`, which the guard keeps alive until the end of this function. Owner,
    // group and SACL are null because only the DACL flags are set.
    let r = unsafe {
        SetNamedSecurityInfoW(
            to_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    check(r)
}
