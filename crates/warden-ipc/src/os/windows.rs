//! Windows transport: a named pipe `\\.\pipe\aivory-warden-<user-sid>`.
//!
//! - `PIPE_REJECT_REMOTE_CLIENTS` is set on every instance (Tokio `reject_remote_clients(true)`).
//! - The first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, so no other process owns the name.
//! - Every instance gets the DACL `D:P(A;;GA;;;<user-sid>)`: only the current user has access.
//! - Both ends read the SID of the peer process token and compare it with their own SID.
//!   A peer whose token cannot be read (for example an elevated process of the same user
//!   seen from a non-elevated one) is refused: the check fails closed.
//! - The client opens the pipe with `SECURITY_IDENTIFICATION`, so the server cannot
//!   impersonate it.
#![allow(unsafe_code)]

use super::BoxedStream;
use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const CONNECT_RETRY: Duration = Duration::from_secs(3);

/// Read a NUL-terminated UTF-16 string that Windows allocated, and free it with `LocalFree`.
///
/// # Safety
/// `p` must be a valid NUL-terminated UTF-16 string from a `LocalAlloc`-based Windows call.
unsafe fn take_wide(p: *mut u16) -> String {
    let mut len = 0;
    // SAFETY: the caller guarantees NUL termination, so the scan stays inside the allocation.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `p` is valid for `len` elements (scanned above).
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
    // SAFETY: `p` came from a LocalAlloc-based call; it is not used after this.
    unsafe { LocalFree(p.cast()) };
    s
}

/// Return the user SID string (`S-1-5-21-...`) of the token of process `pid`.
fn sid_of_process(pid: u32) -> io::Result<String> {
    // SAFETY: plain call; the result is checked below.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `proc` is a new handle that nothing else owns.
    let proc = unsafe { OwnedHandle::from_raw_handle(proc.cast()) };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `proc` is a valid process handle; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(proc.as_raw_handle().cast(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `token` is a new handle that nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };

    let mut len = 0u32;
    // SAFETY: a null buffer with size 0 only asks for the needed size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 elements give the 8-byte alignment that TOKEN_USER needs.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` has at least `len` writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above filled `buf` with a TOKEN_USER; the alignment is sufficient.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into `buf`, which lives until the end of this function.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `out` is a NUL-terminated LocalAlloc string on success.
    Ok(unsafe { take_wide(out) })
}

fn my_sid() -> io::Result<String> {
    // SAFETY: plain call without arguments.
    sid_of_process(unsafe { GetCurrentProcessId() })
}

fn check_pid(pid: u32, mine: &str) -> io::Result<()> {
    if sid_of_process(pid)? == mine {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer SID differs from the current user",
        ))
    }
}

fn check_client(pipe: &NamedPipeServer) -> io::Result<()> {
    let mut pid = 0u32;
    // SAFETY: the handle is a valid pipe handle that `pipe` owns; `pid` is a valid out pointer.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check_pid(pid, &my_sid()?)
}

fn check_server(pipe: &NamedPipeClient) -> io::Result<()> {
    let mut pid = 0u32;
    // SAFETY: the handle is a valid pipe handle that `pipe` owns; `pid` is a valid out pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check_pid(pid, &my_sid()?)
}

fn default_name() -> io::Result<String> {
    Ok(format!(r"\\.\pipe\aivory-warden-{}", my_sid()?))
}

/// Create one pipe instance with the owner-only DACL.
fn create_instance(name: &str, sid: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` is a valid out pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: `sa` and the descriptor it points to are valid for the call; the kernel copies
    // the descriptor into the pipe object.
    let res = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut sa as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    // SAFETY: `sd` was allocated by the conversion call and is not used after this.
    unsafe { LocalFree(sd.cast()) };
    res
}

/// Listening pipe. It always keeps one unconnected instance ready.
#[derive(Debug)]
pub(crate) struct Listener {
    name: String,
    sid: String,
    next: Option<NamedPipeServer>,
}

impl Listener {
    /// Create the first instance. `path` is a full pipe name, or `None` for the default.
    pub(crate) fn bind(path: Option<&Path>) -> io::Result<Self> {
        let sid = my_sid()?;
        let name = match path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => default_name()?,
        };
        let first = create_instance(&name, &sid, true)?;
        Ok(Self {
            name,
            sid,
            next: Some(first),
        })
    }

    pub(crate) fn path(&self) -> PathBuf {
        PathBuf::from(&self.name)
    }

    /// Wait for a client. A client of another user gives `PermissionDenied`.
    pub(crate) async fn accept(&mut self) -> io::Result<BoxedStream> {
        let server = match self.next.take() {
            Some(s) => s,
            None => create_instance(&self.name, &self.sid, false)?,
        };
        server.connect().await?;
        self.next = Some(create_instance(&self.name, &self.sid, false)?);
        check_client(&server)?;
        Ok(Box::new(server))
    }

    #[cfg(test)]
    fn pending_handle(&self) -> HANDLE {
        self.next
            .as_ref()
            .expect("pending instance")
            .as_raw_handle()
            .cast()
    }
}

/// Connect to the server pipe. The client checks that the server runs as the same user.
pub(crate) async fn connect(path: Option<&Path>) -> io::Result<BoxedStream> {
    let name = match path {
        Some(p) => p.as_os_str().to_owned(),
        None => default_name()?.into(),
    };
    let started = Instant::now();
    loop {
        match open_client(&name) {
            Ok(c) => {
                check_server(&c)?;
                return Ok(Box::new(c));
            }
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && started.elapsed() < CONNECT_RETRY =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

fn open_client(name: &OsStr) -> io::Result<NamedPipeClient> {
    ClientOptions::new()
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    fn test_name(tag: &str) -> PathBuf {
        PathBuf::from(format!(
            r"\\.\pipe\aivory-warden-test-{tag}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn sid_has_expected_shape() {
        let sid = my_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
        assert!(default_name().unwrap().ends_with(&sid));
    }

    #[tokio::test]
    async fn pipe_has_owner_only_dacl() {
        let l = Listener::bind(Some(&test_name("dacl"))).unwrap();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: valid pipe handle owned by `l`; `sd` is a valid out pointer.
        let rc = unsafe {
            GetSecurityInfo(
                l.pending_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetSecurityInfo failed");
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sd` is the descriptor from the call above.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut out,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        // SAFETY: `out` is a NUL-terminated LocalAlloc string; `sd` is a LocalAlloc block.
        let sddl = unsafe { take_wide(out) };
        unsafe { LocalFree(sd.cast()) };
        // Protected DACL with exactly one allow entry, for the current user only.
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 1, "{sddl}");
        assert!(sddl.contains(&my_sid().unwrap()), "{sddl}");
    }

    #[tokio::test]
    async fn second_server_on_same_name_fails() {
        // FILE_FLAG_FIRST_PIPE_INSTANCE: nobody else can create the name.
        // `PIPE_REJECT_REMOTE_CLIENTS` has no query API; it is set in `create_instance` only.
        let name = test_name("first");
        let _a = Listener::bind(Some(&name)).unwrap();
        assert!(Listener::bind(Some(&name)).is_err());
    }
}
