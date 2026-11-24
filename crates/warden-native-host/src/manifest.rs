//! Host manifest.

use serde_json::{Value, json};
use std::path::Path;

/// Native messaging host name.
pub const HOST_NAME: &str = "net.aivory.warden";

/// Return true when `id` is a Chromium extension ID: 32 letters from `a` to `p`.
pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Build the host manifest. Only the extension with `extension_id` may connect.
pub fn host_manifest(exe_path: &Path, extension_id: &str) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Aivory Warden native messaging host",
        "path": exe_path.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    })
}
