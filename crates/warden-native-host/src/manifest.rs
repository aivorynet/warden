//! Host manifest.

use serde_json::{Value, json};
use std::path::Path;

/// Native messaging host name.
pub const HOST_NAME: &str = "net.aivory.warden";

/// Return true when `id` is a Chromium extension ID: 32 letters from `a` to `p`.
pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Build the host manifest. Only the extensions in `extension_ids` may connect. The same
/// extension has one id per store (Chrome Web Store, Edge Add-ons) and one for a local build.
pub fn host_manifest(exe_path: &Path, extension_ids: &[&str]) -> Value {
    let origins: Vec<String> = extension_ids
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    json!({
        "name": HOST_NAME,
        "description": "Aivory Warden native messaging host",
        "path": exe_path.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": origins,
    })
}
