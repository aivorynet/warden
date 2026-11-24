//! MCP policy of an item.

use serde::{Deserialize, Serialize};

/// Rules for the use of a secret through the MCP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpPolicy {
    /// Hosts that the secret may be sent to.
    pub allowed_hosts: Vec<String>,
    /// Name of the header that carries the secret.
    pub header_name: String,
    /// Header value template. `{{secret}}` is replaced by the secret.
    pub header_template: String,
    /// Allow `run_with_secret` for this item.
    pub run_with_secret: bool,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            header_name: "Authorization".into(),
            header_template: "Bearer {{secret}}".into(),
            run_with_secret: false,
        }
    }
}

impl McpPolicy {
    /// Render the header value for `secret`.
    pub fn render_header(&self, secret: &str) -> String {
        self.header_template.replace("{{secret}}", secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_header() {
        assert_eq!(McpPolicy::default().render_header("x"), "Bearer x");
    }
}
