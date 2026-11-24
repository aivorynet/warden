//! Sink specifications and the `Sink` trait.

use crate::{Result, SecretValue};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Place that receives a token value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkSpec {
    /// A key in a dotenv file.
    Dotenv {
        /// File path.
        path: PathBuf,
        /// Variable name.
        key: String,
    },
    /// A value in a JSON file.
    Json {
        /// File path.
        path: PathBuf,
        /// JSON pointer (RFC 6901).
        pointer: String,
    },
    /// A value in a TOML file.
    Toml {
        /// File path.
        path: PathBuf,
        /// Key path.
        key_path: Vec<String>,
    },
    /// A scalar in a YAML file.
    Yaml {
        /// File path.
        path: PathBuf,
        /// Key path.
        key_path: Vec<String>,
    },
    /// A regex replacement in a text file.
    Regex {
        /// File path.
        path: PathBuf,
        /// Regex with one capture group for the old value.
        pattern: String,
        /// Replacement template. `{{secret}}` is replaced by the value.
        template: String,
    },
    /// A file on a remote host over SSH/SFTP.
    Ssh {
        /// Host name.
        host: String,
        /// Port.
        port: u16,
        /// User name.
        user: String,
        /// Private key file.
        identity_file: PathBuf,
        /// known_hosts file (strict checking).
        known_hosts: PathBuf,
        /// Remote file path.
        remote_path: String,
        /// Format of the remote file.
        format: Box<RemoteFormat>,
    },
    /// A user environment variable.
    EnvVar {
        /// Variable name.
        name: String,
    },
}

/// File format of a remote sink (a [`SinkSpec`] without the path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteFormat {
    /// Dotenv file.
    Dotenv {
        /// Variable name.
        key: String,
    },
    /// JSON file.
    Json {
        /// JSON pointer.
        pointer: String,
    },
    /// TOML file.
    Toml {
        /// Key path.
        key_path: Vec<String>,
    },
    /// YAML file.
    Yaml {
        /// Key path.
        key_path: Vec<String>,
    },
    /// Text file with a regex replacement.
    Regex {
        /// Regex with one capture group.
        pattern: String,
        /// Replacement template.
        template: String,
    },
}

/// A place that holds a token value.
#[async_trait]
pub trait Sink: Send + Sync {
    /// Write the value to the sink.
    async fn write(&self, value: &SecretValue) -> Result<()>;
    /// Return true when the sink holds exactly `value`.
    async fn read_back_matches(&self, value: &SecretValue) -> Result<bool>;
    /// Describe the sink for logs. Never contains the value.
    fn describe(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_serde() {
        let s = SinkSpec::Dotenv {
            path: "a.env".into(),
            key: "K".into(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["type"], "dotenv");
        assert_eq!(serde_json::from_value::<SinkSpec>(v).unwrap(), s);
        let ssh = SinkSpec::Ssh {
            host: "h".into(),
            port: 22,
            user: "u".into(),
            identity_file: "id".into(),
            known_hosts: "kh".into(),
            remote_path: "/x".into(),
            format: Box::new(RemoteFormat::Json {
                pointer: "/a".into(),
            }),
        };
        let j = serde_json::to_string(&ssh).unwrap();
        assert_eq!(serde_json::from_str::<SinkSpec>(&j).unwrap(), ssh);
    }
}
