//! Pure text editors. Each editor maps `(old text, secret)` to `new text` without I/O.

pub mod dotenv;
pub mod json;
pub mod pattern;
mod quote;
pub mod toml;
pub mod yaml;

use regex::Regex;
use warden_core::{RemoteFormat, Result, SecretValue, WardenError};

/// A text editor for one file format and one location in the file.
#[derive(Debug, Clone)]
pub enum Editor {
    /// Dotenv `KEY=value` line.
    Dotenv {
        /// Variable name.
        key: String,
    },
    /// JSON value at a pointer.
    Json {
        /// RFC 6901 pointer.
        pointer: String,
    },
    /// TOML value at a key path.
    Toml {
        /// Key path.
        key_path: Vec<String>,
    },
    /// YAML scalar at a key path.
    Yaml {
        /// Key path.
        key_path: Vec<String>,
    },
    /// Regex replacement in the first match.
    Regex {
        /// Compiled pattern.
        re: Regex,
        /// Template with `{{secret}}`.
        template: String,
    },
}

impl Editor {
    /// Dotenv editor. Fails when `key` is empty or has a character outside `[A-Za-z0-9_.-]`.
    pub fn dotenv(key: &str) -> Result<Self> {
        dotenv::check_key(key)?;
        Ok(Self::Dotenv { key: key.into() })
    }

    /// JSON editor. Fails when `pointer` is empty or does not start with `/`.
    pub fn json(pointer: &str) -> Result<Self> {
        if !pointer.starts_with('/') {
            return Err(WardenError::Config(
                "JSON pointer must start with '/'".into(),
            ));
        }
        Ok(Self::Json {
            pointer: pointer.into(),
        })
    }

    /// TOML editor. Fails when `key_path` is empty.
    pub fn toml(key_path: &[String]) -> Result<Self> {
        non_empty(key_path)?;
        Ok(Self::Toml {
            key_path: key_path.to_vec(),
        })
    }

    /// YAML editor. Fails when `key_path` is empty.
    pub fn yaml(key_path: &[String]) -> Result<Self> {
        non_empty(key_path)?;
        Ok(Self::Yaml {
            key_path: key_path.to_vec(),
        })
    }

    /// Regex editor. Fails when the pattern does not compile.
    pub fn regex(pattern: &str, template: &str) -> Result<Self> {
        let re =
            Regex::new(pattern).map_err(|e| WardenError::Config(format!("invalid regex: {e}")))?;
        Ok(Self::Regex {
            re,
            template: template.into(),
        })
    }

    /// Editor for the format of a remote file.
    pub fn from_remote(f: &RemoteFormat) -> Result<Self> {
        match f {
            RemoteFormat::Dotenv { key } => Self::dotenv(key),
            RemoteFormat::Json { pointer } => Self::json(pointer),
            RemoteFormat::Toml { key_path } => Self::toml(key_path),
            RemoteFormat::Yaml { key_path } => Self::yaml(key_path),
            RemoteFormat::Regex { pattern, template } => Self::regex(pattern, template),
        }
    }

    /// Return `content` with the secret set at the location of the editor.
    ///
    /// The result equals `content` when the file already holds the value.
    pub fn edit(&self, content: &str, value: &SecretValue) -> Result<String> {
        match self {
            Self::Dotenv { key } => dotenv::edit(content, key, value),
            Self::Json { pointer } => json::edit(content, pointer, value),
            Self::Toml { key_path } => toml::edit(content, key_path, value),
            Self::Yaml { key_path } => yaml::edit(content, key_path, value),
            Self::Regex { re, template } => pattern::edit(content, re, template, value),
        }
    }

    /// Return true when `content` already holds `value` at the location of the editor.
    pub fn matches(&self, content: &str, value: &SecretValue) -> Result<bool> {
        match self {
            Self::Json { pointer } => json::matches(content, pointer, value),
            _ => match self.edit(content, value) {
                Ok(n) => Ok(n == content),
                // A missing key or a missing match means the value is not there.
                Err(WardenError::Sink(_)) => Ok(false),
                Err(e) => Err(e),
            },
        }
    }

    /// True when a missing file is created (dotenv only).
    pub fn creates_missing(&self) -> bool {
        matches!(self, Self::Dotenv { .. })
    }
}

fn non_empty(p: &[String]) -> Result<()> {
    if p.is_empty() || p.iter().any(String::is_empty) {
        return Err(WardenError::Config("key path has an empty part".into()));
    }
    Ok(())
}
