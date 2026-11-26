//! Aivory Warden sinks: the places where a rotated token is written.
//!
//! Pure text editors live in [`edit`]. They map `(old text, secret)` to
//! `new text` and do no I/O. The sink types add file, SSH, and environment I/O.
//! No code path logs or prints the secret value.

mod atomic;
#[cfg(windows)]
#[allow(unsafe_code)]
mod broadcast;
pub mod edit;
mod envvar;
mod file;
mod ssh;
#[cfg(windows)]
#[allow(unsafe_code)]
mod winacl;
#[cfg(windows)]
mod winenv;

pub use atomic::atomic_write;
pub use edit::Editor;
pub use envvar::{ProfileSink, profile_edit};
pub use file::FileSink;
pub use ssh::SshSink;
#[cfg(windows)]
pub use winenv::RegistryEnvSink;

use warden_core::{Result, Sink, SinkSpec, WardenError};

/// Build the sink that a [`SinkSpec`] describes.
///
/// Fails with a config error when a regex does not compile or a name is invalid.
pub fn build(spec: &SinkSpec) -> Result<Box<dyn Sink>> {
    Ok(match spec {
        SinkSpec::Dotenv { path, key } => {
            Box::new(FileSink::new(path.clone(), Editor::dotenv(key)?, "dotenv"))
        }
        SinkSpec::Json { path, pointer } => {
            Box::new(FileSink::new(path.clone(), Editor::json(pointer)?, "json"))
        }
        SinkSpec::Toml { path, key_path } => {
            Box::new(FileSink::new(path.clone(), Editor::toml(key_path)?, "toml"))
        }
        SinkSpec::Yaml { path, key_path } => {
            Box::new(FileSink::new(path.clone(), Editor::yaml(key_path)?, "yaml"))
        }
        SinkSpec::Regex {
            path,
            pattern,
            template,
        } => Box::new(FileSink::new(
            path.clone(),
            Editor::regex(pattern, template)?,
            "regex",
        )),
        SinkSpec::Ssh {
            host,
            port,
            user,
            identity_file,
            known_hosts,
            remote_path,
            format,
        } => Box::new(SshSink::new(
            host.clone(),
            *port,
            user.clone(),
            identity_file.clone(),
            known_hosts.clone(),
            remote_path.clone(),
            Editor::from_remote(format)?,
        )),
        SinkSpec::EnvVar { name } => build_env(name)?,
    })
}

#[cfg(windows)]
fn build_env(name: &str) -> Result<Box<dyn Sink>> {
    Ok(Box::new(RegistryEnvSink::new(name)?))
}

#[cfg(not(windows))]
fn build_env(name: &str) -> Result<Box<dyn Sink>> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| WardenError::Config("HOME is not set".into()))?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    Ok(Box::new(ProfileSink::new(
        name,
        profile_path(std::path::Path::new(&home), &shell),
    )?))
}

/// Choose the profile file for a login shell value (the `$SHELL` path).
///
/// zsh uses `.zshenv`, bash uses `.bashrc`, any other shell uses `.profile`.
#[cfg(any(not(windows), test))]
fn profile_path(home: &std::path::Path, shell: &str) -> std::path::PathBuf {
    let base = shell.rsplit(['/', '\\']).next().unwrap_or("");
    let base = base.strip_suffix(".exe").unwrap_or(base);
    home.join(match base {
        "zsh" => ".zshenv",
        "bash" => ".bashrc",
        _ => ".profile",
    })
}

pub(crate) fn sink_err(msg: impl Into<String>) -> WardenError {
    WardenError::Sink(msg.into())
}

#[cfg(test)]
mod tests {
    use super::profile_path;
    use std::path::Path;

    #[test]
    fn profile_follows_shell() {
        let h = Path::new("/h");
        assert_eq!(profile_path(h, "/bin/zsh"), h.join(".zshenv"));
        assert_eq!(profile_path(h, "/usr/bin/bash"), h.join(".bashrc"));
        assert_eq!(profile_path(h, "/usr/bin/fish"), h.join(".profile"));
        assert_eq!(profile_path(h, ""), h.join(".profile"));
    }

    #[test]
    fn build_validates_specs() {
        use warden_core::SinkSpec;
        let p = std::path::PathBuf::from("f");
        assert!(
            super::build(&SinkSpec::Json {
                path: p.clone(),
                pointer: "a/b".into()
            })
            .is_err()
        );
        assert!(
            super::build(&SinkSpec::Dotenv {
                path: p.clone(),
                key: "A B".into()
            })
            .is_err()
        );
        assert!(
            super::build(&SinkSpec::Regex {
                path: p,
                pattern: "(".into(),
                template: "{{secret}}".into()
            })
            .is_err()
        );
    }
}
