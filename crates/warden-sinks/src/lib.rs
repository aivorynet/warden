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
    Ok(Box::new(ProfileSink::new(
        name,
        std::path::PathBuf::from(home).join(".profile"),
    )?))
}

pub(crate) fn sink_err(msg: impl Into<String>) -> WardenError {
    WardenError::Sink(msg.into())
}
