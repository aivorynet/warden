//! SSH remote file sink: SFTP read, pure edit, temp file, rename.
//!
//! Key authentication only. The server key must be in the `known_hosts` file
//! (strict checking, no trust on first use). Host certificates are rejected.
//!
//! Dependencies: `russh` 0.65 and `russh-sftp` 4 with the `ring` backend (no aws-lc).
//! The `rsa` feature is off, which removes RUSTSEC-2023-0071 (Marvin attack).
//! Ed25519 and ECDSA keys work. RSA keys do not.

use crate::{Editor, sink_err};
use async_trait::async_trait;
use russh::client::{self, AuthResult, Handle};
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts_path, load_secret_key};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use warden_core::{Result, SecretValue, Sink};

const TIMEOUT: Duration = Duration::from_secs(30);

/// A remote file on a host that offers SFTP over SSH.
#[derive(Debug, Clone)]
pub struct SshSink {
    host: String,
    port: u16,
    user: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
    remote_path: String,
    editor: Editor,
}

struct Strict {
    host: String,
    port: u16,
    known_hosts: PathBuf,
}

impl client::Handler for Strict {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        // Only plain host keys match known_hosts. Host certificates are rejected.
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        // Any error (no entry, changed key, unreadable file) rejects the server.
        Ok(check_known_hosts_path(&self.host, self.port, key, &self.known_hosts).unwrap_or(false))
    }
}

impl SshSink {
    /// Create a sink. The editor decides how the remote file changes.
    pub fn new(
        host: String,
        port: u16,
        user: String,
        identity_file: PathBuf,
        known_hosts: PathBuf,
        remote_path: String,
        editor: Editor,
    ) -> Self {
        Self {
            host,
            port,
            user,
            identity_file,
            known_hosts,
            remote_path,
            editor,
        }
    }

    async fn connect(&self) -> Result<(Handle<Strict>, SftpSession)> {
        let key = load_secret_key(&self.identity_file, None)
            .map_err(|e| sink_err(format!("cannot load identity file: {e}")))?;
        let handler = Strict {
            host: self.host.clone(),
            port: self.port,
            known_hosts: self.known_hosts.clone(),
        };
        let config = Arc::new(client::Config::default());
        let mut handle = client::connect(config, (self.host.as_str(), self.port), handler)
            .await
            .map_err(|e| sink_err(format!("ssh connect failed: {e}")))?;
        let hash = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        let auth = handle
            .authenticate_publickey(
                self.user.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .map_err(|e| sink_err(format!("ssh auth failed: {e}")))?;
        if !matches!(auth, AuthResult::Success) {
            return Err(sink_err("ssh key authentication refused"));
        }
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| sink_err(format!("ssh channel failed: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| sink_err(format!("sftp subsystem failed: {e}")))?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| sink_err(format!("sftp start failed: {e}")))?;
        Ok((handle, sftp))
    }

    async fn read_text(&self, sftp: &SftpSession) -> Result<String> {
        let bytes = sftp
            .read(self.remote_path.clone())
            .await
            .map_err(|e| sink_err(format!("remote read failed: {e}")))?;
        String::from_utf8(bytes).map_err(|_| sink_err("remote file is not UTF-8"))
    }

    async fn write_inner(&self, sftp: &SftpSession, value: &SecretValue) -> Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let tmp = format!(
            "{}.warden-{}-{nanos}.tmp",
            self.remote_path,
            std::process::id()
        );
        // The timeout covers only the steps that change nothing at the target.
        let prepared = tokio::time::timeout(TIMEOUT, async {
            let old = self.read_text(sftp).await?;
            let new = self.editor.edit(&old, value)?;
            if new == old {
                return Ok(false);
            }
            let mode = sftp
                .metadata(self.remote_path.clone())
                .await
                .ok()
                .and_then(|m| m.permissions)
                .map(|p| p & 0o7777);
            self.put_tmp(sftp, &tmp, new.as_bytes(), mode).await?;
            Ok(true)
        })
        .await
        .map_err(|_| sink_err("ssh write timed out"))
        .and_then(|r| r);
        match prepared {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(e) => {
                let _ = sftp.remove_file(tmp).await;
                return Err(e);
            }
        }
        // The swap has no outer timeout: a cancel between the two renames would leave the
        // target missing. Every SFTP request has its own timeout, so the swap ends.
        let result = self.swap(sftp, &tmp).await;
        if result.is_err() {
            let _ = sftp.remove_file(tmp).await;
        }
        result
    }

    async fn put_tmp(
        &self,
        sftp: &SftpSession,
        tmp: &str,
        data: &[u8],
        mode: Option<u32>,
    ) -> Result<()> {
        let e = |what: &'static str| {
            move |err: russh_sftp::client::error::Error| {
                sink_err(format!("remote {what} failed: {err}"))
            }
        };
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0o600);
        let mut f = sftp
            .open_with_flags_and_attributes(
                tmp.to_string(),
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE,
                attrs,
            )
            .await
            .map_err(e("create"))?;
        f.write_all(data)
            .await
            .map_err(|err| sink_err(format!("remote write failed: {err}")))?;
        f.flush()
            .await
            .map_err(|err| sink_err(format!("remote write failed: {err}")))?;
        // fsync@openssh.com may be missing; the close below still flushes the data.
        let _ = f.sync_all().await;
        if let Some(m) = mode {
            let mut a = FileAttributes::empty();
            a.permissions = Some(m);
            sftp.set_metadata(tmp.to_string(), a)
                .await
                .map_err(e("chmod"))?;
        }
        f.shutdown()
            .await
            .map_err(|err| sink_err(format!("remote close failed: {err}")))?;
        Ok(())
    }

    /// Replace the target with the temp file. SFTP rename does not replace an existing file,
    /// so the old file moves aside first and comes back when the second rename fails.
    async fn swap(&self, sftp: &SftpSession, tmp: &str) -> Result<()> {
        let e = |err: russh_sftp::client::error::Error| {
            sink_err(format!("remote rename failed: {err}"))
        };
        let backup = format!("{tmp}.old");
        sftp.rename(self.remote_path.clone(), backup.clone())
            .await
            .map_err(e)?;
        if let Err(err) = sftp.rename(tmp.to_string(), self.remote_path.clone()).await {
            if let Err(rb) = sftp.rename(backup.clone(), self.remote_path.clone()).await {
                tracing::error!("ssh sink: rollback failed, the old file is at {backup}: {rb}");
            }
            return Err(e(err));
        }
        if let Err(err) = sftp.remove_file(backup.clone()).await {
            // The backup holds the old secret.
            tracing::warn!("ssh sink: cannot remove the old file {backup}: {err}");
        }
        Ok(())
    }
}

#[async_trait]
impl Sink for SshSink {
    async fn write(&self, value: &SecretValue) -> Result<()> {
        let (handle, sftp) = tokio::time::timeout(TIMEOUT, self.connect())
            .await
            .map_err(|_| sink_err("ssh connect timed out"))??;
        let r = self.write_inner(&sftp, value).await;
        let _ = sftp.close().await;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        r
    }

    async fn read_back_matches(&self, value: &SecretValue) -> Result<bool> {
        let run = async {
            let (handle, sftp) = self.connect().await?;
            let r = self.read_text(&sftp).await;
            let _ = sftp.close().await;
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
            self.editor.matches(&r?, value)
        };
        tokio::time::timeout(TIMEOUT, run)
            .await
            .map_err(|_| sink_err("ssh read timed out"))?
    }

    fn describe(&self) -> String {
        format!(
            "ssh file {}@{}:{}:{}",
            self.user, self.host, self.port, self.remote_path
        )
    }
}
