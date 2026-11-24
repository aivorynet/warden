//! Windows user environment variable in `HKCU\Environment`.

use crate::{broadcast, sink_err};
use async_trait::async_trait;
use warden_core::{Result, SecretValue, Sink, WardenError};
use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};

/// A user environment variable in `HKCU\Environment`. A write broadcasts `WM_SETTINGCHANGE`.
#[derive(Debug, Clone)]
pub struct RegistryEnvSink {
    name: String,
}

impl RegistryEnvSink {
    /// Create a sink for variable `name`. Fails when the name is empty or has `=`.
    pub fn new(name: &str) -> Result<Self> {
        if name.is_empty() || name.contains(['=', '\0']) {
            return Err(WardenError::Config(
                "invalid environment variable name".into(),
            ));
        }
        Ok(Self { name: name.into() })
    }

    fn key() -> std::io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
    }

    fn write_blocking(&self, value: &str) -> Result<()> {
        let key = Self::key()?;
        let expand = key
            .get_raw_value(&self.name)
            .is_ok_and(|v| v.vtype == REG_EXPAND_SZ);
        if expand {
            let bytes: Vec<u8> = value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            key.set_raw_value(
                &self.name,
                &RegValue {
                    bytes,
                    vtype: REG_EXPAND_SZ,
                },
            )?;
        } else {
            key.set_value(&self.name, &value)?;
        }
        broadcast::notify_environment_changed();
        Ok(())
    }
}

#[async_trait]
impl Sink for RegistryEnvSink {
    async fn write(&self, value: &SecretValue) -> Result<()> {
        let (me, v) = (self.clone(), value.clone());
        tokio::task::spawn_blocking(move || me.write_blocking(v.expose()))
            .await
            .map_err(|e| sink_err(format!("task failed: {e}")))?
    }

    async fn read_back_matches(&self, value: &SecretValue) -> Result<bool> {
        let key = Self::key()?;
        match key.get_value::<String, _>(&self.name) {
            Ok(s) => Ok(s == value.expose()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn describe(&self) -> String {
        format!(
            "user env var {} in HKCU\\Environment (plaintext)",
            self.name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_roundtrip_with_test_variable() {
        let name = format!("WARDEN_SINKS_TEST_{}", std::process::id());
        let s = RegistryEnvSink::new(&name).unwrap();
        let v = SecretValue::new("synthetic-value");
        assert!(!s.read_back_matches(&v).await.unwrap());
        let w = s.write(&v).await;
        let ok = s.read_back_matches(&v).await;
        // Clean up before any assert can fail.
        let _ = RegistryEnvSink::key().and_then(|k| k.delete_value(&name));
        w.unwrap();
        assert!(ok.unwrap());
        assert!(!s.read_back_matches(&v).await.unwrap());
        assert!(!s.describe().contains("synthetic-value"));
    }
}
