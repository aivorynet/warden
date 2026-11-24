//! Sink for a local file: read, apply an [`Editor`], write atomically.

use crate::{Editor, atomic_write, sink_err};
use async_trait::async_trait;
use std::io::ErrorKind;
use std::path::PathBuf;
use warden_core::{Result, SecretValue, Sink};

const BOM: &str = "\u{feff}";

/// A sink that edits one local file.
#[derive(Debug, Clone)]
pub struct FileSink {
    path: PathBuf,
    editor: Editor,
    kind: &'static str,
}

impl FileSink {
    /// Create a sink for `path`. `kind` names the format for [`Sink::describe`].
    pub fn new(path: PathBuf, editor: Editor, kind: &'static str) -> Self {
        Self { path, editor, kind }
    }

    fn read(&self) -> Result<Option<String>> {
        match std::fs::read(&self.path) {
            Ok(b) => String::from_utf8(b)
                .map(Some)
                .map_err(|_| sink_err(format!("{} is not UTF-8", self.path.display()))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn write_blocking(&self, value: &SecretValue) -> Result<()> {
        let raw = match self.read()? {
            Some(t) => t,
            None if self.editor.creates_missing() => String::new(),
            None => {
                return Err(warden_core::WardenError::NotFound(
                    self.path.display().to_string(),
                ));
            }
        };
        let (bom, text) = match raw.strip_prefix(BOM) {
            Some(t) => (BOM, t),
            None => ("", raw.as_str()),
        };
        let new = self.editor.edit(text, value)?;
        if new != text {
            atomic_write(&self.path, format!("{bom}{new}").as_bytes())?;
        }
        Ok(())
    }

    fn matches_blocking(&self, value: &SecretValue) -> Result<bool> {
        let Some(raw) = self.read()? else {
            return Ok(false);
        };
        self.editor
            .matches(raw.strip_prefix(BOM).unwrap_or(&raw), value)
    }
}

#[async_trait]
impl Sink for FileSink {
    async fn write(&self, value: &SecretValue) -> Result<()> {
        let (me, v) = (self.clone(), value.clone());
        tokio::task::spawn_blocking(move || me.write_blocking(&v))
            .await
            .map_err(|e| sink_err(format!("task failed: {e}")))?
    }

    async fn read_back_matches(&self, value: &SecretValue) -> Result<bool> {
        let (me, v) = (self.clone(), value.clone());
        tokio::task::spawn_blocking(move || me.matches_blocking(&v))
            .await
            .map_err(|e| sink_err(format!("task failed: {e}")))?
    }

    fn describe(&self) -> String {
        format!("{} file {}", self.kind, self.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dotenv_write_and_read_back() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".env");
        std::fs::write(&p, "# c\nA=1\nTOKEN=old\n").unwrap();
        let s = FileSink::new(p.clone(), Editor::dotenv("TOKEN").unwrap(), "dotenv");
        let v = SecretValue::new("new-value");
        assert!(!s.read_back_matches(&v).await.unwrap());
        s.write(&v).await.unwrap();
        assert!(s.read_back_matches(&v).await.unwrap());
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "# c\nA=1\nTOKEN=new-value\n"
        );
        assert!(!s.describe().contains("new-value"));
    }

    #[tokio::test]
    async fn missing_json_file_is_not_found() {
        let d = tempfile::tempdir().unwrap();
        let s = FileSink::new(d.path().join("x.json"), Editor::json("/a").unwrap(), "json");
        assert!(s.write(&SecretValue::new("v")).await.is_err());
        assert!(!s.read_back_matches(&SecretValue::new("v")).await.unwrap());
    }
}
