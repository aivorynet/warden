//! Unix user environment variable: managed block in a shell profile file.

use crate::{atomic_write, sink_err};
use async_trait::async_trait;
use std::io::ErrorKind;
use std::path::PathBuf;
use warden_core::{Result, SecretValue, Sink, WardenError};

const BEGIN: &str = "# >>> aivory-warden >>>";
const END: &str = "# <<< aivory-warden <<<";

pub(crate) fn check_name(name: &str) -> Result<()> {
    let mut c = name.chars();
    let ok = c
        .next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_');
    if ok {
        Ok(())
    } else {
        Err(WardenError::Config(
            "invalid environment variable name".into(),
        ))
    }
}

fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Set `export NAME='value'` inside the managed block of a profile text.
///
/// The function creates the block at the end of the text when it is missing.
/// It keeps all lines outside the block and all other lines inside it.
pub fn profile_edit(content: &str, name: &str, value: &SecretValue) -> Result<String> {
    check_name(name)?;
    let line = format!("export {name}={}", shell_quote(value.expose()));
    let prefix = format!("export {name}=");
    let lines: Vec<&str> = content.lines().collect();
    let begin = lines.iter().position(|l| l.trim_end() == BEGIN);
    let end = begin.and_then(|b| {
        lines[b + 1..]
            .iter()
            .position(|l| l.trim_end() == END)
            .map(|e| e + b + 1)
    });
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 4);
    match (begin, end) {
        (Some(b), Some(e)) => {
            let mut replaced = false;
            for (i, l) in lines.iter().enumerate() {
                if i > b && i < e && l.starts_with(&prefix) {
                    out.push(line.clone());
                    replaced = true;
                } else if i == e && !replaced {
                    out.push(line.clone());
                    out.push((*l).to_string());
                } else {
                    out.push((*l).to_string());
                }
            }
        }
        (Some(_), None) => return Err(sink_err("profile has a block start without an end")),
        _ => {
            out.extend(lines.iter().map(|l| (*l).to_string()));
            if !out.is_empty() && !out.last().is_some_and(String::is_empty) {
                out.push(String::new());
            }
            out.push(BEGIN.into());
            out.push(line);
            out.push(END.into());
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    Ok(s)
}

/// A user environment variable stored in a managed block of a shell profile.
#[derive(Debug, Clone)]
pub struct ProfileSink {
    name: String,
    path: PathBuf,
}

impl ProfileSink {
    /// Create a sink for variable `name` in the profile file at `path` (for example `~/.profile`).
    pub fn new(name: &str, path: PathBuf) -> Result<Self> {
        check_name(name)?;
        Ok(Self {
            name: name.into(),
            path,
        })
    }

    fn read(&self) -> Result<String> {
        match std::fs::read(&self.path) {
            Ok(b) => String::from_utf8(b).map_err(|_| sink_err("profile is not UTF-8")),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl Sink for ProfileSink {
    async fn write(&self, value: &SecretValue) -> Result<()> {
        let (me, v) = (self.clone(), value.clone());
        tokio::task::spawn_blocking(move || {
            let old = me.read()?;
            let new = profile_edit(&old, &me.name, &v)?;
            if new != old {
                atomic_write(&me.path, new.as_bytes())?;
            }
            Ok(())
        })
        .await
        .map_err(|e| sink_err(format!("task failed: {e}")))?
    }

    async fn read_back_matches(&self, value: &SecretValue) -> Result<bool> {
        let old = self.read()?;
        Ok(profile_edit(&old, &self.name, value)? == old)
    }

    fn describe(&self) -> String {
        format!(
            "env var {} in profile {} (plaintext)",
            self.name,
            self.path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(c: &str, n: &str, v: &str) -> String {
        profile_edit(c, n, &SecretValue::new(v)).unwrap()
    }

    #[test]
    fn creates_block_and_keeps_rest() {
        let out = e("# mine\nPATH=1\n", "T", "a'b");
        assert_eq!(
            out,
            "# mine\nPATH=1\n\n# >>> aivory-warden >>>\nexport T='a'\\''b'\n# <<< aivory-warden <<<\n"
        );
    }

    #[test]
    fn updates_and_adds_inside_block() {
        let c = e("", "A", "1");
        let c = e(&c, "B", "2");
        let c = e(&c, "A", "3");
        assert_eq!(
            c,
            "# >>> aivory-warden >>>\nexport A='3'\nexport B='2'\n# <<< aivory-warden <<<\n"
        );
        assert_eq!(e(&c, "A", "3"), c);
    }

    #[test]
    fn rejects_bad_name() {
        assert!(profile_edit("", "1A", &SecretValue::new("v")).is_err());
        assert!(ProfileSink::new("A B", "x".into()).is_err());
    }

    #[tokio::test]
    async fn sink_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".profile");
        std::fs::write(&p, "# x\n").unwrap();
        let s = ProfileSink::new("WARDEN_T", p.clone()).unwrap();
        let v = SecretValue::new("s3cret");
        assert!(!s.read_back_matches(&v).await.unwrap());
        s.write(&v).await.unwrap();
        assert!(s.read_back_matches(&v).await.unwrap());
        assert!(std::fs::read_to_string(&p).unwrap().starts_with("# x\n"));
        assert!(!s.describe().contains("s3cret"));
    }
}
