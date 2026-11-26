//! JSON editor: set a string at a JSON pointer, keep key order and indent.

use crate::sink_err;
use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{PrettyFormatter, Serializer};
use warden_core::{Result, SecretValue};

/// Return true when the pointer holds exactly `value`.
pub fn matches(content: &str, pointer: &str, value: &SecretValue) -> Result<bool> {
    let doc: Value = serde_json::from_str(content)?;
    Ok(doc.pointer(pointer).and_then(Value::as_str) == Some(value.expose()))
}

/// Set the string at `pointer`. Insert the key when the parent is an object.
pub fn edit(content: &str, pointer: &str, value: &SecretValue) -> Result<String> {
    if matches(content, pointer, value)? {
        return Ok(content.to_string());
    }
    let mut doc: Value = serde_json::from_str(content)?;
    let new = Value::String(value.expose().to_string());
    if let Some(slot) = doc.pointer_mut(pointer) {
        if slot.is_object() || slot.is_array() {
            return Err(sink_err("JSON pointer targets an object or array"));
        }
        *slot = new;
    } else {
        let idx = pointer
            .rfind('/')
            .ok_or_else(|| sink_err("JSON pointer must start with '/'"))?;
        let last = pointer[idx + 1..].replace("~1", "/").replace("~0", "~");
        let parent = doc
            .pointer_mut(&pointer[..idx])
            .and_then(Value::as_object_mut)
            .ok_or_else(|| sink_err("JSON pointer parent is not an object"))?;
        parent.insert(last, new);
    }
    let mut out = match indent_of(content) {
        None => serde_json::to_string(&doc)?,
        Some(indent) => {
            let mut buf = Vec::new();
            let mut ser = Serializer::with_formatter(
                &mut buf,
                PrettyFormatter::with_indent(indent.as_bytes()),
            );
            doc.serialize(&mut ser)?;
            String::from_utf8(buf).map_err(|_| sink_err("JSON output is not UTF-8"))?
        }
    };
    if content.ends_with('\n') {
        out.push('\n');
    }
    // JSON strings escape newlines, so every raw newline is a layout newline.
    if content.contains("\r\n") {
        out = out.replace('\n', "\r\n");
    }
    Ok(out)
}

/// Detect the indent. `None` means compact (single line); default is two spaces.
fn indent_of(content: &str) -> Option<String> {
    if !content.trim_end().contains('\n') {
        return None;
    }
    for line in content.lines().skip(1) {
        let t = line.trim_start();
        if !t.is_empty() && t.len() < line.len() {
            return Some(line[..line.len() - t.len()].to_string());
        }
    }
    Some("  ".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(c: &str, p: &str, v: &str) -> String {
        edit(c, p, &SecretValue::new(v)).unwrap()
    }

    #[test]
    fn keeps_order_and_indent() {
        let out = e(
            "{\n    \"z\": 1,\n    \"a\": {\"t\": \"old\"}\n}\n",
            "/a/t",
            "n",
        );
        assert_eq!(
            out,
            "{\n    \"z\": 1,\n    \"a\": {\n        \"t\": \"n\"\n    }\n}\n"
        );
    }

    #[test]
    fn compact_and_insert() {
        assert_eq!(e("{\"a\":1}", "/b", "v"), "{\"a\":1,\"b\":\"v\"}");
        assert!(edit("{}", "/x/y", &SecretValue::new("v")).is_err());
    }

    #[test]
    fn keeps_crlf() {
        let out = e("{\r\n  \"a\": \"o\"\r\n}\r\n", "/a", "n");
        assert_eq!(out, "{\r\n  \"a\": \"n\"\r\n}\r\n");
    }

    #[test]
    fn same_value_is_unchanged() {
        let c = "{ \"a\":   \"v\" }";
        assert_eq!(e(c, "/a", "v"), c);
    }
}
