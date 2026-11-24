//! TOML editor on `toml_edit`: keeps comments and formatting.

use crate::sink_err;
use toml_edit::{DocumentMut, Item, Value};
use warden_core::{Result, SecretValue};

/// Set the string at `key_path`. Insert the key when the parent table exists.
pub fn edit(content: &str, key_path: &[String], value: &SecretValue) -> Result<String> {
    let (last, parents) = key_path
        .split_last()
        .ok_or_else(|| sink_err("empty TOML key path"))?;
    let mut doc: DocumentMut = content
        .parse()
        .map_err(|e| sink_err(format!("invalid TOML: {e}")))?;
    let mut item = doc.as_item_mut();
    for k in parents {
        item = item
            .get_mut(k.as_str())
            .filter(|i| i.is_table_like())
            .ok_or_else(|| sink_err(format!("TOML table '{k}' not found")))?;
    }
    let table = item
        .as_table_like_mut()
        .ok_or_else(|| sink_err("TOML parent is not a table"))?;
    let new = value.expose();
    match table.get_mut(last) {
        Some(slot) => {
            let old = slot
                .as_value()
                .ok_or_else(|| sink_err("TOML key is not a value"))?;
            if old.as_str() == Some(new) {
                return Ok(content.to_string());
            }
            if old.is_array() || old.is_inline_table() {
                return Err(sink_err("TOML key holds an array or table"));
            }
            let mut v = Value::from(new);
            *v.decor_mut() = old.decor().clone();
            *slot = Item::Value(v);
        }
        None => {
            table.insert(last, Item::Value(Value::from(new)));
        }
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn keeps_comments() {
        let c = "# top\n[a]\n# k\nt = 'old'   # tail\nz = 1\n";
        let out = edit(c, &p(&["a", "t"]), &SecretValue::new("n")).unwrap();
        assert_eq!(out, "# top\n[a]\n# k\nt = \"n\"   # tail\nz = 1\n");
    }

    #[test]
    fn missing_parent_errors_missing_key_inserts() {
        assert!(edit("[a]\n", &p(&["b", "t"]), &SecretValue::new("n")).is_err());
        let out = edit("[a]\nx = 1\n", &p(&["a", "t"]), &SecretValue::new("n")).unwrap();
        assert_eq!(out, "[a]\nx = 1\nt = \"n\"\n");
    }

    #[test]
    fn same_value_is_unchanged() {
        let c = "[a]\nt = 'v'\n";
        assert_eq!(edit(c, &p(&["a", "t"]), &SecretValue::new("v")).unwrap(), c);
    }
}
