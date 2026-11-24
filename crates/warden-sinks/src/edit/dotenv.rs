//! Dotenv editor: replace `KEY=...` and keep quote style, comments, and order.

use super::quote::{Style, check_value, render, split_quoted, unescape_double};
use warden_core::{Result, SecretValue, WardenError};

/// Check a variable name.
pub(super) fn check_key(key: &str) -> Result<()> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(WardenError::Config("invalid dotenv key".into()));
    }
    Ok(())
}

fn plain_ok(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:+=@,%".contains(c))
}

/// Set `key` to `value`. Replace every `KEY=` line; append one when none exists.
pub fn edit(content: &str, key: &str, value: &SecretValue) -> Result<String> {
    check_key(key)?;
    check_value(value.expose())?;
    let nl = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out = String::with_capacity(content.len() + key.len() + value.expose().len() + 4);
    let mut found = false;
    for seg in content.split_inclusive('\n') {
        let body_end = seg.trim_end_matches(['\n', '\r']).len();
        let (body, eol) = seg.split_at(body_end);
        match rewrite_line(body, key, value.expose()) {
            Some(new) => {
                found = true;
                out.push_str(&new);
            }
            None => out.push_str(body),
        }
        out.push_str(eol);
    }
    if !found {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(nl);
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&render(value.expose(), Style::Plain, plain_ok));
        out.push_str(nl);
    }
    Ok(out)
}

fn rewrite_line(body: &str, key: &str, value: &str) -> Option<String> {
    let t = body.trim_start();
    if t.starts_with('#') {
        return None;
    }
    let prefix_len = body.len() - t.len();
    let mut head_len = prefix_len;
    let mut rest = t;
    if let Some(r) = t.strip_prefix("export")
        && r.starts_with([' ', '\t'])
    {
        let r2 = r.trim_start();
        head_len += t.len() - r2.len();
        rest = r2;
    }
    let after_key = rest.strip_prefix(key)?;
    let after_ws = after_key.trim_start_matches([' ', '\t']);
    let after_eq = after_ws.strip_prefix('=')?;
    head_len += key.len() + (after_key.len() - after_ws.len()) + 1;
    let val_part = after_eq.trim_start_matches([' ', '\t']);
    head_len += after_eq.len() - val_part.len();

    let (style, decoded, token_len) = match split_quoted(val_part, false) {
        Some((st, inner, rest_after)) => {
            let dec = if st == Style::Double {
                unescape_double(inner)
            } else {
                Some(inner.to_string())
            };
            (st, dec, val_part.len() - rest_after.len())
        }
        None => {
            let end = val_part
                .find(" #")
                .or_else(|| val_part.find("\t#"))
                .unwrap_or(val_part.len());
            let tok = val_part[..end].trim_end();
            (Style::Plain, Some(tok.to_string()), tok.len())
        }
    };
    if decoded.as_deref() == Some(value) {
        return Some(body.to_string());
    }
    let mut new = String::with_capacity(body.len() + value.len());
    new.push_str(&body[..head_len]);
    new.push_str(&render(value, style, plain_ok));
    new.push_str(&val_part[token_len..]);
    Some(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(c: &str, v: &str) -> String {
        edit(c, "K", &SecretValue::new(v)).unwrap()
    }

    #[test]
    fn keeps_quote_style_and_comment() {
        assert_eq!(e("K=\"old\" # c\n", "new"), "K=\"new\" # c\n");
        assert_eq!(e("K='old'\n", "new"), "K='new'\n");
        assert_eq!(e("export K = old # c\n", "n"), "export K = n # c\n");
    }

    #[test]
    fn quotes_when_needed() {
        assert_eq!(e("K=old\n", "a b"), "K=\"a b\"\n");
        assert_eq!(e("K='o'\n", "it's"), "K=\"it's\"\n");
        assert_eq!(e("", "a\"b"), "K=\"a\\\"b\"\n");
    }

    #[test]
    fn appends_and_keeps_crlf() {
        assert_eq!(e("A=1", "v"), "A=1\nK=v\n");
        assert_eq!(e("A=1\r\n", "v"), "A=1\r\nK=v\r\n");
    }

    #[test]
    fn ignores_commented_and_prefix_keys() {
        assert_eq!(e("#K=1\nKK=2\n", "v"), "#K=1\nKK=2\nK=v\n");
    }

    #[test]
    fn same_value_is_unchanged() {
        assert_eq!(e("K=\"a b\"\n", "a b"), "K=\"a b\"\n");
    }
}
