//! YAML editor: line-preserving edit of one scalar at a key path.
//!
//! Supported: block mappings. The editor replaces only the scalar token on
//! the target line. Comments, blank lines, and all other lines stay as they are.
//! It fails on flow style (`{}` / `[]`), block scalars, anchors, aliases, and
//! tags at the target, on a missing key, and on a path through a sequence.

use super::quote::{Style, check_value, render, split_quoted, unescape_double};
use crate::sink_err;
use warden_core::{Result, SecretValue};

const RESERVED: [&str; 10] = [
    "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~",
];

fn plain_ok(v: &str) -> bool {
    let mut chars = v.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || "_./".contains(first)) {
        return false;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-./+=@,%:".contains(c))
        || v.ends_with(':')
    {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if RESERVED.contains(&lower.as_str())
        || v.parse::<f64>().is_ok()
        || ["0x", "0o", "0b"].iter().any(|p| lower.starts_with(p))
    {
        return false;
    }
    !(first.is_ascii_digit() && v.contains(['-', ':']))
}

fn is_dash(t: &str) -> bool {
    t == "-" || t.starts_with("- ") || t.starts_with("-\t")
}

/// Parse `key:` at the start of `t`. Return the key and the text after the colon.
fn parse_key(t: &str) -> Option<(String, &str)> {
    let first = t.chars().next()?;
    if matches!(first, '"' | '\'') {
        let (style, inner, rest) = split_quoted(t, true)?;
        let r = rest.trim_start_matches([' ', '\t']).strip_prefix(':')?;
        if !(r.is_empty() || r.starts_with([' ', '\t'])) {
            return None;
        }
        let key = match style {
            Style::Double => unescape_double(inner)?,
            _ => inner.replace("''", "'"),
        };
        return Some((key, r));
    }
    if "#{[?&*!|>%@`".contains(first) {
        return None;
    }
    let b = t.as_bytes();
    let idx = (0..b.len())
        .find(|&i| b[i] == b':' && (i + 1 == b.len() || b[i + 1] == b' ' || b[i + 1] == b'\t'))?;
    Some((t[..idx].trim_end().to_string(), &t[idx + 1..]))
}

/// Kind of the value part of a key line.
enum Val {
    /// Nothing, or only a comment: children may follow.
    Empty,
    /// A scalar token with its style, decoded text, and token length.
    Scalar(Style, Option<String>, usize),
    /// Flow collection, block scalar, anchor, alias, or tag.
    Other,
    /// Anchor only (`&name`): children may follow.
    AnchorOnly,
}

fn classify(v: &str) -> Val {
    let Some(first) = v.chars().next() else {
        return Val::Empty;
    };
    match first {
        '#' => Val::Empty,
        '"' | '\'' => match split_quoted(v, true) {
            Some((st, inner, rest)) => {
                let dec = match st {
                    Style::Double => unescape_double(inner),
                    _ => Some(inner.replace("''", "'")),
                };
                Val::Scalar(st, dec, v.len() - rest.len())
            }
            None => Val::Other,
        },
        '|' | '>' | '{' | '[' | '*' | '!' => Val::Other,
        '&' => {
            let rest = v
                .split_once([' ', '\t'])
                .map_or("", |(_, r)| r.trim_start());
            if rest.is_empty() || rest.starts_with('#') {
                Val::AnchorOnly
            } else {
                Val::Other
            }
        }
        _ => {
            let end = v.find(" #").or_else(|| v.find("\t#")).unwrap_or(v.len());
            let tok = v[..end].trim_end();
            Val::Scalar(Style::Plain, Some(tok.to_string()), tok.len())
        }
    }
}

/// Set the scalar at `key_path` to `value`.
pub fn edit(content: &str, key_path: &[String], value: &SecretValue) -> Result<String> {
    check_value(value.expose())?;
    if key_path.is_empty() {
        return Err(sink_err("empty YAML key path"));
    }
    let n = key_path.len();
    let mut indents: Vec<usize> = Vec::new(); // indent of each matched component
    let mut levels: Vec<Option<usize>> = vec![None]; // mapping indent per level
    let mut skip_deeper: Option<usize> = None;
    let mut seq_indent: Option<usize> = None;
    let mut done = false;
    let mut out = String::with_capacity(content.len() + value.expose().len());
    for seg in content.split_inclusive('\n') {
        if done {
            out.push_str(seg);
            continue;
        }
        let body_end = seg.trim_end_matches(['\n', '\r']).len();
        let (body, eol) = seg.split_at(body_end);
        let t = body.trim_start();
        let indent = body.len() - t.len();
        let keep = |out: &mut String| {
            out.push_str(body);
            out.push_str(eol);
        };
        if t.is_empty() || t.starts_with('#') {
            keep(&mut out);
            continue;
        }
        if indent == 0 && (t == "---" || t.starts_with("--- ") || t == "...") {
            indents.clear();
            levels = vec![None];
            skip_deeper = None;
            seq_indent = None;
            keep(&mut out);
            continue;
        }
        if let Some(s) = skip_deeper {
            if indent > s {
                keep(&mut out);
                continue;
            }
            skip_deeper = None;
        }
        if let Some(s) = seq_indent {
            if indent > s || (indent == s && is_dash(t)) {
                keep(&mut out);
                continue;
            }
            seq_indent = None;
        }
        if is_dash(t) {
            seq_indent = Some(indent);
            keep(&mut out);
            continue;
        }
        let Some((key, after)) = parse_key(t) else {
            keep(&mut out);
            continue;
        };
        while indents.last().is_some_and(|&i| i >= indent) {
            indents.pop();
            levels.truncate(indents.len() + 1);
        }
        let d = indents.len();
        let level = &mut levels[d];
        if level.is_none() {
            *level = Some(indent);
        }
        let val_raw = after.trim_start_matches([' ', '\t']);
        let val_start = body.len() - val_raw.len();
        let kind = classify(val_raw);
        if *level == Some(indent) && key == key_path[d] {
            indents.push(indent);
            levels.push(None);
            if d + 1 == n {
                let Val::Scalar(style, decoded, tok_len) = kind else {
                    return Err(sink_err(
                        "YAML target is not a plain or quoted scalar (flow, block scalar, anchor, alias, tag, or empty)",
                    ));
                };
                if decoded.as_deref() == Some(value.expose()) {
                    return Ok(content.to_string());
                }
                out.push_str(&body[..val_start]);
                out.push_str(&render(value.expose(), style, plain_ok));
                out.push_str(&val_raw[tok_len..]);
                out.push_str(eol);
                done = true;
                continue;
            }
        }
        if matches!(kind, Val::Scalar(..) | Val::Other) {
            skip_deeper = Some(indent);
        }
        keep(&mut out);
    }
    if !done {
        return Err(sink_err("YAML key path not found"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    fn e(c: &str, path: &[&str], v: &str) -> Result<String> {
        edit(c, &p(path), &SecretValue::new(v))
    }

    #[test]
    fn replaces_nested_scalar_keeps_comments() {
        let c = "# h\na:\n  x: 1\n  b: 'old'  # c\n  list:\n    - b: z\nc:\n  b: keep\n";
        assert_eq!(
            e(c, &["a", "b"], "new").unwrap(),
            "# h\na:\n  x: 1\n  b: 'new'  # c\n  list:\n    - b: z\nc:\n  b: keep\n"
        );
    }

    #[test]
    fn does_not_match_deeper_or_sequence_keys() {
        assert!(e("a:\n  - x: 1\n    b: 2\n", &["a", "b"], "n").is_err());
        assert!(e("x:\n  a:\n    b: 1\n", &["a", "b"], "n").is_err());
    }

    #[test]
    fn rejects_flow_anchor_block_scalar() {
        assert!(e("a: {b: 1}\n", &["a"], "n").is_err());
        assert!(e("a: &x old\n", &["a"], "n").is_err());
        assert!(e("a: |\n  text\n", &["a"], "n").is_err());
        assert!(e("a: *x\n", &["a"], "n").is_err());
    }

    #[test]
    fn quotes_ambiguous_plain_values() {
        assert_eq!(e("a: old\n", &["a"], "true").unwrap(), "a: \"true\"\n");
        assert_eq!(e("a: old\n", &["a"], "12").unwrap(), "a: \"12\"\n");
        assert_eq!(e("a: old\n", &["a"], "ab-1").unwrap(), "a: ab-1\n");
    }

    #[test]
    fn same_value_is_unchanged() {
        assert_eq!(e("a: 12\n", &["a"], "12").unwrap(), "a: 12\n");
    }

    #[test]
    fn anchor_on_ancestor_is_allowed() {
        assert_eq!(
            e("a: &x\n  b: old\n", &["a", "b"], "newv").unwrap(),
            "a: &x\n  b: newv\n"
        );
    }
}
