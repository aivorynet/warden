//! Quote helpers shared by the dotenv and YAML editors.

use crate::sink_err;
use warden_core::Result;

/// Quote style of an existing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// No quotes.
    Plain,
    /// Single quotes.
    Single,
    /// Double quotes.
    Double,
}

/// Reject control characters that no quoting style can carry on one line.
pub fn check_value(v: &str) -> Result<()> {
    if v.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(sink_err("value has a control character"));
    }
    Ok(())
}

/// Render `v` in `style`. Fall back to double quotes when the style cannot carry `v`.
pub fn render(v: &str, style: Style, plain_ok: impl Fn(&str) -> bool) -> String {
    let multiline = v.contains(['\n', '\r']);
    match style {
        Style::Plain if plain_ok(v) => v.to_string(),
        Style::Single if !v.contains('\'') && !multiline => format!("'{v}'"),
        _ => double(v),
    }
}

fn double(v: &str) -> String {
    let mut o = String::with_capacity(v.len() + 2);
    o.push('"');
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Decode the inner text of a double-quoted token. Return `None` for an unknown escape.
pub fn unescape_double(inner: &str) -> Option<String> {
    let mut o = String::with_capacity(inner.len());
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            o.push(c);
            continue;
        }
        o.push(match it.next()? {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return None,
        });
    }
    Some(o)
}

/// Split a token that starts with a quote. Return `(style, inner, rest after closing quote)`.
///
/// Double quotes honour backslash escapes. Single quotes end at the first `'`
/// unless `yaml_single` is true, where `''` is an escaped quote.
pub fn split_quoted(s: &str, yaml_single: bool) -> Option<(Style, &str, &str)> {
    let q = s.chars().next()?;
    let style = match q {
        '"' => Style::Double,
        '\'' => Style::Single,
        _ => return None,
    };
    let b = s.as_bytes();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' if style == Style::Double => i += 2,
            c if c == q as u8 => {
                if yaml_single && style == Style::Single && b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                } else {
                    return Some((style, &s[1..i], &s[i + 1..]));
                }
            }
            _ => i += 1,
        }
    }
    None
}
