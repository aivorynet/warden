//! Regex editor: replace capture group 1 (or the whole match) in the first match.

use crate::sink_err;
use regex::Regex;
use warden_core::{Result, SecretValue};

/// Replace capture group 1 of the first match with the rendered `template`.
///
/// When the pattern has no group 1, the whole match is replaced.
/// `{{secret}}` in `template` becomes the value. Fail when nothing matches.
pub fn edit(content: &str, re: &Regex, template: &str, value: &SecretValue) -> Result<String> {
    let caps = re
        .captures(content)
        .ok_or_else(|| sink_err("regex does not match"))?;
    let span = caps.get(1).or_else(|| caps.get(0)).map(|m| m.range());
    let Some(span) = span else {
        return Err(sink_err("regex does not match"));
    };
    let rendered = template.replace("{{secret}}", value.expose());
    if content[span.clone()] == rendered {
        return Ok(content.to_string());
    }
    let mut out = String::with_capacity(content.len() + rendered.len());
    out.push_str(&content[..span.start]);
    out.push_str(&rendered);
    out.push_str(&content[span.end..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_group_in_first_match_only() {
        let re = Regex::new(r#"token=(\w+)"#).unwrap();
        let out = edit(
            "token=aaa\ntoken=bbb\n",
            &re,
            "{{secret}}",
            &SecretValue::new("new"),
        )
        .unwrap();
        assert_eq!(out, "token=new\ntoken=bbb\n");
    }

    #[test]
    fn no_match_is_error_and_dollar_is_literal() {
        let re = Regex::new("x=(.*)").unwrap();
        assert!(edit("y", &re, "{{secret}}", &SecretValue::new("v")).is_err());
        let out = edit("x=1", &re, "{{secret}}", &SecretValue::new("$1$0")).unwrap();
        assert_eq!(out, "x=$1$0");
    }
}
