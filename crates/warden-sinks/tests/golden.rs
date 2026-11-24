//! Golden-file tests: input with comments, expected output, per format.

use std::fs;
use std::path::Path;
use warden_core::{SecretValue, SinkSpec};
use warden_sinks::{Editor, build};

fn read(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    fs::read_to_string(p).unwrap().replace("\r\n", "\n")
}

fn check(editor: Editor, stem: &str) {
    let v = SecretValue::new("new-token-123");
    let out = editor.edit(&read(&format!("{stem}.in")), &v).unwrap();
    assert_eq!(out, read(&format!("{stem}.out")), "golden {stem}");
    assert!(editor.matches(&out, &v).unwrap());
    assert_eq!(editor.edit(&out, &v).unwrap(), out, "idempotent {stem}");
}

#[test]
fn dotenv_golden() {
    check(Editor::dotenv("API_TOKEN").unwrap(), "dotenv");
}

#[test]
fn json_golden() {
    check(Editor::json("/auth/token").unwrap(), "json");
}

#[test]
fn toml_golden() {
    check(
        Editor::toml(&["auth".into(), "token".into()]).unwrap(),
        "toml",
    );
}

#[test]
fn yaml_golden() {
    check(
        Editor::yaml(&["service".into(), "auth".into(), "token".into()]).unwrap(),
        "yaml",
    );
}

#[test]
fn regex_golden() {
    check(
        Editor::regex(r"(?m)^token = (\S+)$", "{{secret}}").unwrap(),
        "regex",
    );
}

#[test]
fn regex_without_match_fails() {
    let e = Editor::regex("nomatch=(.*)", "{{secret}}").unwrap();
    assert!(e.edit("a=b", &SecretValue::new("v")).is_err());
}

#[tokio::test]
async fn factory_builds_and_writes_every_file_format() {
    let d = tempfile::tempdir().unwrap();
    let cases: Vec<(&str, SinkSpec)> = vec![
        (
            "dotenv",
            SinkSpec::Dotenv {
                path: d.path().join("dotenv"),
                key: "API_TOKEN".into(),
            },
        ),
        (
            "json",
            SinkSpec::Json {
                path: d.path().join("json"),
                pointer: "/auth/token".into(),
            },
        ),
        (
            "toml",
            SinkSpec::Toml {
                path: d.path().join("toml"),
                key_path: vec!["auth".into(), "token".into()],
            },
        ),
        (
            "yaml",
            SinkSpec::Yaml {
                path: d.path().join("yaml"),
                key_path: vec!["service".into(), "auth".into(), "token".into()],
            },
        ),
        (
            "regex",
            SinkSpec::Regex {
                path: d.path().join("regex"),
                pattern: r"(?m)^token = (\S+)$".into(),
                template: "{{secret}}".into(),
            },
        ),
    ];
    let v = SecretValue::new("new-token-123");
    for (stem, spec) in cases {
        let path = d.path().join(stem);
        fs::write(&path, read(&format!("{stem}.in"))).unwrap();
        let sink = build(&spec).unwrap();
        assert!(!sink.read_back_matches(&v).await.unwrap(), "{stem}");
        sink.write(&v).await.unwrap();
        assert!(sink.read_back_matches(&v).await.unwrap(), "{stem}");
        let got = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        assert_eq!(got, read(&format!("{stem}.out")), "{stem}");
        assert!(!sink.describe().contains("new-token-123"));
    }
}

#[test]
fn factory_rejects_bad_regex() {
    let spec = SinkSpec::Regex {
        path: "x".into(),
        pattern: "(".into(),
        template: "t".into(),
    };
    assert!(build(&spec).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn sink_write_keeps_file_mode() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("c.env");
    fs::write(&p, "API_TOKEN=old\n").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
    let sink = build(&SinkSpec::Dotenv {
        path: p.clone(),
        key: "API_TOKEN".into(),
    })
    .unwrap();
    sink.write(&SecretValue::new("new")).await.unwrap();
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
        0o640
    );
}
