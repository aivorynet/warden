//! SSH sink test. Runs only when `WARDEN_TEST_SSH` is set (CI with an sshd container).
//!
//! Format: `host;port;user;identity_file;known_hosts;remote_dir`.
//! `known_hosts` must hold the server key. The remote dir must be writable.

use warden_core::{RemoteFormat, SecretValue, SinkSpec};
use warden_sinks::build;

#[tokio::test]
async fn ssh_sink_roundtrip() {
    let Ok(cfg) = std::env::var("WARDEN_TEST_SSH") else {
        eprintln!("WARDEN_TEST_SSH not set: skipped");
        return;
    };
    let p: Vec<&str> = cfg.split(';').collect();
    assert_eq!(p.len(), 6, "WARDEN_TEST_SSH needs 6 fields");
    let remote_path = format!("{}/warden-sink-test.env", p[5].trim_end_matches('/'));
    let spec = |known_hosts: &str| SinkSpec::Ssh {
        host: p[0].into(),
        port: p[1].parse().unwrap(),
        user: p[2].into(),
        identity_file: p[3].into(),
        known_hosts: known_hosts.into(),
        remote_path: remote_path.clone(),
        format: Box::new(RemoteFormat::Dotenv {
            key: "TOKEN".into(),
        }),
    };

    let sink = build(&spec(p[4])).unwrap();
    let v = SecretValue::new("synthetic-token-1");
    // The CI job creates the remote file first (see the CI snippet).
    sink.write(&v)
        .await
        .unwrap_or_else(|e| panic!("remote file {remote_path} must exist: {e}"));
    assert!(sink.read_back_matches(&v).await.unwrap());
    let v2 = SecretValue::new("synthetic-token-2");
    sink.write(&v2).await.unwrap();
    assert!(sink.read_back_matches(&v2).await.unwrap());
    assert!(!sink.read_back_matches(&v).await.unwrap());

    // Strict known_hosts: an empty known_hosts file must refuse the server.
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("known_hosts");
    std::fs::write(&empty, "").unwrap();
    let strict = build(&spec(empty.to_str().unwrap())).unwrap();
    assert!(strict.write(&v).await.is_err());
}
