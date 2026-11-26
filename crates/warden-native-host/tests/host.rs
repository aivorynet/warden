//! Host tests with a fake daemon connection.

use async_trait::async_trait;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{Arc, Mutex};
use warden_core::InboxId;
use warden_core::ipc::{InboxEntry, Request, Response};
use warden_native_host::{
    HostError, MAX_MESSAGE, Upstream, host_manifest, read_message, register_in, run, unregister_in,
    write_message,
};

struct Fake(Arc<Mutex<Vec<String>>>);

#[async_trait]
impl Upstream for Fake {
    async fn call(&mut self, req: Request) -> warden_core::Result<Response> {
        match req {
            Request::InboxAdd {
                origin,
                label,
                value,
                ..
            } => {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("{origin}|{label}|{}", value.expose()));
                Ok(Response::InboxAdded { id: InboxId::new() })
            }
            Request::InboxList => Ok(Response::Inbox {
                inbox: Vec::<InboxEntry>::new(),
            }),
            _ => panic!("host forwarded a forbidden request"),
        }
    }
}

async fn exchange(input: Vec<u8>) -> (Result<(), HostError>, Vec<Value>, Vec<String>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let mut out = Vec::new();
    let res = run(&input[..], &mut out, move || {
        let s = s2.clone();
        async move { Ok(Fake(s)) }
    })
    .await;
    let mut replies = Vec::new();
    let mut r = &out[..];
    while let Some(b) = read_message(&mut r).await.unwrap() {
        replies.push(serde_json::from_slice(&b).unwrap());
    }
    let calls = seen.lock().unwrap().clone();
    (res, replies, calls)
}

async fn framed(v: &Value) -> Vec<u8> {
    let mut b = Vec::new();
    write_message(&mut b, v).await.unwrap();
    b
}

#[tokio::test]
async fn framing_round_trip_and_add() {
    let msg = json!({"type":"inbox_add","origin":"https://gitlab.com","label":"gl","value":"glpat-FAKE0000000000000000","provider_hint":"gitlab"});
    let (res, replies, calls) = exchange(framed(&msg).await).await;
    assert!(res.is_ok());
    assert_eq!(replies[0]["type"], "inbox_added");
    assert_eq!(calls, ["https://gitlab.com|gl|glpat-FAKE0000000000000000"]);
}

#[tokio::test]
async fn list_forwarded() {
    let (_, replies, _) = exchange(framed(&json!({"type":"inbox_list"})).await).await;
    assert_eq!(replies[0]["type"], "inbox");
}

#[tokio::test]
async fn frame_is_little_endian() {
    let b = framed(&json!({"a":1})).await;
    assert_eq!(b[..4], (b.len() as u32 - 4).to_le_bytes());
}

#[tokio::test]
async fn unknown_type_refused() {
    let (res, replies, calls) =
        exchange(framed(&json!({"type":"get_secret","id":"x"})).await).await;
    assert!(res.is_ok());
    assert_eq!(replies[0]["type"], "error");
    assert_eq!(replies[0]["code"], "unsupported");
    assert!(calls.is_empty());
}

#[tokio::test]
async fn bad_origin_refused() {
    let msg = json!({"type":"inbox_add","origin":"javascript:x","label":"a","value":"v"});
    let (_, replies, calls) = exchange(framed(&msg).await).await;
    assert_eq!(replies[0]["code"], "bad_request");
    assert!(calls.is_empty());
}

#[tokio::test]
async fn oversize_input_refused() {
    let mut input = ((MAX_MESSAGE + 1) as u32).to_le_bytes().to_vec();
    input.extend(vec![b'x'; 16]);
    let (res, replies, calls) = exchange(input).await;
    assert!(matches!(res, Err(HostError::TooLarge(_))));
    assert_eq!(replies[0]["code"], "too_large");
    assert!(calls.is_empty());
}

#[tokio::test]
async fn oversize_output_replaced() {
    let mut out = Vec::new();
    write_message(&mut out, &json!({"x": "a".repeat(MAX_MESSAGE)}))
        .await
        .unwrap();
    let mut r = &out[..];
    let b = read_message(&mut r).await.unwrap().unwrap();
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["code"], "too_large");
}

#[tokio::test]
async fn truncated_body_is_io_error() {
    let mut input = 10u32.to_le_bytes().to_vec();
    input.extend(b"abc");
    let (res, _, _) = exchange(input).await;
    assert!(matches!(res, Err(HostError::Io(_))));
}

#[test]
fn manifest_allowed_origins_exact() {
    let id = "abcdefghijklmnopabcdefghijklmnop";
    let m = host_manifest(Path::new("/x/host"), &[id]);
    assert_eq!(
        m["allowed_origins"],
        json!([format!("chrome-extension://{id}/")])
    );
    let other = "ponmlkjihgfedcbaponmlkjihgfedcba";
    let m = host_manifest(Path::new("/x/host"), &[id, other]);
    assert_eq!(
        m["allowed_origins"],
        json!([
            format!("chrome-extension://{id}/"),
            format!("chrome-extension://{other}/")
        ])
    );
    assert_eq!(m["name"], "net.aivory.warden");
    assert_eq!(m["type"], "stdio");
}

#[test]
fn register_writes_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let dirs = vec![dir.path().join("a"), dir.path().join("b")];
    let id = "abcdefghijklmnopabcdefghijklmnop";
    let exe = std::env::current_exe().unwrap();
    let files = register_in(&dirs, &exe, &[id]).unwrap();
    assert_eq!(files.len(), 2);
    let v: Value = serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    assert_eq!(v["allowed_origins"][0], format!("chrome-extension://{id}/"));
    assert!(register_in(&dirs, &exe, &["BAD"]).is_err());
    assert!(register_in(&dirs, &exe, &[id, "BAD"]).is_err());
    assert!(register_in(&dirs, &exe, &[]).is_err());
    unregister_in(&dirs).unwrap();
    assert!(!files[0].exists());
    unregister_in(&dirs).unwrap();
}
