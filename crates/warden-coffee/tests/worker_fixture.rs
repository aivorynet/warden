//! The receipt that the Cloudflare Worker signs must verify in Rust.

#[test]
fn worker_fixture_verifies() {
    let raw = include_str!("../../../services/coffee-receipt/test/fixture-receipt.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("fixture json");
    let hex = v["public_key_hex"].as_str().expect("key");
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    let code = v["code"].as_str().expect("code");
    let receipt = warden_coffee::verify_with_key(code, &key).expect("valid receipt");
    assert_eq!(receipt.year, 2026);
    assert_eq!(receipt.receipt_id, "cs_test_fixture");
}
