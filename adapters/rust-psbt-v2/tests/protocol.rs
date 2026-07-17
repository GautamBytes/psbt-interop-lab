use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{ADAPTER_PROTOCOL, handle_value};
use psbt_v2::v2::Psbt;
use serde_json::{Value, json};

const VALID_PSBT_V2: &str = "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": "test-1",
        "operation": operation,
        "payload": payload
    })
}

#[test]
fn advertises_only_bounded_psbt_v2_parser_capabilities() {
    let response = handle_value(request("hello", json!({})), DIGEST);

    assert_eq!(response["status"], "ok");
    assert_eq!(
        response["output"]["operations"],
        json!(["hello", "native-parse", "inspect", "roundtrip"])
    );
    assert_eq!(response["output"]["roles"], json!(["parser"]));
    assert_eq!(response["output"]["psbtVersions"], json!([2]));
    assert_eq!(response["output"]["scriptTypes"], json!(["p2wpkh"]));
}

#[test]
fn parses_inspects_and_roundtrips_psbt_v2() {
    let parsed = handle_value(
        request("native-parse", json!({ "psbt": VALID_PSBT_V2 })),
        DIGEST,
    );
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["output"]["nativeParser"], "rust-psbt-v2");
    assert_eq!(parsed["output"]["psbtVersion"], 2);
    assert_eq!(parsed["output"]["inputs"], 1);
    assert_eq!(parsed["output"]["outputs"], 2);

    let inspected = handle_value(request("inspect", json!({ "psbt": VALID_PSBT_V2 })), DIGEST);
    assert_eq!(inspected["status"], "ok");
    assert_eq!(inspected["output"]["psbtVersion"], 2);
    assert_eq!(inspected["output"]["inputs"], 1);
    assert_eq!(inspected["output"]["outputs"], 2);
    assert_eq!(inspected["output"]["finalizedInputs"], 0);
    assert_eq!(inspected["output"]["partialSignatureInputs"], 0);

    let roundtripped = handle_value(
        request("roundtrip", json!({ "psbt": VALID_PSBT_V2 })),
        DIGEST,
    );
    assert_eq!(roundtripped["status"], "ok");
    let encoded = roundtripped["output"]["psbt"]
        .as_str()
        .expect("roundtrip returns base64 PSBTv2");
    assert_eq!(
        Psbt::from_str(encoded).expect("roundtripped PSBTv2 parses"),
        Psbt::from_str(VALID_PSBT_V2).expect("fixture parses")
    );
    assert!(roundtripped["output"]["byteIdentical"].is_boolean());
    assert_eq!(roundtripped["output"]["psbtVersion"], 2);
}

#[test]
fn rejects_operations_outside_parser_scope() {
    let response = handle_value(request("sign", json!({})), DIGEST);

    assert_eq!(response["status"], "unsupported");
    assert_eq!(response["error"]["class"], "operation.unsupported");
}

#[test]
fn rejects_noncanonical_base64_and_unknown_payload_fields() {
    let noncanonical = handle_value(request("native-parse", json!({ "psbt": "cHNidA" })), DIGEST);
    assert_eq!(noncanonical["status"], "rejected");
    assert_eq!(noncanonical["error"]["class"], "psbt.native_parse_failed");

    let extra = handle_value(
        request(
            "roundtrip",
            json!({ "psbt": VALID_PSBT_V2, "network": "mainnet" }),
        ),
        DIGEST,
    );
    assert_eq!(extra["status"], "rejected");
    assert_eq!(extra["error"]["class"], "protocol.invalid_payload");
}

#[test]
fn rejects_oversized_declared_map_counts_before_native_allocation() {
    let oversized_count = "cHNidP8BAgQCAAAAAQQF/f////////8BBQEAAfsEAgAAAAA=";
    let response = handle_value(
        request("native-parse", json!({ "psbt": oversized_count })),
        DIGEST,
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "psbt.native_parse_failed");
}

#[test]
fn rejects_pathological_map_entry_counts_before_native_allocation() {
    let mut bytes = b"psbt\xff".to_vec();
    bytes.extend_from_slice(&[1, 0x02, 4, 2, 0, 0, 0]);
    bytes.extend_from_slice(&[1, 0x04, 1, 1]);
    bytes.extend_from_slice(&[1, 0x05, 1, 0]);
    bytes.extend_from_slice(&[1, 0xfb, 4, 2, 0, 0, 0]);
    for index in 0_u32..20_000 {
        bytes.extend_from_slice(&[5, 0xaa]);
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.push(0);
    }
    bytes.push(0);
    bytes.extend_from_slice(&[1, 0x0e, 32]);
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[1, 0x0f, 4, 0, 0, 0, 0, 0]);
    let native = Psbt::deserialize(&bytes);
    assert!(native.is_ok(), "native parser rejected fixture: {native:?}");
    let encoded = STANDARD.encode(bytes);

    let response = handle_value(request("native-parse", json!({ "psbt": encoded })), DIGEST);
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "psbt.native_parse_failed");
}

#[test]
fn rejects_requests_that_do_not_match_protocol_0_2() {
    let response = handle_value(
        json!({
            "protocol": "psbt-lab.adapter/0.1",
            "id": "unsafe id",
            "operation": "hello",
            "payload": {},
            "extra": true
        }),
        DIGEST,
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["id"], "invalid-1");
    assert_eq!(response["error"]["class"], "protocol.invalid_request");
}
