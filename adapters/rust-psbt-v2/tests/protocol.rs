use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{ADAPTER_PROTOCOL, handle_value};
use psbt_v2::v2::Psbt;
use serde_json::{Value, json};

const VALID_PSBT_V2: &str = "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";
const VALID_BIP375_PSBT: &str = "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQECAQYBAAABDiAYpxdmOwurFLEqGncTI/8eQHndUy5d0T4o6hCBxwCYSgEPBAAAAAABAR9ADQMAAAAAABYAFCKactNKZFvTSWu79Qu7gckGP0+UAQMEAQAAACIGAsgXu3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/sAPKZZQi/CAAAAIAAAAAAARAE/v///yIdA1LXjEE5ADKtkYFqaX/HQNjrkJzwTXCIUmSwUfI4XiXsIQMJH9SAORd/RNe3npYWiEnGLrP4eADEZ2fFCo84+Y79FSIeA1LXjEE5ADKtkYFqaX/HQNjrkJzwTXCIUmSwUfI4XiXsQL4acjrvVeiYG5lZmpvBKzj4froBWMxwZokPImnK3kY7dzQal9KScZZNAcAkHMMi/VOQwpuZFg+CbzKTZYmMvwIAAQMIkF8BAAAAAAABCUIDZR0sBz/LAqTYLdpT8dUB13oDUGZnmFRkc7ISa2zRp94D8nDgpWMhg7arAQdOh35oANsA9cfF0vr7to+cKNSFRSQAAQMIkF8BAAAAAAABBCJRIENYHfbIefmqrcU2YN6xVrnxIr0a7KczIDvOh/zx84buAQlCA1LXjEE5ADKtkYFqaX/HQNjrkJzwTXCIUmSwUfI4XiXsAuDEwYe3IV+ZfISFp1tFkbbChHe5WhEjuZaSLTFUhgv4AA==";
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
fn advertises_native_psbt_v2_workflow_capabilities() {
    let response = handle_value(request("hello", json!({})), DIGEST);

    assert_eq!(response["status"], "ok");
    assert_eq!(
        response["output"]["operations"],
        json!([
            "hello",
            "native-parse",
            "inspect",
            "roundtrip",
            "sign",
            "combine",
            "finalize",
            "extract",
            "construct",
            "silent-payment-send",
            "silent-payment-send-advanced",
            "silent-payment-spend"
        ])
    );
    assert_eq!(
        response["output"]["roles"],
        json!([
            "parser",
            "updater",
            "signer",
            "combiner",
            "finalizer",
            "extractor",
            "constructor"
        ])
    );
    assert_eq!(response["output"]["psbtVersions"], json!([2]));
    assert_eq!(
        response["output"]["scriptTypes"],
        json!([
            "p2pkh",
            "p2wpkh",
            "p2wsh",
            "p2tr-keypath",
            "p2tr-scriptpath"
        ])
    );
    assert_eq!(
        response["output"]["operationScriptTypes"]["roundtrip"],
        json!([
            "p2pkh",
            "p2wpkh",
            "p2wsh",
            "p2tr-keypath",
            "p2tr-scriptpath"
        ])
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features array")
            .contains(&json!("bip371-taproot-roundtrip"))
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features array")
            .contains(&json!("bip375-silent-payments"))
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features array")
            .contains(&json!("bip375-sender-workflow"))
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features array")
            .contains(&json!("bip375-advanced-sender-workflows"))
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features array")
            .contains(&json!("bip376-spend-workflow"))
    );
    assert!(
        !response["output"]["operations"]
            .as_array()
            .expect("operations array")
            .contains(&json!("convert"))
    );
}

#[test]
fn exposes_typed_bip375_fields_from_the_native_parser() {
    let parsed = handle_value(
        request("native-parse", json!({ "psbt": VALID_BIP375_PSBT })),
        DIGEST,
    );

    assert_eq!(parsed["status"], "ok", "{parsed:#}");
    assert_eq!(
        parsed["output"]["silentPaymentFields"],
        json!({
            "globalEcdhShares": 0,
            "globalDleqProofs": 0,
            "inputEcdhShares": 1,
            "inputDleqProofs": 1,
            "outputsWithInfo": 2,
            "outputsWithLabel": 0
        })
    );

    let roundtripped = handle_value(
        request("roundtrip", json!({ "psbt": VALID_BIP375_PSBT })),
        DIGEST,
    );
    assert_eq!(roundtripped["status"], "ok", "{roundtripped:#}");
    assert_eq!(
        roundtripped["output"]["silentPaymentFields"],
        parsed["output"]["silentPaymentFields"]
    );
}

#[test]
fn creates_a_strict_modifiable_psbt_v2() {
    let response = handle_value(
        request(
            "construct",
            json!({
                "action": "create",
                "inputsModifiable": true,
                "outputsModifiable": false,
                "fallbackLocktime": 42
            }),
        ),
        DIGEST,
    );

    assert_eq!(response["status"], "ok", "{response:#}");
    assert_eq!(response["output"]["psbtVersion"], 2);
    assert_eq!(response["output"]["inputs"], 0);
    assert_eq!(response["output"]["outputs"], 0);
    assert_eq!(response["output"]["transactionModifiableFlags"], 1);
    assert_eq!(response["output"]["locktime"], 42);
    assert_eq!(response["output"]["locktimeType"], "height");
    Psbt::from_str(
        response["output"]["psbt"]
            .as_str()
            .expect("constructor returns PSBT"),
    )
    .expect("constructor PSBT parses");

    let extra = handle_value(
        request("construct", json!({ "action": "create", "unknown": true })),
        DIGEST,
    );
    assert_eq!(extra["status"], "rejected");
    assert_eq!(extra["error"]["class"], "protocol.invalid_payload");
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
fn reports_the_unavailable_native_conversion_api_without_claiming_support() {
    let response = handle_value(
        request(
            "convert",
            json!({ "psbt": VALID_PSBT_V2, "targetVersion": 0 }),
        ),
        DIGEST,
    );

    assert_eq!(response["status"], "unsupported");
    assert_eq!(
        response["error"]["class"],
        "conversion.native_api_unavailable"
    );
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
