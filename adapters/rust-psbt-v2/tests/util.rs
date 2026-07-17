// Functions in this file are all used but clippy complains still.
#![allow(dead_code)]

use core::str::FromStr;

use psbt_lab_rust_psbt_v2_adapter::{ADAPTER_PROTOCOL, handle_value};
use psbt_v2::bitcoin::hex::{self, FromHex};
use psbt_v2::{v0, v2};
use serde_json::{Value, json};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn adapter_request(operation: &str, psbt: &str) -> Value {
    handle_value(
        json!({
            "protocol": ADAPTER_PROTOCOL,
            "id": "bip370-vector",
            "operation": operation,
            "payload": { "psbt": psbt }
        }),
        DIGEST,
    )
}

#[track_caller]
pub fn hex_psbt_v0(s: &str) -> Result<v0::Psbt, v0::bitcoin::Error> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v0 from hex string {}", s),
        Ok(v) => v0::Psbt::deserialize(&v),
    }
}

#[track_caller]
pub fn hex_psbt_v2(s: &str) -> Result<v2::Psbt, v2::DeserializeError> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v2 from hex string {}", s),
        Ok(v) => v2::Psbt::deserialize(&v),
    }
}

#[track_caller]
pub fn assert_valid_v0(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt_v0(hex) {
        println!("Parse PSBT v0 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    // If we got this far decoding works so this is basically just a sanity check.
    assert!(v0::Psbt::from_str(base64).is_ok());
}

#[track_caller]
pub fn assert_valid_v2(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt_v2(hex) {
        println!("Parse PSBT v2 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    // If we got this far decoding works so this is basically just a sanity check.
    assert!(v2::Psbt::from_str(base64).is_ok());

    for operation in ["native-parse", "inspect", "roundtrip"] {
        let response = adapter_request(operation, base64);
        assert_eq!(
            response["status"], "ok",
            "adapter rejected valid BIP370 vector during {operation}: {response}"
        );
        assert_eq!(response["output"]["psbtVersion"], 2);
    }
}

#[track_caller]
pub fn assert_invalid_v0(hex: &str, base64: &str) {
    assert!(hex_psbt_v0(hex).is_err());
    assert!(v0::Psbt::from_str(base64).is_err());
}

#[track_caller]
pub fn assert_invalid_v2(hex: &str, base64: &str) {
    assert!(hex_psbt_v2(hex).is_err());
    assert!(v2::Psbt::from_str(base64).is_err());

    for operation in ["native-parse", "inspect", "roundtrip"] {
        let response = adapter_request(operation, base64);
        assert_eq!(
            response["status"], "rejected",
            "adapter accepted invalid BIP370 vector during {operation}: {response}"
        );
        let expected = if operation == "native-parse" {
            "psbt.native_parse_failed"
        } else {
            "psbt.parse_failed"
        };
        assert_eq!(response["error"]["class"], expected);
    }
}
