use std::str::FromStr;

use psbt_lab_rust_psbt_v2_adapter::{ADAPTER_PROTOCOL, handle_value};
use psbt_v2::v2::Psbt;
use serde_json::{Value, json};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const IN_PROGRESS_PSBT: &str = "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEBAQYBAwABDiBSJ0jrF3ZNKMpJSBXsjUnn0w1SvHNCLHyG63TjlwVylAEPBAAAAAABAFUCAAAAAfTCEtWu0ef2/2M/LOCcZHxXvt2TAxTZjed1A9WOlAszAAAAAAD/////AaCGAQAAAAAAGXapFB4q14ctMpQTpW3wlovjOCIngxY7iKwAAAAAAQMEAQAAACIGAsgXu3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/sAPKZZQi/CAAAAIAAAAAAARAE/v///wABAwgYcwEAAAAAAAEJQgJ6SH/Bn7dph3uHQtbqGBGPPE5yseqMbeYCp61KQdvgaANh4bHp3l5CyyAH98pUueDVftE5OPrVbT8Z5XUTqPzgOQA=";
const EXPECTED_OUTPUT_SCRIPT: &str =
    "5120e140d287b45b46cd4eaafa4377061570babe83d1b8bc950a74a9fea09233d7a6";

fn request(psbt: &str, network: &str) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": "silent-payment-send-1",
        "operation": "silent-payment-send",
        "payload": {
            "psbt": psbt,
            "network": network,
            "fixtureId": "bip375-valid-01"
        }
    })
}

#[test]
fn completes_signs_finalizes_and_extracts_the_pinned_bip375_sender_fixture() {
    let response = handle_value(request(IN_PROGRESS_PSBT, "regtest"), DIGEST);
    assert_eq!(response["status"], "ok", "{response:#}");

    let signed = Psbt::from_str(response["output"]["psbt"].as_str().expect("signed PSBT"))
        .expect("signed PSBT parses");
    assert_eq!(signed.global.tx_modifiable_flags & 0x03, 0);
    assert_eq!(signed.inputs[0].sp_ecdh_shares.len(), 1);
    assert_eq!(signed.inputs[0].sp_dleq_proofs.len(), 1);
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    assert_eq!(
        signed.outputs[0].script_pubkey.to_hex_string(),
        EXPECTED_OUTPUT_SCRIPT
    );

    let finalized = Psbt::from_str(
        response["output"]["finalizedPsbt"]
            .as_str()
            .expect("finalized PSBT"),
    )
    .expect("finalized PSBT parses");
    assert!(finalized.inputs[0].final_script_sig.is_some());
    assert!(finalized.inputs[0].partial_sigs.is_empty());
    assert_eq!(response["output"]["finalized"], true);
    assert_eq!(response["output"]["signedInputs"], 1);
    assert_eq!(response["output"]["silentPaymentOutputs"], 1);
    assert_eq!(response["output"]["outputScript"], EXPECTED_OUTPUT_SCRIPT);
    assert!(response["output"]["transaction"].as_str().is_some());
    assert!(response["output"]["transactionId"].as_str().is_some());
}

#[test]
fn rejects_mainnet_and_any_change_to_the_pinned_sender_fixture() {
    let mainnet = handle_value(request(IN_PROGRESS_PSBT, "mainnet"), DIGEST);
    assert_eq!(mainnet["status"], "rejected");
    assert_eq!(mainnet["error"]["class"], "policy.network_not_allowed");

    let mut changed = IN_PROGRESS_PSBT.to_owned();
    changed.replace_range(20..21, if &changed[20..21] == "A" { "B" } else { "A" });
    let tampered = handle_value(request(&changed, "regtest"), DIGEST);
    assert_eq!(tampered["status"], "rejected");
    assert!(matches!(
        tampered["error"]["class"].as_str(),
        Some("policy.fixture_commitment_mismatch" | "psbt.parse_failed")
    ));
}
