use psbt_lab_rust_psbt_v2_adapter::{ADAPTER_PROTOCOL, handle_value};
use serde_json::{Value, json};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const VALID_02_IN_PROGRESS: &str = "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQIBBQEBAQYBAwABDiAYpxdmOwurFLEqGncTI/8eQHndUy5d0T4o6hCBxwCYSgEPBAAAAAABAR+ghgEAAAAAABYAFCKactNKZFvTSWu79Qu7gckGP0+UIgYCyBe7dSGvw16pbzv7Jw5utQ3f+lVgYnuWH+wA8pllCL8IAAAAgAAAAAABEAT+////AAEOIL6dZcg5FfsJJIq738qMo+7mzjUMVU9l6NUm5d9SerUiAQ8EAAAAAAEBH6CGAQAAAAAAFgAUE5NQEXxXeUGphYArue3vwROTK8ciBgL1tZ+l5JIiHr9VunitRCYFvq6VFmuh66MlDQu6rH4u3AgAAACAAQAAAAEQBP7///8AAQMIGHMBAAAAAAABCUICekh/wZ+3aYd7h0LW6hgRjzxOcrHqjG3mAqetSkHb4GgDYeGx6d5eQssgB/fKVLng1X7ROTj61W0/GeV1E6j84DkA";
const EXPECTED_SCRIPT: &str =
    "5120133d6a4f509095b5794f7491fbc3f12c3c45bc2d9b60af25b8bba704c8072aaf";

fn request(psbt: &str, network: &str, fixture_id: &str, signer: Value) -> Value {
    handle_value(
        json!({
            "protocol": ADAPTER_PROTOCOL,
            "id": "advanced-send",
            "operation": "silent-payment-send-advanced",
            "payload": {
                "psbt": psbt,
                "network": network,
                "fixtureId": fixture_id,
                "signer": signer
            }
        }),
        DIGEST,
    )
}

#[test]
fn declares_the_advanced_sender_operation() {
    let response = handle_value(
        json!({
            "protocol": ADAPTER_PROTOCOL,
            "id": "hello-advanced",
            "operation": "hello",
            "payload": {}
        }),
        DIGEST,
    );
    assert_eq!(response["status"], "ok");
    assert!(
        response["output"]["operations"]
            .as_array()
            .expect("operations")
            .iter()
            .any(|operation| operation == "silent-payment-send-advanced")
    );
    assert!(
        response["output"]["features"]
            .as_array()
            .expect("features")
            .iter()
            .any(|feature| feature == "bip375-advanced-sender-workflows")
    );
}

#[test]
fn aggregates_two_inputs_derives_and_signs_valid_02() {
    let response = request(VALID_02_IN_PROGRESS, "regtest", "valid-02", json!("all"));
    assert_eq!(response["status"], "ok", "{response:#}");
    assert_eq!(response["output"]["finalized"], false);
    assert_eq!(response["output"]["finalizationAvailable"], false);
    assert_eq!(response["output"]["partialSignatureInputs"], 2);
    assert_eq!(response["output"]["silentPaymentOutputs"], 1);
    assert_eq!(
        response["output"]["outputScripts"],
        json!([EXPECTED_SCRIPT])
    );
    assert!(response["output"]["psbt"].as_str().is_some());
}

#[test]
fn rejects_untrusted_networks_and_fixture_aliases_before_signing() {
    let mainnet = request(VALID_02_IN_PROGRESS, "mainnet", "valid-02", json!("all"));
    assert_eq!(mainnet["status"], "rejected");
    assert_eq!(mainnet["error"]["class"], "policy.network_not_allowed");

    let alias = request(VALID_02_IN_PROGRESS, "regtest", "valid-03", json!("all"));
    assert_eq!(alias["status"], "rejected");
    assert_eq!(
        alias["error"]["class"],
        "policy.fixture_commitment_mismatch"
    );
}
