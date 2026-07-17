use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG};
use bitcoin::psbt::PsbtSighashType;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use psbt_lab_bdk_wallet_adapter::{
    FixtureCommitments, handle_value, handle_value_with_commitments,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MINIMAL_PSBT: &str = "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const BIP370_PSBT_V2: &str = "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";
const FIXTURE_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": "psbt-lab.adapter/0.2",
        "id": "test-1",
        "operation": operation,
        "payload": payload
    })
}

fn scalar_secret_key(scalar: u8) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = scalar;
    SecretKey::from_slice(&bytes).expect("valid fixture scalar")
}

fn scalar_public_key(scalar: u8) -> bitcoin::PublicKey {
    bitcoin::PublicKey::new(scalar_secret_key(scalar).public_key(&Secp256k1::new()))
}

fn scalar_xonly(scalar: u8) -> bitcoin::XOnlyPublicKey {
    Keypair::from_secret_key(&Secp256k1::new(), &scalar_secret_key(scalar))
        .x_only_public_key()
        .0
}

fn multisig_witness_script() -> ScriptBuf {
    Builder::new()
        .push_int(2)
        .push_key(&scalar_public_key(1))
        .push_key(&scalar_public_key(2))
        .push_key(&scalar_public_key(3))
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn profile_fixture(fixture_id: &str, input_count: usize) -> String {
    let secp = Secp256k1::new();
    let public_key = scalar_public_key(1);
    let (script_pubkey, witness_script, tap_internal_key) = match fixture_id {
        "happy-path" | "bdk-finalize-regression" | "p2wsh-single-key" => {
            let witness_script = Builder::new()
                .push_key(&public_key)
                .push_opcode(OP_CHECKSIG)
                .into_script();
            (witness_script.to_p2wsh(), Some(witness_script), None)
        }
        "p2wpkh" | "intent-rich-p2wpkh" => (
            ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().expect("compressed key")),
            None,
            None,
        ),
        "p2wsh-2-of-3" => {
            let witness_script = multisig_witness_script();
            (witness_script.to_p2wsh(), Some(witness_script), None)
        }
        "p2tr-keypath" => {
            let internal_key = scalar_xonly(1);
            (
                ScriptBuf::new_p2tr(&secp, internal_key, None),
                None,
                Some(internal_key),
            )
        }
        _ => panic!("unsupported fixture profile"),
    };
    let funding = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..input_count)
            .map(|index| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(
                        [u8::try_from(index + 1).expect("test input index"); 32],
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(
                u64::try_from(input_count).expect("test input count") * 50_000 - 10_000,
            ),
            script_pubkey: funding.script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned fixture transaction");
    for input in &mut psbt.inputs {
        input.witness_utxo = Some(funding.clone());
        input.witness_script = witness_script.clone();
        input.tap_internal_key = tap_internal_key;
    }
    STANDARD.encode(psbt.serialize())
}

fn decode_psbt(encoded: &str) -> Psbt {
    Psbt::deserialize(&STANDARD.decode(encoded).expect("base64 PSBT")).expect("valid PSBT")
}

fn fixture_commitments(fixture_id: &str, encoded: &str) -> FixtureCommitments {
    let psbt = decode_psbt(encoded);
    let transaction = bitcoin::consensus::serialize(&psbt.unsigned_tx);
    let commitment = format!("sha256:{:x}", Sha256::digest(transaction));
    FixtureCommitments::from_json(Some(&format!(r#"{{"{fixture_id}":"{commitment}"}}"#)))
        .expect("valid fixture commitment configuration")
}

fn authorized_request(operation: &str, fixture_id: &str, encoded: &str) -> Value {
    handle_value_with_commitments(
        request(
            operation,
            json!({
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": fixture_id
            }),
        ),
        "sha256:deadbeef",
        &fixture_commitments(fixture_id, encoded),
    )
}

fn response_psbt(response: &Value) -> Psbt {
    decode_psbt(response["output"]["psbt"].as_str().expect("response PSBT"))
}

#[test]
fn negotiates_current_bdk_capabilities() {
    let response = handle_value(request("hello", json!({})), "sha256:deadbeef");

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["implementation"]["name"], "bdk-wallet-current");
    assert_eq!(response["implementation"]["version"], "3.1.0");
    assert_eq!(
        response["implementation"]["sourceRevision"],
        "bdk-wallet-v3.1.0+bitcoin-0.32.102+miniscript-12.3.7"
    );
    assert_eq!(
        response["output"],
        json!({
            "operations": ["hello", "native-parse", "inspect", "roundtrip", "sign", "finalize"],
            "roles": ["parser", "signer", "finalizer"],
            "psbtVersions": [0],
            "scriptTypes": ["p2wpkh", "p2wsh", "p2tr-keypath"],
            "operationScriptTypes": {
                "inspect": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                "roundtrip": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                "sign": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                "finalize": ["p2wpkh", "p2wsh", "p2tr-keypath"]
            },
            "features": [
                "fixture-commitment-sha256",
                "network-free",
                "trusted-witness-utxo-authorized-fixtures-only"
            ]
        })
    );
}

#[test]
fn rejects_requests_with_unsafe_ids_or_non_exact_top_level_fields() {
    let cases = [
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "", "operation": "hello", "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "-bad", "operation": "hello", "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "bad id", "operation": "hello", "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "a".repeat(65), "operation": "hello", "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.1", "id": "safe-1", "operation": "hello", "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "safe-1", "operation": "hello", "payload": {}, "extra": true}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "safe-1", "operation": 7, "payload": {}}),
        json!({"protocol": "psbt-lab.adapter/0.2", "id": "safe-1", "operation": "hello", "payload": []}),
    ];

    for value in cases {
        let response = handle_value(value, "sha256:deadbeef");
        assert_eq!(response["status"], "rejected", "{response}");
        assert_eq!(response["error"]["class"], "protocol.invalid_request");
        assert!(response.get("output").is_none());
    }
}

#[test]
fn rejects_non_empty_hello_payload_and_reports_unknown_operations() {
    let invalid = handle_value(request("hello", json!({"extra": true})), "sha256:deadbeef");
    assert_eq!(invalid["status"], "rejected", "{invalid}");
    assert_eq!(invalid["error"]["class"], "protocol.invalid_payload");

    let unsupported = handle_value(request("combine", json!({})), "sha256:deadbeef");
    assert_eq!(unsupported["status"], "unsupported", "{unsupported}");
    assert_eq!(unsupported["error"]["class"], "operation.unsupported");
}

#[test]
fn native_parse_uses_bdk_reexported_rust_bitcoin_parser() {
    let accepted = handle_value(
        request("native-parse", json!({"psbt": MINIMAL_PSBT})),
        "sha256:deadbeef",
    );
    assert_eq!(accepted["status"], "ok", "{accepted}");
    assert_eq!(
        accepted["output"],
        json!({
            "nativeParser": "bdk_wallet::bitcoin::Psbt",
            "psbtVersion": 0,
            "inputs": 1,
            "outputs": 1
        })
    );

    for psbt in ["***", "bm90IGEgcHNidA==", BIP370_PSBT_V2] {
        let rejected = handle_value(
            request("native-parse", json!({"psbt": psbt})),
            "sha256:deadbeef",
        );
        assert_eq!(rejected["status"], "rejected", "{rejected}");
        assert_eq!(rejected["error"]["class"], "psbt.native_parse_failed");
    }
}

#[test]
fn inspect_reports_psbt_v0_shape_and_signature_state() {
    let response = handle_value(
        request("inspect", json!({"psbt": MINIMAL_PSBT})),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(
        response["output"],
        json!({
            "psbtVersion": 0,
            "inputs": 1,
            "outputs": 1,
            "finalizedInputs": 0,
            "partialSignatureInputs": 0
        })
    );
}

#[test]
fn roundtrip_preserves_a_canonical_psbt_v0() {
    let response = handle_value(
        request("roundtrip", json!({"psbt": MINIMAL_PSBT})),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["psbt"], MINIMAL_PSBT);
    assert_eq!(response["output"]["byteIdentical"], true);
    assert_eq!(response["output"]["psbtVersion"], 0);
}

#[test]
fn parser_operations_require_only_bounded_canonical_base64() {
    let noncanonical = MINIMAL_PSBT.trim_end_matches('=');
    let oversized = "A".repeat(4 * 1024 * 1024);
    for operation in ["native-parse", "inspect", "roundtrip"] {
        for psbt in [noncanonical, oversized.as_str()] {
            let response =
                handle_value(request(operation, json!({"psbt": psbt})), "sha256:deadbeef");
            assert_eq!(response["status"], "rejected", "{operation}: {response}");
            let expected = if operation == "native-parse" {
                "psbt.native_parse_failed"
            } else {
                "psbt.parse_failed"
            };
            assert_eq!(
                response["error"]["class"], expected,
                "{operation}: {response}"
            );
        }

        let unknown = handle_value(
            request(operation, json!({"psbt": MINIMAL_PSBT, "extra": true})),
            "sha256:deadbeef",
        );
        assert_eq!(unknown["status"], "rejected", "{operation}: {unknown}");
        assert_eq!(unknown["error"]["class"], "protocol.invalid_payload");
    }
}

#[test]
fn parses_only_bounded_allowlisted_fixture_commitments() {
    assert!(FixtureCommitments::from_json(None).is_ok());
    assert!(FixtureCommitments::from_json(Some("[]")).is_err());
    assert!(FixtureCommitments::from_json(Some("{}")).is_err());
    assert!(
        FixtureCommitments::from_json(Some(&format!(
            r#"{{"unknown":"sha256:{}"}}"#,
            "00".repeat(32)
        )))
        .is_err()
    );
    assert!(
        FixtureCommitments::from_json(Some(&format!(
            r#"{{"p2wpkh":"sha256:{}"}}"#,
            "AA".repeat(32)
        )))
        .is_err()
    );
    assert!(FixtureCommitments::from_json(Some(&"x".repeat(4 * 1024 + 1))).is_err());

    for fixture_id in [
        "happy-path",
        "bdk-finalize-regression",
        "p2wpkh",
        "intent-rich-p2wpkh",
        "p2wsh-single-key",
        "p2wsh-2-of-3",
        "p2tr-keypath",
    ] {
        let raw = format!(r#"{{"{fixture_id}":"sha256:{}"}}"#, "00".repeat(32));
        assert!(
            FixtureCommitments::from_json(Some(&raw)).is_ok(),
            "{fixture_id}"
        );
    }
}

#[test]
fn signing_requires_exact_regtest_fixture_authorization() {
    let encoded = profile_fixture("p2wpkh", 1);
    let payload = json!({
        "psbt": encoded,
        "network": "regtest",
        "fixtureId": "p2wpkh"
    });

    let missing = handle_value(request("sign", payload.clone()), "sha256:deadbeef");
    assert_eq!(missing["status"], "rejected", "{missing}");
    assert_eq!(
        missing["error"]["class"],
        "policy.fixture_commitment_missing"
    );

    let wrong = FixtureCommitments::from_json(Some(&format!(
        r#"{{"p2wpkh":"sha256:{}"}}"#,
        "00".repeat(32)
    )))
    .expect("valid wrong commitment");
    let mismatch =
        handle_value_with_commitments(request("sign", payload.clone()), "sha256:deadbeef", &wrong);
    assert_eq!(mismatch["status"], "rejected", "{mismatch}");
    assert_eq!(
        mismatch["error"]["class"],
        "policy.fixture_commitment_mismatch"
    );

    let network = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded,
                "network": "bitcoin",
                "fixtureId": "p2wpkh"
            }),
        ),
        "sha256:deadbeef",
        &fixture_commitments("p2wpkh", &encoded),
    );
    assert_eq!(network["status"], "rejected", "{network}");
    assert_eq!(network["error"]["class"], "policy.network_not_allowed");

    let caller_key = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": "p2wpkh",
                "keyWif": FIXTURE_WIF
            }),
        ),
        "sha256:deadbeef",
        &fixture_commitments("p2wpkh", &profile_fixture("p2wpkh", 1)),
    );
    assert_eq!(caller_key["status"], "rejected", "{caller_key}");
    assert_eq!(caller_key["error"]["class"], "protocol.invalid_payload");
}

#[test]
fn bdk_signs_all_declared_script_profiles_without_finalizing() {
    for fixture_id in ["p2wpkh", "p2wsh-single-key", "p2wsh-2-of-3", "p2tr-keypath"] {
        let encoded = profile_fixture(fixture_id, 1);
        let response = authorized_request("sign", fixture_id, &encoded);

        assert_eq!(response["status"], "ok", "{fixture_id}: {response}");
        assert_eq!(response["output"]["signedInputs"], 1, "{fixture_id}");
        let signed = response_psbt(&response);
        assert!(
            signed.inputs[0].final_script_sig.is_none()
                && signed.inputs[0].final_script_witness.is_none(),
            "sign must not finalize {fixture_id}"
        );
        if fixture_id == "p2tr-keypath" {
            let signature = signed.inputs[0]
                .tap_key_sig
                .as_ref()
                .expect("Taproot key-path signature");
            assert_eq!(signature.sighash_type, TapSighashType::Default);
        } else {
            let signature = signed.inputs[0]
                .partial_sigs
                .get(&scalar_public_key(1))
                .expect("scalar-1 ECDSA signature");
            assert_eq!(signature.sighash_type, EcdsaSighashType::All);
        }
    }
}

#[test]
fn sign_preserves_unselected_inputs() {
    let encoded = profile_fixture("p2wpkh", 2);
    let original = decode_psbt(&encoded);
    let response = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": "p2wpkh",
                "inputIndexes": [1]
            }),
        ),
        "sha256:deadbeef",
        &fixture_commitments("p2wpkh", &profile_fixture("p2wpkh", 2)),
    );

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = response_psbt(&response);
    assert_eq!(signed.inputs[0], original.inputs[0]);
    assert!(
        signed.inputs[1]
            .partial_sigs
            .contains_key(&scalar_public_key(1))
    );
}

#[test]
fn signing_rejects_nonstandard_sighashes_and_profile_tampering() {
    let mut psbt = decode_psbt(&profile_fixture("p2wpkh", 1));
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::Single));
    let encoded = STANDARD.encode(psbt.serialize());
    let sighash = authorized_request("sign", "p2wpkh", &encoded);
    assert_eq!(sighash["status"], "rejected", "{sighash}");
    assert_eq!(sighash["error"]["class"], "policy.psbt_not_authorized");

    let mut psbt = decode_psbt(&profile_fixture("p2tr-keypath", 1));
    psbt.inputs[0].tap_merkle_root = Some(bitcoin::TapNodeHash::from_byte_array([7; 32]));
    let encoded = STANDARD.encode(psbt.serialize());
    let script_path = authorized_request("sign", "p2tr-keypath", &encoded);
    assert_eq!(script_path["status"], "rejected", "{script_path}");
    assert_eq!(script_path["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn bdk_finalizes_fully_signed_p2wpkh_p2wsh_and_p2tr() {
    for fixture_id in ["p2wpkh", "p2wsh-single-key", "p2tr-keypath"] {
        let encoded = profile_fixture(fixture_id, 1);
        let signed = authorized_request("sign", fixture_id, &encoded);
        assert_eq!(signed["status"], "ok", "{fixture_id}: {signed}");
        let signed_encoded = signed["output"]["psbt"].as_str().expect("signed PSBT");
        let finalized = authorized_request("finalize", fixture_id, signed_encoded);

        assert_eq!(finalized["status"], "ok", "{fixture_id}: {finalized}");
        assert_eq!(finalized["output"]["finalizedInputs"], json!([0]));
        let psbt = response_psbt(&finalized);
        assert!(psbt.inputs[0].final_script_witness.is_some());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }
}

#[test]
fn bdk_finalizer_skips_an_already_finalized_regression_input() {
    let encoded = profile_fixture("bdk-finalize-regression", 2);
    let signed = authorized_request("sign", "bdk-finalize-regression", &encoded);
    assert_eq!(signed["status"], "ok", "{signed}");
    let mut partial = response_psbt(&signed);
    let signature = partial.inputs[0]
        .partial_sigs
        .get(&scalar_public_key(1))
        .expect("fixture signature")
        .to_vec();
    let witness_script = partial.inputs[0]
        .witness_script
        .clone()
        .expect("fixture witness script");
    partial.inputs[0].final_script_witness = Some(Witness::from_slice(&[
        signature,
        witness_script.as_bytes().to_vec(),
    ]));
    partial.inputs[0].partial_sigs.clear();
    partial.inputs[0].sighash_type = None;
    partial.inputs[0].witness_script = None;
    partial.inputs[0].bip32_derivation.clear();
    let partial_encoded = STANDARD.encode(partial.serialize());

    let finalized = authorized_request("finalize", "bdk-finalize-regression", &partial_encoded);
    assert_eq!(finalized["status"], "ok", "{finalized}");
    assert_eq!(finalized["output"]["finalizedInputs"], json!([1]));
    assert!(
        response_psbt(&finalized)
            .inputs
            .iter()
            .all(|input| input.final_script_witness.is_some())
    );
}

#[test]
fn bdk_finalizes_a_complete_two_of_three_multisig() {
    let encoded = profile_fixture("p2wsh-2-of-3", 1);
    let signed = authorized_request("sign", "p2wsh-2-of-3", &encoded);
    assert_eq!(signed["status"], "ok", "{signed}");
    let mut psbt = response_psbt(&signed);
    let funding = psbt.inputs[0].witness_utxo.as_ref().expect("witness UTXO");
    let witness_script = psbt.inputs[0]
        .witness_script
        .as_ref()
        .expect("multisig witness script");
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wsh_signature_hash(0, witness_script, funding.value, EcdsaSighashType::All)
        .expect("multisig sighash");
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        Secp256k1::new().sign_ecdsa(&Message::from(sighash), &scalar_secret_key(2)),
    );
    psbt.inputs[0]
        .partial_sigs
        .insert(scalar_public_key(2), signature);
    let fully_signed = STANDARD.encode(psbt.serialize());

    let finalized = authorized_request("finalize", "p2wsh-2-of-3", &fully_signed);
    assert_eq!(finalized["status"], "ok", "{finalized}");
    assert_eq!(finalized["output"]["finalizedInputs"], json!([0]));
    assert!(
        response_psbt(&finalized).inputs[0]
            .final_script_witness
            .is_some()
    );
}

#[test]
fn finalization_rejects_an_invalid_partial_signature() {
    let encoded = profile_fixture("p2wpkh", 1);
    let signed = authorized_request("sign", "p2wpkh", &encoded);
    assert_eq!(signed["status"], "ok", "{signed}");
    let mut psbt = response_psbt(&signed);
    psbt.inputs[0]
        .partial_sigs
        .get_mut(&scalar_public_key(1))
        .expect("fixture signature")
        .signature =
        Secp256k1::new().sign_ecdsa(&Message::from_digest([42; 32]), &scalar_secret_key(1));
    let tampered = STANDARD.encode(psbt.serialize());

    let finalized = authorized_request("finalize", "p2wpkh", &tampered);
    assert_eq!(finalized["status"], "rejected", "{finalized}");
    assert_eq!(finalized["error"]["class"], "finalize.signature_invalid");
    assert!(finalized.get("output").is_none());
}

#[test]
fn finalization_rejects_an_invalid_already_finalized_witness() {
    let encoded = profile_fixture("bdk-finalize-regression", 1);
    let signed = authorized_request("sign", "bdk-finalize-regression", &encoded);
    assert_eq!(signed["status"], "ok", "{signed}");
    let mut psbt = response_psbt(&signed);
    let bad_signature = bitcoin::ecdsa::Signature::sighash_all(
        Secp256k1::new().sign_ecdsa(&Message::from_digest([99; 32]), &scalar_secret_key(1)),
    );
    let witness_script = psbt.inputs[0]
        .witness_script
        .clone()
        .expect("fixture witness script");
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[
        bad_signature.to_vec(),
        witness_script.as_bytes().to_vec(),
    ]));
    psbt.inputs[0].partial_sigs.clear();
    psbt.inputs[0].sighash_type = None;
    psbt.inputs[0].witness_script = None;
    let tampered = STANDARD.encode(psbt.serialize());

    let finalized = authorized_request("finalize", "bdk-finalize-regression", &tampered);
    assert_eq!(finalized["status"], "rejected", "{finalized}");
    assert_eq!(finalized["error"]["class"], "finalize.signature_invalid");
}
