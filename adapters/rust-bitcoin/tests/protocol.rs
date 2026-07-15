use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::key::PrivateKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use psbt_lab_rust_adapter::handle_value;
use serde_json::{Value, json};

const MINIMAL_PSBT: &str = "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": "psbt-lab.adapter/0.2",
        "id": "test-1",
        "operation": operation,
        "payload": payload
    })
}

#[test]
fn negotiates_supported_operations() {
    let response = handle_value(request("hello", json!({})), "sha256:deadbeef");

    assert_eq!(response["status"], "ok");
    assert_eq!(response["implementation"]["name"], "rust-bitcoin");
    assert_eq!(
        response["output"],
        json!({
            "operations": ["hello", "roundtrip", "sign", "finalize-inputs"],
            "roles": ["parser", "signer", "finalizer"],
            "psbtVersions": [0],
            "scriptTypes": ["p2wsh"]
        })
    );
}

#[test]
fn roundtrips_a_psbt_v0() {
    let response = handle_value(
        request("roundtrip", json!({ "psbt": MINIMAL_PSBT })),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "ok");
    assert_eq!(response["output"]["psbt"], MINIMAL_PSBT);
    assert_eq!(response["output"]["byteIdentical"], true);
}

#[test]
fn refuses_signing_outside_regtest() {
    let response = handle_value(
        request(
            "sign",
            json!({
                "psbt": MINIMAL_PSBT,
                "network": "bitcoin",
                "fixtureId": "happy-path"
            }),
        ),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.network_not_allowed");
}

#[test]
fn refuses_caller_supplied_private_keys() {
    let response = handle_value(
        request(
            "sign",
            json!({
                "psbt": MINIMAL_PSBT,
                "network": "regtest",
                "fixtureId": "happy-path",
                "keyWif": "caller-controlled"
            }),
        ),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "protocol.invalid_payload");
}

#[test]
fn reports_unsupported_operations_with_a_stable_error() {
    for operation in [
        "inspect",
        "combine",
        "finalize",
        "fixture-finalize-input",
        "broadcast",
    ] {
        let response = handle_value(request(operation, json!({})), "sha256:deadbeef");

        assert_eq!(response["status"], "unsupported", "operation {operation}");
        assert_eq!(
            response["error"]["class"], "operation.unsupported",
            "operation {operation}"
        );
    }
}

#[test]
fn rejects_invalid_finalize_input_indexes() {
    for input_indexes in [
        json!([]),
        json!([0, 0]),
        json!([-1]),
        json!([0.5]),
        json!([9_007_199_254_740_992_u64]),
        json!([1]),
    ] {
        let response = handle_value(
            request(
                "finalize-inputs",
                json!({
                    "psbt": MINIMAL_PSBT,
                    "network": "regtest",
                    "fixtureId": "bdk-finalize-regression",
                    "inputIndexes": input_indexes
                }),
            ),
            "sha256:deadbeef",
        );

        assert_eq!(response["status"], "rejected");
        assert_eq!(response["error"]["class"], "protocol.invalid_payload");
    }
}

#[test]
fn finalize_inputs_only_finalizes_requested_inputs() {
    let key = PrivateKey::from_wif("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        .expect("fixture key");
    let public_key = key.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let witness_script = Builder::new()
        .push_key(&public_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let funding_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: witness_script.to_p2wsh(),
    };
    let funding_transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![funding_output.clone(), funding_output.clone()],
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: funding_transaction.compute_txid(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: funding_output.script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned transaction");
    for input in &mut psbt.inputs {
        input.witness_script = Some(witness_script.clone());
        input.non_witness_utxo = Some(funding_transaction.clone());
        input.bip32_derivation.insert(
            public_key.inner,
            (Fingerprint::from([0; 4]), DerivationPath::master()),
        );
    }
    let signed = handle_value(
        request(
            "sign",
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression"
            }),
        ),
        "sha256:deadbeef",
    );
    assert_eq!(signed["status"], "ok");

    let response = handle_value(
        request(
            "finalize-inputs",
            json!({
                "psbt": signed["output"]["psbt"],
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression",
                "inputIndexes": [1]
            }),
        ),
        "sha256:deadbeef",
    );
    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["finalizedInputs"], json!([1]));
    let encoded = response["output"]["psbt"].as_str().expect("encoded PSBT");
    let finalized =
        Psbt::deserialize(&STANDARD.decode(encoded).expect("base64 PSBT")).expect("valid PSBT");

    assert!(finalized.inputs[0].final_script_witness.is_none());
    assert!(!finalized.inputs[0].partial_sigs.is_empty());
    assert!(finalized.inputs[1].final_script_witness.is_some());
    assert!(finalized.inputs[1].partial_sigs.is_empty());
}

#[test]
fn refuses_a_non_witness_utxo_with_the_wrong_txid() {
    let key = PrivateKey::from_wif("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        .expect("fixture key");
    let public_key = key.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let witness_script = Builder::new()
        .push_key(&public_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let funding_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: witness_script.to_p2wsh(),
    };
    let funding_transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![funding_output.clone()],
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: funding_output.script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned transaction");
    psbt.inputs[0].witness_script = Some(witness_script);
    psbt.inputs[0].non_witness_utxo = Some(funding_transaction);

    let response = handle_value(
        request(
            "sign",
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "network": "regtest",
                "fixtureId": "happy-path"
            }),
        ),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn refuses_a_non_witness_utxo_with_an_out_of_range_vout() {
    let key = PrivateKey::from_wif("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        .expect("fixture key");
    let public_key = key.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let witness_script = Builder::new()
        .push_key(&public_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let funding_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: witness_script.to_p2wsh(),
    };
    let funding_transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![funding_output.clone()],
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_transaction.compute_txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: funding_output.script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned transaction");
    psbt.inputs[0].witness_script = Some(witness_script);
    psbt.inputs[0].witness_utxo = Some(funding_output);
    psbt.inputs[0].non_witness_utxo = Some(funding_transaction);

    let response = handle_value(
        request(
            "sign",
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "network": "regtest",
                "fixtureId": "happy-path"
            }),
        ),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}
