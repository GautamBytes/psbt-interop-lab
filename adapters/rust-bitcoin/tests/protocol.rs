use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::absolute::LockTime;
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
        "protocol": "psbt-lab.adapter/0.1",
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
    assert_eq!(response["output"]["psbtVersions"], json!([0]));
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
fn reports_unknown_operations_as_unsupported() {
    let response = handle_value(request("broadcast", json!({})), "sha256:deadbeef");

    assert_eq!(response["status"], "unsupported");
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
