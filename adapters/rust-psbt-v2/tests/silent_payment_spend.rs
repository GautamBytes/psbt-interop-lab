use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::key::TapTweak;
use psbt_v2::bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use psbt_v2::bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut, Txid,
};
use psbt_v2::raw;
use psbt_v2::v2::{Constructor, InputBuilder, Modifiable, Output, Psbt, Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const FIXTURE_ID: &str = "bip376-spend";

fn scalar(value: u8) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = value;
    SecretKey::from_slice(&bytes).expect("fixture scalar")
}

fn fixture_psbt(tweak: u8) -> Psbt {
    let secp = Secp256k1::new();
    let spend_key = SecpPublicKey::from_secret_key(&secp, &scalar(1));
    let output_key = SecpPublicKey::from_secret_key(&secp, &scalar(3));
    let output_xonly = output_key.x_only_public_key().0;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0x37; 32]),
        vout: 0,
    };
    let mut input = InputBuilder::new(&outpoint)
        .segwit_fund(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_xonly.dangerous_assume_tweaked()),
        })
        .build();
    input.sequence = Some(Sequence::ENABLE_RBF_NO_LOCKTIME);
    input.unknowns.insert(
        raw::Key {
            type_value: 0x1f,
            key: spend_key.serialize().to_vec(),
        },
        vec![0_u8; 4],
    );
    let mut tweak_value = vec![0_u8; 32];
    tweak_value[31] = tweak;
    input.unknowns.insert(
        raw::Key {
            type_value: 0x20,
            key: Vec::new(),
        },
        tweak_value,
    );

    let destination_key = PublicKey::new(spend_key);
    Constructor::<Modifiable>::default()
        .input(input)
        .output(Output::new(TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &CompressedPublicKey::try_from(destination_key)
                    .expect("compressed key")
                    .wpubkey_hash(),
            ),
        }))
        .psbt()
        .expect("valid fixture PSBT")
}

fn commitment(psbt: &Psbt) -> FixtureCommitments {
    let transaction = Signer::new(psbt.clone()).expect("signer").unsigned_tx();
    let sha = format!(
        "sha256:{:x}",
        Sha256::digest(psbt_v2::bitcoin::consensus::serialize(&transaction))
    );
    FixtureCommitments::from_json(Some(&json!({ FIXTURE_ID: sha }).to_string()))
        .expect("fixture commitment")
}

fn request(psbt: &Psbt) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": "silent-payment-spend-1",
        "operation": "silent-payment-spend",
        "payload": {
            "psbt": STANDARD.encode(psbt.serialize()),
            "network": "regtest",
            "fixtureId": FIXTURE_ID
        }
    })
}

#[test]
fn verifies_tweak_signs_finalizes_and_extracts_the_bip376_spend() {
    let psbt = fixture_psbt(2);
    let response = handle_value_with_commitments(request(&psbt), DIGEST, &commitment(&psbt));
    assert_eq!(response["status"], "ok", "{response:#}");
    assert_eq!(
        response["output"]["derivedOutputKey"],
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    );
    assert_eq!(response["output"]["signedInputs"], 1);
    assert_eq!(response["output"]["finalized"], true);

    let finalized = Psbt::from_str(
        response["output"]["finalizedPsbt"]
            .as_str()
            .expect("finalized PSBT"),
    )
    .expect("finalized PSBT parses");
    let input = &finalized.inputs[0];
    assert_eq!(
        input.final_script_witness.as_ref().expect("witness").len(),
        1
    );
    assert!(input.witness_utxo.is_none());
    assert!(input.tap_key_sig.is_none());
    assert!(
        input
            .unknowns
            .keys()
            .all(|key| key.type_value != 0x1f && key.type_value != 0x20)
    );
    assert!(response["output"]["transaction"].as_str().is_some());
}

#[test]
fn rejects_a_tweak_that_does_not_match_the_witness_output_key() {
    let psbt = fixture_psbt(3);
    let response = handle_value_with_commitments(request(&psbt), DIGEST, &commitment(&psbt));
    assert_eq!(response["status"], "rejected", "{response:#}");
    assert_eq!(
        response["error"]["class"],
        "silent_payment.output_key_mismatch"
    );
}
