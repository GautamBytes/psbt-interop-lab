use std::collections::BTreeMap;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value, handle_value_with_commitments,
};
use psbt_v2::bitcoin::bip32::{DerivationPath, Fingerprint};
use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::hex::FromHex as _;
use psbt_v2::bitcoin::script::Builder;
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::bitcoin::{
    Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxOut,
    Txid, opcodes::all::OP_CHECKMULTISIG,
};
use psbt_v2::v2::{Constructor, InputBuilder, Modifiable, Output, Psbt, Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SCALAR_ONE_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const SCALAR_TWO_PUBLIC_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SCALAR_THREE_PUBLIC_KEY: &str =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": "workflow-1",
        "operation": operation,
        "payload": payload
    })
}

fn construct(payload: Value) -> Value {
    handle_value(request("construct", payload), DIGEST)
}

fn constructed_psbt(response: &Value) -> Psbt {
    assert_eq!(response["status"], "ok", "{response:#}");
    Psbt::from_str(
        response["output"]["psbt"]
            .as_str()
            .expect("construct response PSBT"),
    )
    .expect("constructed PSBT parses")
}

fn create_for_construction(fallback_locktime: u32) -> Value {
    construct(json!({
        "action": "create",
        "inputsModifiable": true,
        "outputsModifiable": true,
        "fallbackLocktime": fallback_locktime
    }))
}

fn add_input(psbt: &Value, txid_byte: &str, height: Option<u32>, time: Option<u32>) -> Value {
    add_input_outpoint(psbt, &txid_byte.repeat(64), 0, height, time)
}

fn add_input_outpoint(
    psbt: &Value,
    previous_txid: &str,
    output_index: u32,
    height: Option<u32>,
    time: Option<u32>,
) -> Value {
    let mut payload = json!({
        "action": "add-input",
        "psbt": psbt["output"]["psbt"],
        "previousTxid": previous_txid,
        "outputIndex": output_index
    });
    if let Some(height) = height {
        payload["requiredHeightLocktime"] = json!(height);
    }
    if let Some(time) = time {
        payload["requiredTimeLocktime"] = json!(time);
    }
    construct(payload)
}

#[test]
fn constructs_updates_removes_and_seals_psbt_v2_maps() {
    const FIRST_TXID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SECOND_TXID: &str = "f0e0d0c0b0a09080706050403020100ffeeddbbccaa998877665544332211000";
    let created = create_for_construction(0);
    let first_input = add_input_outpoint(&created, FIRST_TXID, 3, None, None);
    let first_output = construct(json!({
        "action": "add-output",
        "psbt": first_input["output"]["psbt"],
        "amountSats": 50_000,
        "scriptHex": format!("0014{}", "00".repeat(20))
    }));
    let second_input = add_input_outpoint(&first_output, SECOND_TXID, 7, None, None);
    let second_output = construct(json!({
        "action": "add-output",
        "psbt": second_input["output"]["psbt"],
        "amountSats": 40_000,
        "scriptHex": format!("0014{}", "11".repeat(20))
    }));
    let sequenced = construct(json!({
        "action": "set-sequence",
        "psbt": second_output["output"]["psbt"],
        "index": 1,
        "sequence": 4_294_967_294_u32
    }));
    let removed_input = construct(json!({
        "action": "remove-input",
        "psbt": sequenced["output"]["psbt"],
        "index": 0
    }));
    let removed_output = construct(json!({
        "action": "remove-output",
        "psbt": removed_input["output"]["psbt"],
        "index": 0
    }));
    let sealed = construct(json!({
        "action": "seal",
        "psbt": removed_output["output"]["psbt"],
        "scope": "all"
    }));
    let psbt = constructed_psbt(&sealed);

    assert_eq!(psbt.global.input_count, 1);
    assert_eq!(psbt.global.output_count, 1);
    assert_eq!(psbt.inputs.len(), 1);
    assert_eq!(psbt.outputs.len(), 1);
    assert_eq!(
        psbt.inputs[0].previous_txid,
        Txid::from_str(SECOND_TXID).expect("second txid")
    );
    assert_eq!(psbt.inputs[0].spent_output_index, 7);
    assert_eq!(psbt.inputs[0].sequence, Some(Sequence(4_294_967_294)));
    assert_eq!(psbt.outputs[0].amount, Amount::from_sat(40_000));
    assert_eq!(
        psbt.outputs[0].script_pubkey,
        ScriptBuf::from_hex(&format!("0014{}", "11".repeat(20))).expect("second output script")
    );
    assert_eq!(psbt.global.tx_modifiable_flags & 0x03, 0);
    assert_eq!(sealed["output"]["inputs"], 1);
    assert_eq!(sealed["output"]["outputs"], 1);

    let rejected = add_input(&sealed, "3", None, None);
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["error"]["class"], "psbt.not_modifiable");
}

#[test]
fn rejects_zero_valued_output_with_library_boundary_error() {
    let created = create_for_construction(0);
    let response = construct(json!({
        "action": "add-output",
        "psbt": created["output"]["psbt"],
        "amountSats": 0,
        "scriptHex": "6a"
    }));
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "psbt.zero_amount_unsupported");
}

#[test]
fn determines_fallback_and_compatible_height_or_time_locktimes() {
    let fallback = add_input(&create_for_construction(99), "1", None, None);
    assert_eq!(fallback["output"]["locktime"], 99);
    assert_eq!(fallback["output"]["locktimeType"], "height");

    let height_one = add_input(&create_for_construction(0), "1", Some(100), None);
    let height_two = add_input(&height_one, "2", Some(250), None);
    assert_eq!(height_two["output"]["locktime"], 250);
    assert_eq!(height_two["output"]["locktimeType"], "height");

    let time_one = add_input(&create_for_construction(0), "1", None, Some(500_000_100));
    let time_two = add_input(&time_one, "2", None, Some(500_000_200));
    assert_eq!(time_two["output"]["locktime"], 500_000_200_u32);
    assert_eq!(time_two["output"]["locktimeType"], "time");

    let both_one = add_input(
        &create_for_construction(0),
        "1",
        Some(300),
        Some(500_000_300),
    );
    let both_two = add_input(&both_one, "2", Some(350), Some(500_000_350));
    assert_eq!(both_two["output"]["locktime"], 350);
    assert_eq!(both_two["output"]["locktimeType"], "height");
}

#[test]
fn rejects_incompatible_locktime_domains_and_invalid_indexes() {
    let height = add_input(&create_for_construction(0), "1", Some(100), None);
    let conflict = add_input(&height, "2", None, Some(500_000_100));
    assert_eq!(conflict["status"], "rejected");
    assert_eq!(conflict["error"]["class"], "psbt.locktime_conflict");

    let invalid_index = construct(json!({
        "action": "set-sequence",
        "psbt": height["output"]["psbt"],
        "index": 5,
        "sequence": 1
    }));
    assert_eq!(invalid_index["status"], "rejected");
    assert_eq!(invalid_index["error"]["class"], "psbt.index_out_of_bounds");
}

fn scalar_one_public_key() -> PublicKey {
    let key = PrivateKey::from_wif(SCALAR_ONE_WIF).expect("fixture WIF");
    key.public_key(&Secp256k1::new())
}

fn multisig_witness_script() -> ScriptBuf {
    let scalar_one = scalar_one_public_key();
    let scalar_two = PublicKey::from_str(SCALAR_TWO_PUBLIC_KEY).expect("scalar-2 public key");
    let scalar_three = PublicKey::from_str(SCALAR_THREE_PUBLIC_KEY).expect("scalar-3 public key");
    Builder::new()
        .push_int(2)
        .push_key(&scalar_one)
        .push_key(&scalar_two)
        .push_key(&scalar_three)
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn fixture_psbt(multisig: bool) -> Psbt {
    let scalar_one = scalar_one_public_key();
    let (script_pubkey, witness_script) = if multisig {
        let script = multisig_witness_script();
        (script.to_p2wsh(), Some(script))
    } else {
        (
            ScriptBuf::new_p2wpkh(&scalar_one.wpubkey_hash().expect("compressed public key")),
            None,
        )
    };
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 1,
    };
    let mut input = InputBuilder::new(&outpoint)
        .segwit_fund(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        })
        .build();
    input.sequence = Some(Sequence::ENABLE_RBF_NO_LOCKTIME);
    input.witness_script = witness_script;
    Constructor::<Modifiable>::default()
        .input(input)
        .output(Output::new(TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &scalar_one.wpubkey_hash().expect("compressed public key"),
            ),
        }))
        .psbt()
        .expect("valid fixture locktime")
}

fn encoded(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

fn unsigned_tx_sha256(psbt: &Psbt) -> String {
    let transaction = Signer::new(psbt.clone()).expect("signer").unsigned_tx();
    format!(
        "sha256:{:x}",
        Sha256::digest(psbt_v2::bitcoin::consensus::serialize(&transaction))
    )
}

fn authorized_commitments(fixture_id: &str, psbt: &Psbt) -> FixtureCommitments {
    let encoded = json!({ fixture_id: unsigned_tx_sha256(psbt) }).to_string();
    FixtureCommitments::from_json(Some(&encoded)).expect("valid commitments")
}

fn sign_with_adapter(psbt: &Psbt, fixture_id: &str) -> Psbt {
    let response = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded(psbt),
                "network": "regtest",
                "fixtureId": fixture_id
            }),
        ),
        DIGEST,
        &authorized_commitments(fixture_id, psbt),
    );
    assert_eq!(response["status"], "ok", "{response:#}");
    Psbt::from_str(response["output"]["psbt"].as_str().expect("signed PSBT"))
        .expect("signed PSBT parses")
}

fn sign_with_private_key(mut psbt: Psbt, scalar: u8) -> (Psbt, PublicKey) {
    let mut key_bytes = [0_u8; 32];
    key_bytes[31] = scalar;
    let private_key = PrivateKey::from_slice(&key_bytes, Network::Regtest).expect("private key");
    let secp = Secp256k1::new();
    let public_key = private_key.public_key(&secp);
    psbt.inputs[0].bip32_derivations.insert(
        public_key,
        (Fingerprint::default(), DerivationPath::default()),
    );
    let mut keys = BTreeMap::new();
    keys.insert(public_key, private_key);
    let (mut signed, _) = Signer::new(psbt)
        .expect("signer")
        .sign(&keys, &secp)
        .expect("native signing");
    signed.inputs[0].bip32_derivations.remove(&public_key);
    (signed, public_key)
}

#[test]
fn inspect_distinguishes_actual_transaction_identity_from_bip370_unique_id() {
    let psbt = fixture_psbt(false);
    let signer = Signer::new(psbt.clone()).expect("signer");
    let unsigned_tx = signer.unsigned_tx();
    let expected_txid = unsigned_tx.compute_txid().to_string();
    let expected_commitment = format!(
        "sha256:{:x}",
        Sha256::digest(psbt_v2::bitcoin::consensus::serialize(&unsigned_tx))
    );
    let expected_bip370_id = signer.id().expect("BIP370 id").to_string();
    assert_ne!(expected_txid, expected_bip370_id);

    let response = handle_value(
        request("inspect", json!({ "psbt": encoded(&psbt) })),
        DIGEST,
    );

    assert_eq!(response["status"], "ok");
    assert_eq!(response["output"]["transactionId"], expected_txid);
    assert_eq!(response["output"]["unsignedTxSha256"], expected_commitment);
    assert_eq!(response["output"]["bip370UniqueId"], expected_bip370_id);
    assert_eq!(response["output"]["transactionModifiableFlags"], 3);
}

#[test]
fn signing_requires_a_run_scoped_unsigned_transaction_commitment() {
    let psbt = fixture_psbt(false);
    let response = handle_value(
        request(
            "sign",
            json!({
                "psbt": encoded(&psbt),
                "network": "regtest",
                "fixtureId": "p2wpkh"
            }),
        ),
        DIGEST,
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(
        response["error"]["class"],
        "policy.fixture_commitment_missing"
    );
}

fn assert_native_signing(multisig: bool, fixture_id: &str) {
    let psbt = fixture_psbt(multisig);
    let before_identity = Signer::new(psbt.clone())
        .expect("signer")
        .id()
        .expect("BIP370 id");
    let before_commitment = unsigned_tx_sha256(&psbt);
    let commitments = authorized_commitments(fixture_id, &psbt);

    let response = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded(&psbt),
                "network": "regtest",
                "fixtureId": fixture_id
            }),
        ),
        DIGEST,
        &commitments,
    );

    assert_eq!(response["status"], "ok", "{response:#}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = Psbt::from_str(response["output"]["psbt"].as_str().expect("signed PSBT"))
        .expect("signed PSBT parses");
    assert!(
        signed.inputs[0]
            .partial_sigs
            .contains_key(&scalar_one_public_key())
    );
    assert_eq!(signed.global.tx_modifiable_flags & 0x03, 0);
    assert_eq!(unsigned_tx_sha256(&signed), before_commitment);
    assert_eq!(
        Signer::new(signed)
            .expect("signed signer")
            .id()
            .expect("signed BIP370 id"),
        before_identity
    );
}

#[test]
fn signs_p2wpkh_with_the_native_psbt_v2_signer() {
    assert_native_signing(false, "p2wpkh");
}

#[test]
fn signs_one_key_of_the_2_of_3_fixture_with_the_native_psbt_v2_signer() {
    assert_native_signing(true, "p2wsh-2-of-3");
}

#[test]
fn combines_distinct_native_signatures_for_the_same_bip370_identity() {
    let psbt = fixture_psbt(true);
    let commitments = authorized_commitments("p2wsh-2-of-3", &psbt);
    let scalar_one_response = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded(&psbt),
                "network": "regtest",
                "fixtureId": "p2wsh-2-of-3"
            }),
        ),
        DIGEST,
        &commitments,
    );
    let scalar_one = scalar_one_response["output"]["psbt"]
        .as_str()
        .expect("scalar-1 PSBT");
    let (scalar_two, scalar_two_public_key) = sign_with_private_key(psbt.clone(), 2);
    let expected_id = Signer::new(psbt).expect("signer").id().expect("BIP370 id");

    let response = handle_value(
        request(
            "combine",
            json!({ "psbts": [scalar_one, encoded(&scalar_two)] }),
        ),
        DIGEST,
    );

    assert_eq!(response["status"], "ok", "{response:#}");
    let combined = Psbt::from_str(response["output"]["psbt"].as_str().expect("combined PSBT"))
        .expect("combined PSBT parses");
    assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
    assert!(
        combined.inputs[0]
            .partial_sigs
            .contains_key(&scalar_one_public_key())
    );
    assert!(
        combined.inputs[0]
            .partial_sigs
            .contains_key(&scalar_two_public_key)
    );
    assert_eq!(
        Signer::new(combined)
            .expect("combined signer")
            .id()
            .expect("combined BIP370 id"),
        expected_id
    );
}

fn assert_finalize_and_extract(psbt: Psbt, fixture_id: &str) {
    let expected_tx = Signer::new(psbt.clone()).expect("signer").unsigned_tx();
    let expected_txid = expected_tx.compute_txid().to_string();
    let expected_commitment = unsigned_tx_sha256(&psbt);
    let expected_bip370_id = Signer::new(psbt.clone())
        .expect("signer")
        .id()
        .expect("BIP370 id")
        .to_string();
    let commitments = authorized_commitments(fixture_id, &psbt);
    let finalized_response = handle_value_with_commitments(
        request(
            "finalize",
            json!({
                "psbt": encoded(&psbt),
                "network": "regtest",
                "fixtureId": fixture_id
            }),
        ),
        DIGEST,
        &commitments,
    );
    assert_eq!(finalized_response["status"], "ok", "{finalized_response:#}");
    assert_eq!(finalized_response["output"]["finalized"], true);
    let finalized = finalized_response["output"]["psbt"]
        .as_str()
        .expect("finalized PSBT");
    let finalized_psbt = Psbt::from_str(finalized).expect("finalized PSBT parses");
    assert!(
        finalized_psbt
            .inputs
            .iter()
            .all(|input| input.final_script_witness.is_some())
    );
    assert!(
        finalized_psbt
            .inputs
            .iter()
            .all(|input| input.final_script_sig.is_none())
    );

    let extracted_response = handle_value(request("extract", json!({ "psbt": finalized })), DIGEST);
    assert_eq!(extracted_response["status"], "ok", "{extracted_response:#}");
    let raw_transaction = extracted_response["output"]["transaction"]
        .as_str()
        .expect("raw transaction");
    let transaction: Transaction = psbt_v2::bitcoin::consensus::deserialize(
        &Vec::<u8>::from_hex(raw_transaction).expect("transaction hex"),
    )
    .expect("transaction decodes");
    assert_eq!(transaction.compute_txid().to_string(), expected_txid);
    assert_eq!(
        extracted_response["output"]["transactionId"],
        transaction.compute_txid().to_string()
    );
    assert_eq!(
        extracted_response["output"]["witnessTransactionId"],
        transaction.compute_wtxid().to_string()
    );
    assert_eq!(
        extracted_response["output"]["bip370UniqueId"],
        expected_bip370_id
    );
    assert_eq!(
        extracted_response["output"]["unsignedTxSha256"],
        expected_commitment
    );
}

#[test]
fn finalizes_and_extracts_p2wpkh_with_native_library_apis() {
    let psbt = fixture_psbt(false);
    let signed = sign_with_adapter(&psbt, "p2wpkh");
    assert_finalize_and_extract(signed, "p2wpkh");
}

#[test]
fn finalizes_p2wpkh_without_noncanonical_empty_final_scriptsig() {
    let psbt = fixture_psbt(false);
    let signed = sign_with_adapter(&psbt, "p2wpkh");
    let commitments = authorized_commitments("p2wpkh", &signed);

    let finalized_response = handle_value_with_commitments(
        request(
            "finalize",
            json!({
                "psbt": encoded(&signed),
                "network": "regtest",
                "fixtureId": "p2wpkh"
            }),
        ),
        DIGEST,
        &commitments,
    );

    assert_eq!(finalized_response["status"], "ok", "{finalized_response:#}");
    let finalized = Psbt::from_str(
        finalized_response["output"]["psbt"]
            .as_str()
            .expect("finalized PSBT"),
    )
    .expect("finalized PSBT parses");
    assert!(finalized.inputs[0].final_script_witness.is_some());
    assert_eq!(finalized.inputs[0].final_script_sig, None);
}

#[test]
fn extracts_p2wpkh_with_omitted_empty_final_scriptsig() {
    let psbt = fixture_psbt(false);
    let signed = sign_with_adapter(&psbt, "p2wpkh");
    let commitments = authorized_commitments("p2wpkh", &signed);
    let finalized_response = handle_value_with_commitments(
        request(
            "finalize",
            json!({
                "psbt": encoded(&signed),
                "network": "regtest",
                "fixtureId": "p2wpkh"
            }),
        ),
        DIGEST,
        &commitments,
    );
    assert_eq!(finalized_response["status"], "ok", "{finalized_response:#}");
    let mut finalized = Psbt::from_str(
        finalized_response["output"]["psbt"]
            .as_str()
            .expect("finalized PSBT"),
    )
    .expect("finalized PSBT parses");
    assert!(finalized.inputs[0].final_script_witness.is_some());
    finalized.inputs[0].final_script_sig = None;

    let extracted_response = handle_value(
        request("extract", json!({ "psbt": encoded(&finalized) })),
        DIGEST,
    );

    assert_eq!(extracted_response["status"], "ok", "{extracted_response:#}");
    assert!(extracted_response["output"]["transaction"].is_string());
}

#[test]
fn finalizes_and_extracts_combined_2_of_3_with_native_library_apis() {
    let psbt = fixture_psbt(true);
    let scalar_one = sign_with_adapter(&psbt, "p2wsh-2-of-3");
    let (scalar_two, _) = sign_with_private_key(psbt, 2);
    let combined = scalar_one
        .combine_with(scalar_two)
        .expect("compatible signed PSBTs");
    assert_finalize_and_extract(combined, "p2wsh-2-of-3");
}
