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
    assert!(
        Psbt::from_str(finalized)
            .expect("finalized PSBT parses")
            .is_finalized()
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
fn finalizes_and_extracts_combined_2_of_3_with_native_library_apis() {
    let psbt = fixture_psbt(true);
    let scalar_one = sign_with_adapter(&psbt, "p2wsh-2-of-3");
    let (scalar_two, _) = sign_with_private_key(psbt, 2);
    let combined = scalar_one
        .combine_with(scalar_two)
        .expect("compatible signed PSBTs");
    assert_finalize_and_extract(combined, "p2wsh-2-of-3");
}
