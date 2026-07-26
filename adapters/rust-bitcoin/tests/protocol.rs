use std::io::Write;
use std::process::{Command, Stdio};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::{PrivateKey, TapTweak};
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG};
use bitcoin::psbt::PsbtSighashType;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use psbt_lab_rust_adapter::{FixtureCommitments, handle_value, handle_value_with_commitments};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MINIMAL_PSBT: &str = "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const FIXED_SIGNABLE_PSBT_V0: &str = "cHNidP8BAF4CAAAAAabTulINz+LhVA4VD8G0vFOohTRR1SaURoBkvPBzDudKAAAAAAD/////AWi/AAAAAAAAIgAgGGMUPBTFFmgEvRkgM1baE2yYVnjNTSehuMYylgSQMmIAAAAAAAEBK1DDAAAAAAAAIgAgGGMUPBTFFmgEvRkgM1baE2yYVnjNTSehuMYylgSQMmIBBSMhAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYrAAA";
const CORE_TYPESCRIPT_UNSIGNED_TX_HEX: &str = "0200000001a6d3ba520dcfe2e1540e150fc1b4bc53a8853451d52694468064bcf0730ee74a0000000000ffffffff0168bf0000000000002200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326200000000";
const CORE_TYPESCRIPT_UNSIGNED_TX_COMMITMENT: &str =
    "sha256:2f46d1ac133fc2d11c6c267ae8a299eb19d688f9d1ea7d1fa0e178aaf339e4de";
const FIXTURE_COMMITMENTS_ENV: &str = "PSBT_LAB_FIXTURE_COMMITMENTS";
const FIXTURE_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

fn request(operation: &str, payload: Value) -> Value {
    json!({
        "protocol": "psbt-lab.adapter/0.2",
        "id": "test-1",
        "operation": operation,
        "payload": payload
    })
}

fn spawned_signing_response(fixture_commitments: Option<&str>) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_psbt-lab-rust-adapter"));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match fixture_commitments {
        Some(value) => {
            command.env(FIXTURE_COMMITMENTS_ENV, value);
        }
        None => {
            command.env_remove(FIXTURE_COMMITMENTS_ENV);
        }
    }

    let mut child = command.spawn().expect("adapter executable starts");
    let mut stdin = child.stdin.take().expect("adapter stdin");
    serde_json::to_writer(
        &mut stdin,
        &request(
            "sign",
            json!({
                "psbt": FIXED_SIGNABLE_PSBT_V0,
                "network": "regtest",
                "fixtureId": "happy-path"
            }),
        ),
    )
    .expect("serialize signing request");
    stdin.write_all(b"\n").expect("write request terminator");
    drop(stdin);

    let output = child.wait_with_output().expect("adapter exits");
    assert!(
        output.status.success(),
        "adapter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON response")
}

fn fixture_commitments(fixture_id: &str, encoded: &str) -> FixtureCommitments {
    let psbt = Psbt::deserialize(&STANDARD.decode(encoded).expect("base64 PSBT"))
        .expect("valid fixture PSBT");
    let transaction = bitcoin::consensus::serialize(&psbt.unsigned_tx);
    let commitment = format!("sha256:{:x}", Sha256::digest(transaction));
    FixtureCommitments::from_json(Some(&format!(r#"{{"{fixture_id}":"{commitment}"}}"#)))
        .expect("fixture commitments")
}

fn handle_authorized(value: Value, fixture_id: &str, encoded: &str) -> Value {
    handle_value_with_commitments(
        value,
        "sha256:deadbeef",
        &fixture_commitments(fixture_id, encoded),
    )
}

fn sign_profile(fixture_id: &str, encoded: &str, input_indexes: Option<Value>) -> Value {
    let payload = match input_indexes {
        Some(input_indexes) => json!({
            "psbt": encoded,
            "network": "regtest",
            "fixtureId": fixture_id,
            "inputIndexes": input_indexes
        }),
        None => json!({
            "psbt": encoded,
            "network": "regtest",
            "fixtureId": fixture_id
        }),
    };
    handle_authorized(request("sign", payload), fixture_id, encoded)
}

fn sign_profile_with_sighash(fixture_id: &str, encoded: &str, sighash_type: u32) -> Value {
    sign_profile_with_sighash_and_indexes(fixture_id, encoded, sighash_type, None)
}

fn sign_profile_with_sighash_and_indexes(
    fixture_id: &str,
    encoded: &str,
    sighash_type: u32,
    input_indexes: Option<Value>,
) -> Value {
    let mut payload = json!({
        "psbt": encoded,
        "network": "regtest",
        "fixtureId": fixture_id,
        "sighashType": sighash_type
    });
    if let Some(input_indexes) = input_indexes {
        payload["inputIndexes"] = input_indexes;
    }
    handle_authorized(request("sign", payload), fixture_id, encoded)
}

fn decode_psbt(encoded: &str) -> Psbt {
    Psbt::deserialize(&STANDARD.decode(encoded).expect("base64 PSBT")).expect("valid PSBT")
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

fn taproot_script_path() -> (ScriptBuf, ScriptBuf, ControlBlock, TapLeafHash) {
    let secp = Secp256k1::new();
    let leaf_script = Builder::new()
        .push_x_only_key(&scalar_xonly(2))
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .expect("single Taproot leaf")
        .finalize(&secp, scalar_xonly(1))
        .expect("complete Taproot tree");
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .expect("fixture control block");
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    (
        ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        leaf_script,
        control_block,
        leaf_hash,
    )
}

fn unsigned_profile_fixture(fixture_id: &str, input_count: usize) -> String {
    let secp = Secp256k1::new();
    let fixture_public_key = scalar_public_key(1);
    let (script_pubkey, redeem_script, witness_script, tap_internal_key, tap_script) =
        match fixture_id {
            "p2pkh" => (
                ScriptBuf::new_p2pkh(&fixture_public_key.pubkey_hash()),
                None,
                None,
                None,
                None,
            ),
            "p2wpkh" | "intent-rich-p2wpkh" | "sighash-p2wpkh" => (
                ScriptBuf::new_p2wpkh(&fixture_public_key.wpubkey_hash().expect("compressed key")),
                None,
                None,
                None,
                None,
            ),
            "p2wsh-2-of-3" => {
                let witness_script = multisig_witness_script();
                (
                    witness_script.to_p2wsh(),
                    None,
                    Some(witness_script),
                    None,
                    None,
                )
            }
            "p2sh-p2wsh-2-of-3" => {
                let witness_script = multisig_witness_script();
                let redeem_script = witness_script.to_p2wsh();
                (
                    redeem_script.to_p2sh(),
                    Some(redeem_script),
                    Some(witness_script),
                    None,
                    None,
                )
            }
            "p2tr-keypath" | "sighash-p2tr-keypath" => {
                let internal_key = scalar_xonly(1);
                (
                    ScriptBuf::new_p2tr(&secp, internal_key, None),
                    None,
                    None,
                    Some(internal_key),
                    None,
                )
            }
            "p2tr-scriptpath" => {
                let (script_pubkey, leaf_script, control_block, _) = taproot_script_path();
                (
                    script_pubkey,
                    None,
                    None,
                    Some(scalar_xonly(1)),
                    Some((control_block, (leaf_script, LeafVersion::TapScript))),
                )
            }
            _ => panic!("unsupported profile fixture"),
        };
    let funding_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let funding_transactions = (0..input_count)
        .map(|index| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new()
                    .push_int(i64::try_from(index + 1).expect("test index"))
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![funding_output.clone()],
        })
        .collect::<Vec<_>>();
    let fixture_fee = match fixture_id {
        "p2pkh" => 10_500,
        "p2wpkh" => 11_000,
        "p2sh-p2wsh-2-of-3" => 12_500,
        "p2wsh-2-of-3" => 13_000,
        "p2tr-keypath" => 14_000,
        "p2tr-scriptpath" => 14_500,
        "intent-rich-p2wpkh" => 15_000,
        "sighash-p2wpkh" => 22_000,
        "sighash-p2tr-keypath" => 28_000,
        _ => panic!("missing fixture fee"),
    };
    let output_count = if fixture_id.starts_with("sighash-") {
        input_count
    } else {
        1
    };
    let spendable = u64::try_from(input_count).expect("test input count") * 50_000 - fixture_fee;
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..input_count)
            .map(|index| TxIn {
                previous_output: OutPoint {
                    txid: funding_transactions[index].compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..output_count)
            .map(|index| {
                let quotient = spendable / u64::try_from(output_count).expect("output count");
                let remainder = spendable % u64::try_from(output_count).expect("output count");
                TxOut {
                    value: Amount::from_sat(
                        quotient + u64::from(index == output_count - 1) * remainder,
                    ),
                    script_pubkey: funding_output.script_pubkey.clone(),
                }
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned transaction");
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if fixture_id == "p2pkh" {
            input.non_witness_utxo = Some(funding_transactions[index].clone());
        } else {
            input.witness_utxo = Some(funding_output.clone());
        }
        input.redeem_script = redeem_script.clone();
        input.witness_script = witness_script.clone();
        input.tap_internal_key = tap_internal_key;
        if let Some((control_block, script)) = tap_script.clone() {
            input.tap_scripts.insert(control_block, script);
        }
        if fixture_id == "p2tr-scriptpath" {
            let (_, _, _, leaf_hash) = taproot_script_path();
            input.tap_merkle_root = Some(bitcoin::TapNodeHash::from(leaf_hash));
            input.tap_key_origins.insert(
                scalar_xonly(1),
                (
                    vec![],
                    (
                        Fingerprint::from([0x75, 0x1e, 0x76, 0xe8]),
                        DerivationPath::default(),
                    ),
                ),
            );
            input.tap_key_origins.insert(
                scalar_xonly(2),
                (
                    vec![leaf_hash],
                    (
                        Fingerprint::from([0xab, 0x11, 0xb8, 0xce]),
                        DerivationPath::default(),
                    ),
                ),
            );
        }
        assert!(input.bip32_derivation.is_empty());
    }
    STANDARD.encode(psbt.serialize())
}

fn assert_valid_ecdsa_signature(psbt: &Psbt, input_index: usize) {
    assert_valid_ecdsa_signature_with_type(psbt, input_index, EcdsaSighashType::All);
}

fn assert_valid_ecdsa_signature_with_type(
    psbt: &Psbt,
    input_index: usize,
    sighash_type: EcdsaSighashType,
) {
    let public_key = scalar_public_key(1);
    let input = &psbt.inputs[input_index];
    let signature = input
        .partial_sigs
        .get(&public_key)
        .expect("scalar-1 ECDSA signature");
    assert_eq!(signature.sighash_type, sighash_type);
    let previous_output = psbt.unsigned_tx.input[input_index].previous_output;
    let funding_output = input.witness_utxo.as_ref().unwrap_or_else(|| {
        input
            .non_witness_utxo
            .as_ref()
            .expect("non-witness UTXO")
            .output
            .get(previous_output.vout as usize)
            .expect("referenced funding output")
    });
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let message = if funding_output.script_pubkey.is_p2pkh() {
        Message::from(
            cache
                .legacy_signature_hash(
                    input_index,
                    &funding_output.script_pubkey,
                    sighash_type.to_u32(),
                )
                .expect("P2PKH sighash"),
        )
    } else {
        Message::from(match input.witness_script.as_ref() {
            Some(witness_script) => cache
                .p2wsh_signature_hash(
                    input_index,
                    witness_script,
                    funding_output.value,
                    sighash_type,
                )
                .expect("P2WSH sighash"),
            None => cache
                .p2wpkh_signature_hash(
                    input_index,
                    &funding_output.script_pubkey,
                    funding_output.value,
                    sighash_type,
                )
                .expect("P2WPKH sighash"),
        })
    };
    Secp256k1::verification_only()
        .verify_ecdsa(&message, &signature.signature, &public_key.inner)
        .expect("valid scalar-1 ECDSA signature");
}

fn assert_valid_taproot_signature(psbt: &Psbt, input_index: usize) {
    assert_valid_taproot_signature_with_type(psbt, input_index, TapSighashType::Default);
}

fn assert_valid_taproot_signature_with_type(
    psbt: &Psbt,
    input_index: usize,
    sighash_type: TapSighashType,
) {
    let input = &psbt.inputs[input_index];
    let signature = input.tap_key_sig.as_ref().expect("Taproot key signature");
    assert_eq!(signature.sighash_type, sighash_type);
    assert_eq!(
        signature.to_vec().len(),
        if sighash_type == TapSighashType::Default {
            64
        } else {
            65
        }
    );
    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("validated prevout"))
        .collect::<Vec<_>>();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(&prevouts), sighash_type)
        .expect("Taproot key-path sighash");
    let secp = Secp256k1::verification_only();
    let output_key = scalar_xonly(1)
        .tap_tweak(&secp, None)
        .0
        .to_x_only_public_key();
    secp.verify_schnorr(&signature.signature, &Message::from(sighash), &output_key)
        .expect("valid tweaked scalar-1 Schnorr signature");
}

fn p2wpkh_signature_is_valid_for_transaction(
    psbt: &Psbt,
    transaction: &Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
) -> bool {
    let public_key = scalar_public_key(1);
    let input = &psbt.inputs[input_index];
    let Some(signature) = input.partial_sigs.get(&public_key) else {
        return false;
    };
    let Some(funding_output) = input.witness_utxo.as_ref() else {
        return false;
    };
    let Ok(sighash) = SighashCache::new(transaction).p2wpkh_signature_hash(
        input_index,
        &funding_output.script_pubkey,
        funding_output.value,
        sighash_type,
    ) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from(sighash),
            &signature.signature,
            &public_key.inner,
        )
        .is_ok()
}

fn taproot_signature_is_valid_for_transaction(
    psbt: &Psbt,
    transaction: &Transaction,
    input_index: usize,
    sighash_type: TapSighashType,
) -> bool {
    let Some(signature) = psbt.inputs[input_index].tap_key_sig.as_ref() else {
        return false;
    };
    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("validated prevout"))
        .collect::<Vec<_>>();
    let Ok(sighash) = SighashCache::new(transaction).taproot_key_spend_signature_hash(
        input_index,
        &Prevouts::All(&prevouts),
        sighash_type,
    ) else {
        return false;
    };
    let secp = Secp256k1::verification_only();
    let output_key = scalar_xonly(1)
        .tap_tweak(&secp, None)
        .0
        .to_x_only_public_key();
    secp.verify_schnorr(&signature.signature, &Message::from(sighash), &output_key)
        .is_ok()
}

fn assert_valid_taproot_script_signature(psbt: &Psbt, input_index: usize) {
    let (_, leaf_script, _, leaf_hash) = taproot_script_path();
    let signature = psbt.inputs[input_index]
        .tap_script_sigs
        .get(&(scalar_xonly(2), leaf_hash))
        .expect("scalar-2 Taproot script-path signature");
    assert_eq!(signature.sighash_type, TapSighashType::Default);
    assert_eq!(signature.to_vec().len(), 64);
    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("validated prevout"))
        .collect::<Vec<_>>();
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .expect("Taproot script-path sighash");
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature.signature,
            &Message::from(sighash),
            &scalar_xonly(2),
        )
        .expect("valid scalar-2 Schnorr signature");
}

#[test]
fn negotiates_supported_operations() {
    let response = handle_value(request("hello", json!({})), "sha256:deadbeef");

    assert_eq!(response["status"], "ok");
    assert_eq!(response["implementation"]["name"], "rust-bitcoin");
    assert_eq!(
        response["output"],
        json!({
            "operations": ["hello", "native-parse", "roundtrip", "sign", "finalize-inputs"],
            "roles": ["parser", "signer", "finalizer"],
            "psbtVersions": [0],
            "scriptTypes": ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
            "operationScriptTypes": {
                "roundtrip": ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                "sign": ["p2pkh", "p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                "finalize-inputs": ["p2wsh", "p2tr-scriptpath"]
            },
            "features": [
                "fixture-commitment-sha256",
                "sighash-matrix-v1",
                "adversarial-signer-inputs-v1"
            ]
        })
    );
}

#[test]
fn native_parse_uses_rust_bitcoin_without_fixture_policy() {
    let accepted = handle_value(
        request("native-parse", json!({ "psbt": MINIMAL_PSBT })),
        "sha256:deadbeef",
    );
    assert_eq!(accepted["status"], "ok", "{accepted}");
    assert_eq!(accepted["output"]["nativeParser"], "rust-bitcoin");

    let rejected = handle_value(
        request(
            "native-parse",
            json!({ "psbt": STANDARD.encode(b"not a psbt") }),
        ),
        "sha256:deadbeef",
    );
    assert_eq!(rejected["status"], "rejected", "{rejected}");
    assert_eq!(rejected["error"]["class"], "psbt.native_parse_failed");
}

#[test]
fn signing_requires_the_configured_unsigned_transaction_commitment() {
    let encoded = unsigned_two_input_fixture();
    let request_value = request(
        "sign",
        json!({
            "psbt": encoded.clone(),
            "network": "regtest",
            "fixtureId": "bdk-finalize-regression"
        }),
    );

    let missing = handle_value(request_value.clone(), "sha256:deadbeef");
    assert_eq!(missing["status"], "rejected");
    assert_eq!(
        missing["error"]["class"],
        "policy.fixture_commitment_missing"
    );

    let wrong = FixtureCommitments::from_json(Some(&format!(
        r#"{{"bdk-finalize-regression":"sha256:{}"}}"#,
        "00".repeat(32)
    )))
    .expect("valid mismatched commitment config");
    let mismatched = handle_value_with_commitments(request_value, "sha256:deadbeef", &wrong);
    assert_eq!(mismatched["status"], "rejected");
    assert_eq!(
        mismatched["error"]["class"],
        "policy.fixture_commitment_mismatch"
    );

    let invalid = handle_value_with_commitments(
        request(
            "sign",
            json!({
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression"
            }),
        ),
        "sha256:deadbeef",
        &FixtureCommitments::invalid(),
    );
    assert_eq!(invalid["status"], "crashed");
    assert_eq!(invalid["error"]["class"], "adapter.invalid_configuration");
}

#[test]
fn spawned_adapter_signs_with_valid_startup_fixture_commitments() {
    let psbt = Psbt::deserialize(
        &STANDARD
            .decode(FIXED_SIGNABLE_PSBT_V0)
            .expect("base64 fixture vector"),
    )
    .expect("valid PSBTv0 fixture vector");
    assert_eq!(
        bitcoin::consensus::serialize(&psbt.unsigned_tx).to_lower_hex_string(),
        CORE_TYPESCRIPT_UNSIGNED_TX_HEX
    );

    // This digest was produced independently from the exact bytes above by the TypeScript
    // PSBT document parser and node:crypto, so keep it literal rather than deriving it here.
    let commitments = format!(r#"{{"happy-path":"{CORE_TYPESCRIPT_UNSIGNED_TX_COMMITMENT}"}}"#);
    let response = spawned_signing_response(Some(&commitments));

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    assert_eq!(response_psbt(&response).inputs[0].partial_sigs.len(), 1);
}

#[test]
fn signs_p2wpkh_without_derivation_metadata() {
    let encoded = unsigned_profile_fixture("p2wpkh", 1);
    let response = sign_profile("p2wpkh", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = response_psbt(&response);
    assert_valid_ecdsa_signature(&signed, 0);
}

#[test]
fn signs_intent_rich_p2wpkh_with_its_matching_commitment() {
    let encoded = unsigned_profile_fixture("intent-rich-p2wpkh", 1);
    let response = sign_profile("intent-rich-p2wpkh", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    assert_valid_ecdsa_signature(&response_psbt(&response), 0);
}

#[test]
fn intent_rich_p2wpkh_requires_its_matching_run_scoped_commitment() {
    let encoded = unsigned_profile_fixture("intent-rich-p2wpkh", 1);
    let request_value = request(
        "sign",
        json!({
            "psbt": encoded,
            "network": "regtest",
            "fixtureId": "intent-rich-p2wpkh"
        }),
    );

    let missing = handle_value(request_value.clone(), "sha256:deadbeef");
    assert_eq!(missing["status"], "rejected", "{missing}");
    assert_eq!(
        missing["error"]["class"],
        "policy.fixture_commitment_missing"
    );

    let wrong = FixtureCommitments::from_json(Some(&format!(
        r#"{{"intent-rich-p2wpkh":"sha256:{}"}}"#,
        "00".repeat(32)
    )))
    .expect("valid mismatched intent-rich commitment config");
    let mismatched = handle_value_with_commitments(request_value, "sha256:deadbeef", &wrong);
    assert_eq!(mismatched["status"], "rejected", "{mismatched}");
    assert_eq!(
        mismatched["error"]["class"],
        "policy.fixture_commitment_mismatch"
    );
}

#[test]
fn intent_rich_p2wpkh_rejects_a_mismatched_funding_script() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("intent-rich-p2wpkh", 1));
    psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("witness UTXO")
        .script_pubkey =
        ScriptBuf::new_p2wpkh(&scalar_public_key(2).wpubkey_hash().expect("compressed key"));
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("intent-rich-p2wpkh", &encoded, None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
    assert!(response.get("output").is_none());
}

#[test]
fn contributes_scalar_one_to_the_exact_ordered_two_of_three_script() {
    let encoded = unsigned_profile_fixture("p2wsh-2-of-3", 1);
    let response = sign_profile("p2wsh-2-of-3", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = response_psbt(&response);
    assert_eq!(
        signed.inputs[0].witness_script,
        Some(multisig_witness_script())
    );
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    assert_valid_ecdsa_signature(&signed, 0);
}

#[test]
fn signs_exact_p2pkh_with_non_witness_utxo() {
    let encoded = unsigned_profile_fixture("p2pkh", 1);
    let response = sign_profile("p2pkh", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    let signed = response_psbt(&response);
    assert!(signed.inputs[0].witness_utxo.is_none());
    assert!(signed.inputs[0].non_witness_utxo.is_some());
    assert_valid_ecdsa_signature(&signed, 0);
}

#[test]
fn signs_exact_nested_p2sh_p2wsh_multisig_profile() {
    let encoded = unsigned_profile_fixture("p2sh-p2wsh-2-of-3", 1);
    let response = sign_profile("p2sh-p2wsh-2-of-3", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    let signed = response_psbt(&response);
    let witness_script = multisig_witness_script();
    assert_eq!(
        signed.inputs[0].redeem_script,
        Some(witness_script.to_p2wsh())
    );
    assert_eq!(signed.inputs[0].witness_script, Some(witness_script));
    assert_valid_ecdsa_signature(&signed, 0);
}

#[test]
fn signs_exact_p2tr_keypath_with_default_sighash() {
    let encoded = unsigned_profile_fixture("p2tr-keypath", 1);
    let response = sign_profile("p2tr-keypath", &encoded, None);

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = response_psbt(&response);
    assert_valid_taproot_signature(&signed, 0);
}

#[test]
fn signs_and_finalizes_exact_p2tr_scriptpath_while_preserving_bip371_fields() {
    let encoded = unsigned_profile_fixture("p2tr-scriptpath", 1);
    let original = decode_psbt(&encoded);
    let signed_response = sign_profile("p2tr-scriptpath", &encoded, None);

    assert_eq!(signed_response["status"], "ok", "{signed_response}");
    assert_eq!(signed_response["output"]["signedInputs"], 1);
    let signed = response_psbt(&signed_response);
    assert_eq!(signed.inputs[0].tap_scripts, original.inputs[0].tap_scripts);
    assert_eq!(
        signed.inputs[0].tap_internal_key,
        original.inputs[0].tap_internal_key
    );
    assert_eq!(
        signed.inputs[0].tap_key_origins,
        original.inputs[0].tap_key_origins
    );
    assert_valid_taproot_script_signature(&signed, 0);

    let signed_encoded = STANDARD.encode(signed.serialize());
    let finalized_response = handle_authorized(
        request(
            "finalize-inputs",
            json!({
                "psbt": signed_encoded,
                "network": "regtest",
                "fixtureId": "p2tr-scriptpath",
                "inputIndexes": [0]
            }),
        ),
        "p2tr-scriptpath",
        &signed_encoded,
    );
    assert_eq!(finalized_response["status"], "ok", "{finalized_response}");
    let finalized = response_psbt(&finalized_response);
    let witness = finalized.inputs[0]
        .final_script_witness
        .as_ref()
        .expect("final Taproot script-path witness")
        .iter()
        .collect::<Vec<_>>();
    let (_, leaf_script, control_block, _) = taproot_script_path();
    assert_eq!(witness.len(), 3);
    assert_eq!(witness[1], leaf_script.as_bytes());
    assert_eq!(witness[2], control_block.serialize());
    assert!(finalized.inputs[0].tap_script_sigs.is_empty());
    assert!(finalized.inputs[0].tap_scripts.is_empty());
}

#[test]
fn rejects_wrong_or_missing_p2tr_scriptpath_metadata() {
    let fixture = unsigned_profile_fixture("p2tr-scriptpath", 1);
    let original = decode_psbt(&fixture);

    let mut wrong_leaf = original.clone();
    let control_block = wrong_leaf.inputs[0]
        .tap_scripts
        .keys()
        .next()
        .expect("control block")
        .clone();
    wrong_leaf.inputs[0].tap_scripts.insert(
        control_block,
        (
            Builder::new()
                .push_x_only_key(&scalar_xonly(3))
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            LeafVersion::TapScript,
        ),
    );

    let mut wrong_control = original.clone();
    let (control_block, script) = wrong_control.inputs[0]
        .tap_scripts
        .pop_first()
        .expect("Taproot leaf");
    let mut altered_control = control_block;
    altered_control.internal_key = scalar_xonly(3);
    wrong_control.inputs[0]
        .tap_scripts
        .insert(altered_control, script);

    let mut dropped_metadata = original;
    dropped_metadata.inputs[0].tap_scripts.clear();

    let mut wrong_origin = decode_psbt(&fixture);
    let (leaf_hashes, _) = wrong_origin.inputs[0]
        .tap_key_origins
        .get_mut(&scalar_xonly(2))
        .expect("leaf key origin");
    leaf_hashes.clear();

    for psbt in [wrong_leaf, wrong_control, dropped_metadata, wrong_origin] {
        let encoded = STANDARD.encode(psbt.serialize());
        let response = sign_profile("p2tr-scriptpath", &encoded, None);
        assert_eq!(response["status"], "rejected", "{response}");
        assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
        assert!(response.get("output").is_none());
    }
}

#[test]
fn rejects_non_all_ecdsa_sighashes() {
    for fixture_id in ["p2wpkh", "intent-rich-p2wpkh", "p2wsh-2-of-3"] {
        let mut psbt = decode_psbt(&unsigned_profile_fixture(fixture_id, 1));
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::Single));
        let encoded = STANDARD.encode(psbt.serialize());
        let response = sign_profile(fixture_id, &encoded, None);

        assert_eq!(response["status"], "rejected", "{fixture_id}: {response}");
        assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
        assert!(response.get("output").is_none());
    }
}

#[test]
fn rejects_non_default_taproot_sighashes() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("p2tr-keypath", 1));
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::All));
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("p2tr-keypath", &encoded, None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
    assert!(response.get("output").is_none());
}

#[test]
fn signs_all_standard_ecdsa_sighashes_for_matrix_fixture() {
    let sighash_types = [
        EcdsaSighashType::All,
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ];
    for sighash_type in sighash_types {
        let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2wpkh", 2));
        for input in &mut psbt.inputs {
            input.sighash_type = Some(PsbtSighashType::from(sighash_type));
        }
        let encoded = STANDARD.encode(psbt.serialize());
        let response = sign_profile_with_sighash("sighash-p2wpkh", &encoded, sighash_type.to_u32());

        assert_eq!(response["status"], "ok", "{sighash_type}: {response}");
        let signed = response_psbt(&response);
        for input_index in 0..signed.inputs.len() {
            assert_valid_ecdsa_signature_with_type(&signed, input_index, sighash_type);
        }
    }
}

#[test]
fn ecdsa_sighash_commitments_match_permitted_mutations() {
    let sighash_types = [
        EcdsaSighashType::All,
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ];
    for sighash_type in sighash_types {
        let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2wpkh", 2));
        for input in &mut psbt.inputs {
            input.sighash_type = Some(PsbtSighashType::from(sighash_type));
        }
        let encoded = STANDARD.encode(psbt.serialize());
        let response = sign_profile_with_sighash_and_indexes(
            "sighash-p2wpkh",
            &encoded,
            sighash_type.to_u32(),
            Some(json!([0])),
        );
        assert_eq!(response["status"], "ok", "{sighash_type}: {response}");
        let signed = response_psbt(&response);

        let mut committed_input_mutation = signed.unsigned_tx.clone();
        let sequence = committed_input_mutation.input[0]
            .sequence
            .to_consensus_u32();
        committed_input_mutation.input[0].sequence = Sequence::from_consensus(sequence ^ 1);
        assert!(
            !p2wpkh_signature_is_valid_for_transaction(
                &signed,
                &committed_input_mutation,
                0,
                sighash_type
            ),
            "{sighash_type} accepted a mutation to the signed input"
        );

        if matches!(
            sighash_type,
            EcdsaSighashType::None | EcdsaSighashType::NonePlusAnyoneCanPay
        ) {
            let mut permitted_output_mutation = signed.unsigned_tx.clone();
            let value = permitted_output_mutation.output[0].value.to_sat();
            permitted_output_mutation.output[0].value = Amount::from_sat(value + 1);
            assert!(
                p2wpkh_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_output_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed an output despite SIGHASH_NONE"
            );
        }

        if matches!(
            sighash_type,
            EcdsaSighashType::Single | EcdsaSighashType::SinglePlusAnyoneCanPay
        ) {
            let mut permitted_output_mutation = signed.unsigned_tx.clone();
            let value = permitted_output_mutation.output[1].value.to_sat();
            permitted_output_mutation.output[1].value = Amount::from_sat(value + 1);
            assert!(
                p2wpkh_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_output_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed an output other than the matching SINGLE output"
            );
        }

        if matches!(
            sighash_type,
            EcdsaSighashType::AllPlusAnyoneCanPay
                | EcdsaSighashType::NonePlusAnyoneCanPay
                | EcdsaSighashType::SinglePlusAnyoneCanPay
        ) {
            let mut permitted_input_mutation = signed.unsigned_tx.clone();
            let sequence = permitted_input_mutation.input[1]
                .sequence
                .to_consensus_u32();
            permitted_input_mutation.input[1].sequence = Sequence::from_consensus(sequence ^ 1);
            assert!(
                p2wpkh_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_input_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed another input despite ANYONECANPAY"
            );
        }
    }
}

#[test]
fn signs_all_standard_taproot_sighashes_for_matrix_fixture() {
    let sighash_types = [
        TapSighashType::Default,
        TapSighashType::All,
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ];
    for sighash_type in sighash_types {
        let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2tr-keypath", 2));
        if sighash_type != TapSighashType::Default {
            for input in &mut psbt.inputs {
                input.sighash_type = Some(PsbtSighashType::from(sighash_type));
            }
        }
        let encoded = STANDARD.encode(psbt.serialize());
        let response =
            sign_profile_with_sighash("sighash-p2tr-keypath", &encoded, sighash_type as u32);

        assert_eq!(response["status"], "ok", "{sighash_type}: {response}");
        let signed = response_psbt(&response);
        for input_index in 0..signed.inputs.len() {
            assert_valid_taproot_signature_with_type(&signed, input_index, sighash_type);
        }
    }
}

#[test]
fn taproot_sighash_commitments_match_permitted_mutations() {
    let sighash_types = [
        TapSighashType::Default,
        TapSighashType::All,
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ];
    for sighash_type in sighash_types {
        let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2tr-keypath", 2));
        if sighash_type != TapSighashType::Default {
            for input in &mut psbt.inputs {
                input.sighash_type = Some(PsbtSighashType::from(sighash_type));
            }
        }
        let encoded = STANDARD.encode(psbt.serialize());
        let response = sign_profile_with_sighash_and_indexes(
            "sighash-p2tr-keypath",
            &encoded,
            sighash_type as u32,
            Some(json!([0])),
        );
        assert_eq!(response["status"], "ok", "{sighash_type}: {response}");
        let signed = response_psbt(&response);

        let mut committed_input_mutation = signed.unsigned_tx.clone();
        let sequence = committed_input_mutation.input[0]
            .sequence
            .to_consensus_u32();
        committed_input_mutation.input[0].sequence = Sequence::from_consensus(sequence ^ 1);
        assert!(
            !taproot_signature_is_valid_for_transaction(
                &signed,
                &committed_input_mutation,
                0,
                sighash_type
            ),
            "{sighash_type} accepted a mutation to the signed input"
        );

        if matches!(
            sighash_type,
            TapSighashType::None | TapSighashType::NonePlusAnyoneCanPay
        ) {
            let mut permitted_output_mutation = signed.unsigned_tx.clone();
            let value = permitted_output_mutation.output[0].value.to_sat();
            permitted_output_mutation.output[0].value = Amount::from_sat(value + 1);
            assert!(
                taproot_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_output_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed an output despite SIGHASH_NONE"
            );
        }

        if matches!(
            sighash_type,
            TapSighashType::Single | TapSighashType::SinglePlusAnyoneCanPay
        ) {
            let mut permitted_output_mutation = signed.unsigned_tx.clone();
            let value = permitted_output_mutation.output[1].value.to_sat();
            permitted_output_mutation.output[1].value = Amount::from_sat(value + 1);
            assert!(
                taproot_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_output_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed an output other than the matching SINGLE output"
            );
        }

        if matches!(
            sighash_type,
            TapSighashType::AllPlusAnyoneCanPay
                | TapSighashType::NonePlusAnyoneCanPay
                | TapSighashType::SinglePlusAnyoneCanPay
        ) {
            let mut permitted_input_mutation = signed.unsigned_tx.clone();
            let sequence = permitted_input_mutation.input[1]
                .sequence
                .to_consensus_u32();
            permitted_input_mutation.input[1].sequence = Sequence::from_consensus(sequence ^ 1);
            assert!(
                taproot_signature_is_valid_for_transaction(
                    &signed,
                    &permitted_input_mutation,
                    0,
                    sighash_type
                ),
                "{sighash_type} committed another input despite ANYONECANPAY"
            );
        }
    }
}

#[test]
fn rejects_invalid_taproot_default_anyonecanpay() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2tr-keypath", 2));
    for input in &mut psbt.inputs {
        input.sighash_type = Some(PsbtSighashType::from_u32(0x80));
    }
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile_with_sighash("sighash-p2tr-keypath", &encoded, 0x80);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn rejects_invalid_ecdsa_sighash_for_matrix_fixture() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("sighash-p2wpkh", 2));
    for input in &mut psbt.inputs {
        input.sighash_type = Some(PsbtSighashType::from_u32(0x04));
    }
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile_with_sighash("sighash-p2wpkh", &encoded, 0x04);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn rejects_unexpected_bip32_derivation() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("p2wpkh", 1));
    psbt.inputs[0].bip32_derivation.insert(
        scalar_public_key(2).inner,
        (
            Fingerprint::from([0xde, 0xad, 0xbe, 0xef]),
            DerivationPath::default(),
        ),
    );
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("p2wpkh", &encoded, None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn rejects_taproot_merkle_or_script_path_metadata() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("p2tr-keypath", 1));
    psbt.inputs[0].tap_merkle_root = Some(bitcoin::TapNodeHash::from_byte_array([1; 32]));
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("p2tr-keypath", &encoded, None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
    assert!(response.get("output").is_none());
}

#[test]
fn rejects_taproot_with_a_non_fixture_funding_script() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("p2tr-keypath", 1));
    psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("witness UTXO")
        .script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::new(), scalar_xonly(2), None);
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("p2tr-keypath", &encoded, None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
    assert!(response.get("output").is_none());
}

#[test]
fn taproot_requires_all_prevouts_even_when_signing_one_selected_input() {
    let mut psbt = decode_psbt(&unsigned_profile_fixture("p2tr-keypath", 2));
    psbt.inputs[1].witness_utxo = None;
    let encoded = STANDARD.encode(psbt.serialize());
    let response = sign_profile("p2tr-keypath", &encoded, Some(json!([0])));

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
    assert!(response.get("output").is_none());
}

#[test]
fn spawned_adapter_rejects_signing_without_startup_fixture_commitments() {
    let response = spawned_signing_response(None);

    assert_eq!(response["status"], "rejected", "{response}");
    assert_eq!(
        response["error"]["class"],
        "policy.fixture_commitment_missing"
    );
}

#[test]
fn spawned_adapter_reports_malformed_startup_fixture_commitments() {
    let response = spawned_signing_response(Some("{not-json}"));

    assert_eq!(response["status"], "crashed", "{response}");
    assert_eq!(response["error"]["class"], "adapter.invalid_configuration");
}

#[test]
fn validates_bounded_fixture_commitment_configuration() {
    assert!(FixtureCommitments::from_json(None).is_ok());
    assert!(FixtureCommitments::from_json(Some("[]")).is_err());
    assert!(
        FixtureCommitments::from_json(Some(&format!(
            r#"{{"unknown":"sha256:{}"}}"#,
            "00".repeat(32)
        )))
        .is_err()
    );
    assert!(
        FixtureCommitments::from_json(Some(&format!(
            r#"{{"happy-path":"sha256:{}"}}"#,
            "AA".repeat(32)
        )))
        .is_err()
    );
    assert!(FixtureCommitments::from_json(Some(&"x".repeat(4 * 1024 + 1))).is_err());
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
fn sign_only_signs_requested_inputs() {
    let encoded = unsigned_two_input_fixture();
    let original = Psbt::deserialize(&STANDARD.decode(&encoded).expect("base64 PSBT"))
        .expect("valid fixture PSBT");
    let response = handle_authorized(
        request(
            "sign",
            json!({
                "psbt": encoded.clone(),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression",
                "inputIndexes": [1]
            }),
        ),
        "bdk-finalize-regression",
        &encoded,
    );

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 1);
    let signed = response_psbt(&response);
    assert_eq!(signed.inputs[0], original.inputs[0]);
    assert_eq!(signed.inputs[1].partial_sigs.len(), 1);
}

#[test]
fn sign_without_input_indexes_signs_all_inputs() {
    let encoded = unsigned_two_input_fixture();
    let response = handle_authorized(
        request(
            "sign",
            json!({
                "psbt": encoded.clone(),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression"
            }),
        ),
        "bdk-finalize-regression",
        &encoded,
    );

    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["signedInputs"], 2);
    let signed = response_psbt(&response);
    assert!(
        signed
            .inputs
            .iter()
            .all(|input| input.partial_sigs.len() == 1)
    );
}

#[test]
fn rejects_invalid_sign_input_indexes() {
    let encoded = unsigned_two_input_fixture();
    for input_indexes in [
        json!(null),
        json!([]),
        json!([0, 0]),
        json!([-1]),
        json!([0.5]),
        json!([9_007_199_254_740_992_u64]),
        json!(["0"]),
        json!([2]),
    ] {
        let response = handle_authorized(
            request(
                "sign",
                json!({
                    "psbt": encoded.clone(),
                    "network": "regtest",
                    "fixtureId": "bdk-finalize-regression",
                    "inputIndexes": input_indexes
                }),
            ),
            "bdk-finalize-regression",
            &encoded,
        );

        assert_eq!(response["status"], "rejected", "{response}");
        assert_eq!(
            response["error"]["class"], "protocol.invalid_payload",
            "{response}"
        );
    }
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
fn malformed_json_response_uses_current_protocol() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_psbt-lab-rust-adapter"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("adapter executable starts");
    let mut stdin = child.stdin.take().expect("adapter stdin");
    stdin.write_all(b"{not-json}\n").expect("write request");
    drop(stdin);

    let output = child.wait_with_output().expect("adapter exits");
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON response");

    assert_eq!(response["protocol"], "psbt-lab.adapter/0.2");
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "protocol.invalid_json");
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
    let signed_psbt = signed_two_input_fixture();
    let response = handle_authorized(
        request(
            "finalize-inputs",
            json!({
                "psbt": signed_psbt.clone(),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression",
                "inputIndexes": [1]
            }),
        ),
        "bdk-finalize-regression",
        &signed_psbt,
    );
    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["finalizedInputs"], json!([1]));
    let finalized = response_psbt(&response);

    assert!(finalized.inputs[0].final_script_witness.is_none());
    assert!(!finalized.inputs[0].partial_sigs.is_empty());
    assert!(finalized.inputs[1].final_script_witness.is_some());
    assert!(finalized.inputs[1].partial_sigs.is_empty());
}

#[test]
fn finalize_inputs_finalizes_every_requested_input() {
    let signed_psbt = signed_two_input_fixture();
    let response = handle_authorized(
        request(
            "finalize-inputs",
            json!({
                "psbt": signed_psbt.clone(),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression",
                "inputIndexes": [0, 1]
            }),
        ),
        "bdk-finalize-regression",
        &signed_psbt,
    );
    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(response["output"]["finalizedInputs"], json!([0, 1]));
    assert_eq!(response["output"]["remainingPartialInputs"], 0);
    let finalized = response_psbt(&response);

    assert!(
        finalized
            .inputs
            .iter()
            .all(|input| input.final_script_witness.is_some() && input.partial_sigs.is_empty())
    );
}

#[test]
fn finalize_inputs_rejects_non_regression_fixture() {
    let response = handle_value(
        request(
            "finalize-inputs",
            json!({
                "psbt": signed_two_input_fixture(),
                "network": "regtest",
                "fixtureId": "happy-path",
                "inputIndexes": [0]
            }),
        ),
        "sha256:deadbeef",
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.fixture_not_allowed");
}

fn signed_two_input_fixture() -> String {
    let encoded = unsigned_two_input_fixture();
    let signed = handle_authorized(
        request(
            "sign",
            json!({
                "psbt": encoded.clone(),
                "network": "regtest",
                "fixtureId": "bdk-finalize-regression"
            }),
        ),
        "bdk-finalize-regression",
        &encoded,
    );
    assert_eq!(signed["status"], "ok");
    signed["output"]["psbt"]
        .as_str()
        .expect("signed PSBT")
        .to_owned()
}

fn unsigned_two_input_fixture() -> String {
    let key = PrivateKey::from_wif(FIXTURE_WIF).expect("fixture key");
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
    STANDARD.encode(psbt.serialize())
}

fn response_psbt(response: &Value) -> Psbt {
    let encoded = response["output"]["psbt"].as_str().expect("encoded PSBT");
    Psbt::deserialize(&STANDARD.decode(encoded).expect("base64 PSBT")).expect("valid PSBT")
}

#[test]
fn refuses_a_non_witness_utxo_with_the_wrong_txid() {
    let key = PrivateKey::from_wif(FIXTURE_WIF).expect("fixture key");
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

    let encoded = STANDARD.encode(psbt.serialize());
    let response = handle_authorized(
        request(
            "sign",
            json!({
                "psbt": encoded.clone(),
                "network": "regtest",
                "fixtureId": "happy-path"
            }),
        ),
        "happy-path",
        &encoded,
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}

#[test]
fn refuses_a_non_witness_utxo_with_an_out_of_range_vout() {
    let key = PrivateKey::from_wif(FIXTURE_WIF).expect("fixture key");
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

    let encoded = STANDARD.encode(psbt.serialize());
    let response = handle_authorized(
        request(
            "sign",
            json!({
                "psbt": encoded.clone(),
                "network": "regtest",
                "fixtureId": "happy-path"
            }),
        ),
        "happy-path",
        &encoded,
    );

    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"]["class"], "policy.psbt_not_authorized");
}
