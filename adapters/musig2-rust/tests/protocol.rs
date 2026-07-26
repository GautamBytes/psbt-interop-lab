use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::absolute;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, raw::Key as RawKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use psbt_lab_musig2_adapter::{
    ADAPTER_PROTOCOL, AGGREGATE_PUBLIC_KEY, FIXTURE_ID, FixtureCommitments, Musig2Adapter,
    PARTICIPANT_PUBLIC_KEYS, SignerIdentity,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture() -> (String, FixtureCommitments) {
    let aggregate = hex_bytes(AGGREGATE_PUBLIC_KEY);
    let script = ScriptBuf::from_bytes([vec![0x51, 0x20], aggregate[1..].to_vec()].concat());
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::all_zeros(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    };
    let commitment = Sha256::digest(bitcoin::consensus::serialize(&transaction));
    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: script,
    });
    psbt.inputs[0].unknown.insert(
        RawKey {
            type_value: 0x1a,
            key: aggregate,
        },
        PARTICIPANT_PUBLIC_KEYS
            .iter()
            .flat_map(|key| hex_bytes(key))
            .collect(),
    );
    let commitments = FixtureCommitments::from_json(Some(
        &json!({ FIXTURE_ID: format!("sha256:{commitment:x}") }).to_string(),
    ))
    .unwrap();
    (STANDARD.encode(psbt.serialize()), commitments)
}

fn request(operation: &str, psbt: &str, session: Option<&str>) -> Value {
    let mut payload = json!({
        "fixtureId": FIXTURE_ID,
        "psbt": psbt
    });
    if let Some(session) = session {
        payload["sessionId"] = Value::String(session.to_owned());
    }
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": format!("{operation}-1"),
        "operation": operation,
        "payload": payload
    })
}

fn output_psbt(response: &Value) -> String {
    assert_eq!(response["status"], "ok", "{response}");
    response["output"]["psbt"].as_str().unwrap().to_owned()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn completes_two_round_musig2_and_rejects_nonce_reuse() {
    let (psbt, commitments) = fixture();
    let mut signer_one = Musig2Adapter::new(SignerIdentity::One, commitments.clone());
    let mut signer_two = Musig2Adapter::new(SignerIdentity::Two, commitments);

    let psbt = output_psbt(
        &signer_one.handle_value(request("musig2-nonce", &psbt, Some("session-a")), DIGEST),
    );
    let reused = signer_one.handle_value(request("musig2-nonce", &psbt, Some("session-a")), DIGEST);
    assert_eq!(reused["status"], "rejected");
    assert_eq!(reused["error"]["class"], "musig2.nonce_reuse");

    let psbt = output_psbt(
        &signer_two.handle_value(request("musig2-nonce", &psbt, Some("session-a")), DIGEST),
    );
    let psbt = output_psbt(&signer_one.handle_value(
        request("musig2-partial-sign", &psbt, Some("session-a")),
        DIGEST,
    ));
    let psbt = output_psbt(&signer_two.handle_value(
        request("musig2-partial-sign", &psbt, Some("session-a")),
        DIGEST,
    ));
    let psbt =
        output_psbt(&signer_one.handle_value(request("musig2-aggregate", &psbt, None), DIGEST));

    let decoded = Psbt::deserialize(&STANDARD.decode(psbt).unwrap()).unwrap();
    assert!(decoded.inputs[0].tap_key_sig.is_some());
    assert_eq!(
        decoded.inputs[0]
            .unknown
            .keys()
            .filter(|key| key.type_value == 0x1b)
            .count(),
        2
    );
    assert_eq!(
        decoded.inputs[0]
            .unknown
            .keys()
            .filter(|key| key.type_value == 0x1c)
            .count(),
        2
    );
}

#[test]
fn fresh_process_state_uses_fresh_nonce_entropy() {
    let (psbt, commitments) = fixture();
    let mut first = Musig2Adapter::new(SignerIdentity::One, commitments.clone());
    let mut restarted = Musig2Adapter::new(SignerIdentity::One, commitments);

    let first_response =
        first.handle_value(request("musig2-nonce", &psbt, Some("same-session")), DIGEST);
    let restarted_response =
        restarted.handle_value(request("musig2-nonce", &psbt, Some("same-session")), DIGEST);

    assert_eq!(first_response["status"], "ok");
    assert_eq!(restarted_response["status"], "ok");
    assert_ne!(
        first_response["output"]["publicNonce"],
        restarted_response["output"]["publicNonce"]
    );
}

#[test]
fn hello_is_identity_specific_and_capability_scoped() {
    let mut adapter = Musig2Adapter::new(SignerIdentity::Two, FixtureCommitments::default());
    let response = adapter.handle_value(
        json!({
            "protocol": ADAPTER_PROTOCOL,
            "id": "hello-1",
            "operation": "hello",
            "payload": {}
        }),
        DIGEST,
    );

    assert_eq!(response["status"], "ok");
    assert_eq!(response["implementation"]["name"], "musig2-rust-signer-2");
    assert_eq!(
        response["output"]["operations"],
        json!([
            "hello",
            "native-parse",
            "roundtrip",
            "musig2-nonce",
            "musig2-partial-sign",
            "musig2-aggregate"
        ])
    );
}

#[test]
fn process_requires_an_explicit_valid_signer_identity() {
    let binary = env!("CARGO_BIN_EXE_psbt-lab-musig2-adapter");
    for selector in [None, Some("3")] {
        let mut command = Command::new(binary);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("PSBT_LAB_MUSIG2_SIGNER");
        if let Some(value) = selector {
            command.env("PSBT_LAB_MUSIG2_SIGNER", value);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("PSBT_LAB_MUSIG2_SIGNER must be 1 or 2")
        );
    }
}

#[test]
fn malformed_json_uses_the_selected_signer_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_psbt-lab-musig2-adapter"))
        .env("PSBT_LAB_MUSIG2_SIGNER", "2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(b"not-json\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["implementation"]["name"], "musig2-rust-signer-2");
    assert_eq!(response["error"]["class"], "protocol.invalid_json");
}
