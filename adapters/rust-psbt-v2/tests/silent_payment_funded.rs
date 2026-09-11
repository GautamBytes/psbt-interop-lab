use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PrivateKey, ScriptBuf, TxOut, consensus,
};
use psbt_v2::v2::{Constructor, InputBuilder, Modifiable, Output, Psbt, Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
fn fixture() -> Psbt {
    let key = PrivateKey::from_wif("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")
        .unwrap()
        .public_key(&Secp256k1::new());
    let script = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
    Constructor::<Modifiable>::default()
        .input(
            InputBuilder::new(&OutPoint::from_str(&format!("{}:0", "37".repeat(32))).unwrap())
                .segwit_fund(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: script.clone(),
                })
                .build(),
        )
        .output(Output::new(TxOut {
            value: Amount::from_sat(89_000),
            script_pubkey: script,
        }))
        .psbt()
        .unwrap()
}
fn commitments(psbt: &Psbt) -> FixtureCommitments {
    let tx = Signer::new(psbt.clone()).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(
        &json!({"p2wpkh": format!("sha256:{:x}", Sha256::digest(consensus::serialize(&tx)))})
            .to_string(),
    ))
    .unwrap()
}
fn request(psbt: &Psbt) -> Value {
    json!({"protocol": ADAPTER_PROTOCOL, "id": "funded-sender", "operation": "silent-payment-send", "payload": {"network": "regtest", "fixtureId": "p2wpkh", "psbt": STANDARD.encode(psbt.serialize())}})
}
#[test]
fn signs_finalizes_and_preserves_funded_input_and_amount() {
    let psbt = fixture();
    let response = handle_value_with_commitments(request(&psbt), DIGEST, &commitments(&psbt));
    assert_eq!(response["status"], "ok", "{response:#}");
    let signed = Psbt::from_str(response["output"]["psbt"].as_str().unwrap()).unwrap();
    let finalized = Psbt::from_str(response["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
    assert_eq!(signed.inputs[0].previous_txid, psbt.inputs[0].previous_txid);
    assert_eq!(signed.outputs[0].amount, psbt.outputs[0].amount);
    assert!(signed.outputs[0].script_pubkey.is_p2tr());
    assert_eq!(signed.inputs[0].sp_ecdh_shares.len(), 1);
    assert_eq!(signed.inputs[0].sp_dleq_proofs.len(), 1);
    assert_eq!(
        finalized.inputs[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .len(),
        2
    );
    assert!(finalized.inputs[0].partial_sigs.is_empty());
    assert_eq!(response["output"]["signedInputs"], 1);
}
#[test]
fn refuses_missing_commitment_changed_input_and_mainnet() {
    let psbt = fixture();
    let bound = commitments(&psbt);
    let missing =
        handle_value_with_commitments(request(&psbt), DIGEST, &FixtureCommitments::default());
    assert_eq!(
        missing["error"]["class"],
        "policy.fixture_commitment_missing"
    );
    let mut changed = psbt.clone();
    changed.inputs[0].spent_output_index += 1;
    let response = handle_value_with_commitments(request(&changed), DIGEST, &bound);
    assert_eq!(
        response["error"]["class"],
        "policy.fixture_commitment_mismatch"
    );
    let mut mainnet = request(&psbt);
    mainnet["payload"]["network"] = json!("mainnet");
    assert_eq!(
        handle_value_with_commitments(mainnet, DIGEST, &bound)["error"]["class"],
        "policy.network_not_allowed"
    );
}
#[test]
fn refuses_supplied_recipient_proof_and_forged_funding() {
    let psbt = fixture();
    let bound = commitments(&psbt);
    let mut recipient = psbt.clone();
    recipient.outputs[0].sp_v0_info = Some(
        [CompressedPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap()
        .to_bytes(); 2]
            .concat(),
    );
    let mut proof = psbt.clone();
    let scan = CompressedPublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    )
    .unwrap();
    proof.inputs[0].sp_ecdh_shares.insert(scan, scan);
    proof.inputs[0]
        .sp_dleq_proofs
        .insert(scan, [0_u8; 64].into());
    let mut funding = psbt.clone();
    funding.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(100_001);
    for changed in [recipient, proof, funding] {
        let response = handle_value_with_commitments(request(&changed), DIGEST, &bound);
        assert_eq!(response["status"], "rejected", "{response:#}");
        assert_eq!(
            response["error"]["class"],
            "silent_payment.funded_template_invalid"
        );
    }
}
