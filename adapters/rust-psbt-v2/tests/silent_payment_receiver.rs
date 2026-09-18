use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::{
    bitcoin::{Amount, ScriptBuf, consensus},
    raw,
    v2::{Psbt, Signer},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/receiver.json")).unwrap()
}
fn commitments(f: &Value) -> FixtureCommitments {
    let psbt = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
    let tx = Signer::new(psbt).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(
        &json!({"bip375-multi":format!("sha256:{:x}",Sha256::digest(consensus::serialize(&tx)))})
            .to_string(),
    ))
    .unwrap()
}
fn request(f: &Value) -> Value {
    json!({"protocol":ADAPTER_PROTOCOL,"id":"receiver","operation":"silent-payment-spend","payload":{"fixtureId":"bip375-multi","network":"regtest","psbt":f["child"],"parentPsbt":f["parent"],"templatePsbt":f["template"]}})
}
#[test]
fn spends_the_discovered_parent_output_and_cleans_receiver_fields() {
    let f = fixture();
    let result = handle_value_with_commitments(request(&f), DIGEST, &commitments(&f));
    assert_eq!(result["status"], "ok", "{result:#}");
    let signed = Psbt::from_str(result["output"]["psbt"].as_str().unwrap()).unwrap();
    let finalized = Psbt::from_str(result["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
    let child = Psbt::from_str(f["child"].as_str().unwrap()).unwrap();
    assert_eq!(
        signed.inputs[0].previous_txid,
        child.inputs[0].previous_txid
    );
    assert_eq!(signed.outputs, child.outputs);
    assert!(signed.inputs[0].tap_key_sig.is_some());
    assert!(finalized.inputs[0].final_script_witness.is_some());
    assert!(
        finalized.inputs[0]
            .unknowns
            .keys()
            .all(|k| k.type_value != 0x1f && k.type_value != 0x20)
    );
    assert_eq!(result["output"]["signedInputs"], 1);
}
#[test]
fn refuses_wrong_tweak_unrelated_outpoint_forged_utxo_and_changed_destination() {
    let f = fixture();
    let bound = commitments(&f);
    let child = Psbt::from_str(f["child"].as_str().unwrap()).unwrap();
    let mut variants = Vec::new();
    let mut p = child.clone();
    p.inputs[0].unknowns.insert(
        raw::Key {
            type_value: 0x20,
            key: vec![],
        },
        vec![3; 32],
    );
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].spent_output_index = 1;
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(94_001);
    variants.push(p);
    let mut p = child.clone();
    p.outputs[0].script_pubkey = ScriptBuf::new();
    variants.push(p);
    let mut p = child.clone();
    p.outputs[0].amount = Amount::from_sat(84_001);
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].sighash_type = Some(psbt_v2::bitcoin::sighash::TapSighashType::None.into());
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].sequence = Some(psbt_v2::bitcoin::Sequence::MAX);
    variants.push(p);
    let mut p = child.clone();
    p.global.tx_modifiable_flags = 1;
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].final_script_witness = Some(psbt_v2::bitcoin::Witness::new());
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].previous_txid = psbt_v2::bitcoin::Txid::from_str(&"ab".repeat(32)).unwrap();
    variants.push(p);
    let mut p = child.clone();
    p.inputs[0].unknowns.retain(|key, _| key.type_value != 0x1f);
    variants.push(p);
    for p in variants {
        let mut f = f.clone();
        f["child"] = json!(STANDARD.encode(p.serialize()));
        let result = handle_value_with_commitments(request(&f), DIGEST, &bound);
        assert_eq!(result["status"], "rejected", "{result:#}");
        assert!(result.get("output").is_none());
    }
}
#[test]
fn refuses_missing_commitment_changed_template_parent_and_mainnet() {
    let f = fixture();
    let bound = commitments(&f);
    assert_eq!(
        handle_value_with_commitments(request(&f), DIGEST, &FixtureCommitments::default())["error"]
            ["class"],
        "policy.fixture_commitment_missing"
    );
    let mut req = request(&f);
    req["payload"]["network"] = json!("mainnet");
    assert_eq!(
        handle_value_with_commitments(req, DIGEST, &bound)["error"]["class"],
        "policy.network_not_allowed"
    );
    for name in ["template", "parent"] {
        let mut changed = f.clone();
        let mut p = Psbt::from_str(f[name].as_str().unwrap()).unwrap();
        p.outputs[0].amount = Amount::from_sat(95_000);
        changed[name] = json!(STANDARD.encode(p.serialize()));
        assert_eq!(
            handle_value_with_commitments(request(&changed), DIGEST, &bound)["status"],
            "rejected"
        );
    }
}

#[test]
fn rejects_unfinalized_or_corrupted_parent_without_panicking() {
    let f = fixture();
    let bound = commitments(&f);
    let parent = Psbt::from_str(f["parent"].as_str().unwrap()).unwrap();
    for i in 0..2 {
        let mut p = parent.clone();
        p.inputs[i].final_script_witness = None;
        let mut changed = f.clone();
        changed["parent"] = json!(STANDARD.encode(p.serialize()));
        assert_eq!(
            handle_value_with_commitments(request(&changed), DIGEST, &bound)["status"],
            "rejected"
        );
    }
}

#[test]
fn rejects_corrupt_parent_witness_and_stale_receiver_signature() {
    let f = fixture();
    let bound = commitments(&f);
    let mut parent = Psbt::from_str(f["parent"].as_str().unwrap()).unwrap();
    let mut witness: Vec<Vec<u8>> = parent.inputs[0]
        .final_script_witness
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| v.to_vec())
        .collect();
    witness[0][10] ^= 1;
    parent.inputs[0].final_script_witness = Some(psbt_v2::bitcoin::Witness::from_slice(&witness));
    let mut changed = f.clone();
    changed["parent"] = json!(STANDARD.encode(parent.serialize()));
    assert_eq!(
        handle_value_with_commitments(request(&changed), DIGEST, &bound)["status"],
        "rejected"
    );
    let signed = handle_value_with_commitments(request(&f), DIGEST, &bound);
    let mut changed = f.clone();
    changed["child"] = signed["output"]["psbt"].clone();
    assert_eq!(
        handle_value_with_commitments(request(&changed), DIGEST, &bound)["status"],
        "rejected"
    );
}
