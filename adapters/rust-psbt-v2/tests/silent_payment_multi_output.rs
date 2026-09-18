use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::{
    bitcoin::{Amount, ScriptBuf, consensus},
    v2::{Output, Psbt, Signer},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
fn fixture() -> Psbt {
    let f: Value = serde_json::from_str(include_str!("fixtures/receiver.json")).unwrap();
    let mut p = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
    p.outputs[0].amount = Amount::from_sat(60_000);
    p.outputs[1].amount = Amount::from_sat(60_000);
    p.outputs.insert(
        1,
        Output::new(psbt_v2::bitcoin::TxOut {
            value: Amount::from_sat(68_000),
            script_pubkey: ScriptBuf::from_hex(
                "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
            )
            .unwrap(),
        }),
    );
    p.global.output_count = 3;
    p
}
fn commitments(p: &Psbt) -> FixtureCommitments {
    let tx = Signer::new(p.clone()).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(&json!({"bip352-multi-output":format!("sha256:{:x}",Sha256::digest(consensus::serialize(&tx)))}).to_string())).unwrap()
}
fn send(p: &Psbt, shuffle: bool) -> Value {
    handle_value_with_commitments(
        json!({"protocol":ADAPTER_PROTOCOL,"id":"two-output","operation":"silent-payment-send","payload":{"psbt":STANDARD.encode(p.serialize()),"fixtureId":"bip352-multi-output","network":"regtest","shareMode":"per-input","reverseInputs":false,"shuffleOutputs":shuffle}}),
        DIGEST,
        &commitments(p),
    )
}
#[test]
fn derives_two_distinct_outputs_before_signing_both_layouts() {
    let p = fixture();
    let mut recipient_scripts = Vec::new();
    for shuffle in [false, true] {
        let result = send(&p, shuffle);
        assert_eq!(result["status"], "ok", "{result:#}");
        assert_eq!(result["output"]["silentPaymentOutputs"], 2);
        assert_eq!(
            result["output"]["outputScripts"].as_array().unwrap().len(),
            2
        );
        assert!(result["output"].get("outputScript").is_none());
        let signed = Psbt::from_str(result["output"]["psbt"].as_str().unwrap()).unwrap();
        let change = if shuffle { 0 } else { 2 };
        assert_eq!(signed.outputs[change], p.outputs[2]);
        let recipients: Vec<_> = signed
            .outputs
            .iter()
            .filter(|o| o.sp_v0_info.is_some())
            .collect();
        assert_eq!(recipients.len(), 2);
        assert_ne!(recipients[0].script_pubkey, recipients[1].script_pubkey);
        recipient_scripts.push(
            recipients
                .iter()
                .map(|o| o.script_pubkey.clone())
                .collect::<Vec<_>>(),
        );
        assert!(signed.inputs.iter().all(|i| i.partial_sigs.len() == 1));
    }
    assert_eq!(recipient_scripts[0], recipient_scripts[1]);
}
fn receive(f: &Value, v: &Value, child: &Psbt, spdk: bool) -> Value {
    let template = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
    let mut payload = json!({"psbt":STANDARD.encode(child.serialize()),"parentPsbt":v["output"]["finalizedPsbt"],"templatePsbt":f["template"],"fixtureId":"bip352-multi-output","network":"regtest"});
    if spdk {
        payload["receiver"] = json!("spdk");
    }
    handle_value_with_commitments(
        json!({"protocol":ADAPTER_PROTOCOL,"id":"receive-two","operation":"silent-payment-spend","payload":payload}),
        DIGEST,
        &commitments(&template),
    )
}
#[test]
fn spends_both_discovered_outputs_in_both_layouts() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-output.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        let child = Psbt::from_str(v["child"].as_str().unwrap()).unwrap();
        let result = receive(&f, v, &child, false);
        assert_eq!(result["status"], "ok", "{result:#}");
        assert_eq!(result["output"]["signedInputs"], 2);
        assert_eq!(
            result["output"]["derivedOutputKeys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(result["output"].get("derivedOutputKey").is_none());
        let signed = Psbt::from_str(result["output"]["psbt"].as_str().unwrap()).unwrap();
        assert_eq!(signed.outputs, child.outputs);
        assert!(signed.inputs.iter().all(|i| i.tap_key_sig.is_some()));
        let finalized =
            Psbt::from_str(result["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
        assert!(
            finalized
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some() && i.unknowns.is_empty())
        );
    }
}
#[test]
fn rejects_swapped_tweaks_duplicate_inputs_wrong_outpoint_and_changed_value() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-output.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        let child = Psbt::from_str(v["child"].as_str().unwrap()).unwrap();
        let mut cases = Vec::new();
        let mut p = child.clone();
        let tweak = psbt_v2::raw::Key {
            type_value: 0x20,
            key: vec![],
        };
        let first = p.inputs[0].unknowns[&tweak].clone();
        let second = p.inputs[1].unknowns[&tweak].clone();
        p.inputs[0].unknowns.insert(tweak.clone(), second);
        p.inputs[1].unknowns.insert(tweak, first);
        cases.push(p);
        let mut p = child.clone();
        p.inputs[1] = p.inputs[0].clone();
        cases.push(p);
        let mut p = child.clone();
        p.inputs[1].spent_output_index = if v["shuffle"] == json!(true) { 0 } else { 2 };
        cases.push(p);
        let mut p = child.clone();
        p.outputs[0].amount = Amount::from_sat(118_001);
        cases.push(p);
        let mut p = child.clone();
        p.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(67_999);
        cases.push(p);
        for p in cases {
            for spdk in [false, true] {
                let result = receive(&f, v, &p, spdk);
                assert_eq!(result["status"], "rejected", "{result:#}");
                assert!(result.get("output").is_none());
            }
        }
    }
}

#[test]
fn rejects_unauthorized_network_commitment_and_shuffle_payloads() {
    let p = fixture();
    let payload = json!({"psbt":STANDARD.encode(p.serialize()),"fixtureId":"bip352-multi-output","network":"regtest","shareMode":"per-input","reverseInputs":false,"shuffleOutputs":false});
    let mut missing_shuffle = payload.clone();
    missing_shuffle
        .as_object_mut()
        .unwrap()
        .remove("shuffleOutputs");
    let mut invalid_shuffle = payload.clone();
    invalid_shuffle["shuffleOutputs"] = json!("true");
    let mut mainnet = payload.clone();
    mainnet["network"] = json!("mainnet");
    for (payload, bound) in [
        (missing_shuffle, commitments(&p)),
        (invalid_shuffle, commitments(&p)),
        (mainnet, commitments(&p)),
        (payload, FixtureCommitments::from_json(None).unwrap()),
    ] {
        let result = handle_value_with_commitments(
            json!({"protocol":ADAPTER_PROTOCOL,"id":"guard","operation":"silent-payment-send","payload":payload}),
            DIGEST,
            &bound,
        );
        assert_eq!(result["status"], "rejected", "{result:#}");
        assert!(result.get("output").is_none());
    }
}

#[test]
fn rejects_tampered_parent_or_child_authorization_for_both_layouts() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-output.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        let child = Psbt::from_str(v["child"].as_str().unwrap()).unwrap();
        let template = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
        let payload = json!({"psbt":v["child"],"parentPsbt":v["output"]["finalizedPsbt"],"templatePsbt":f["template"],"fixtureId":"bip352-multi-output","network":"regtest"});
        let mut cases = Vec::new();
        let mut mainnet = payload.clone();
        mainnet["network"] = json!("mainnet");
        cases.push(mainnet);
        let mut parent = Psbt::from_str(v["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
        parent.outputs.reverse();
        let mut changed = payload.clone();
        changed["parentPsbt"] = json!(STANDARD.encode(parent.serialize()));
        cases.push(changed);
        let mut changed_template = template.clone();
        changed_template.outputs[0].amount += Amount::from_sat(1);
        let mut changed = payload.clone();
        changed["templatePsbt"] = json!(STANDARD.encode(changed_template.serialize()));
        cases.push(changed);
        let mut changed_child = child.clone();
        changed_child.outputs[0].script_pubkey =
            ScriptBuf::from_hex("001406afd46bcdfd22ef94ac122aa11f241244a37ecc").unwrap();
        let mut changed = payload.clone();
        changed["psbt"] = json!(STANDARD.encode(changed_child.serialize()));
        cases.push(changed);
        let mut changed_child = child.clone();
        changed_child.inputs[1].sighash_type =
            Some(psbt_v2::bitcoin::sighash::TapSighashType::All.into());
        let mut changed = payload.clone();
        changed["psbt"] = json!(STANDARD.encode(changed_child.serialize()));
        cases.push(changed);
        for payload in cases {
            for spdk in [false, true] {
                let mut payload = payload.clone();
                if spdk {
                    payload["receiver"] = json!("spdk");
                }
                let result = handle_value_with_commitments(
                    json!({"protocol":ADAPTER_PROTOCOL,"id":"guard","operation":"silent-payment-spend","payload":payload}),
                    DIGEST,
                    &commitments(&template),
                );
                assert_eq!(result["status"], "rejected", "{result:#}");
                assert!(result.get("output").is_none());
            }
        }
    }
}

#[test]
fn independent_spdk_wallet_discovers_and_spends_both_layouts() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-output.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        let child = Psbt::from_str(v["child"].as_str().unwrap()).unwrap();
        let response = receive(&f, v, &child, true);
        assert_eq!(response["status"], "ok", "{response:#}");
        assert_eq!(
            response["output"]["receiverImplementation"],
            "spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7"
        );
        assert_eq!(response["output"]["signedInputs"], 2);
        assert_eq!(
            response["output"]["transactionId"],
            v["receiverOutput"]["transactionId"]
        );
        let finalized =
            Psbt::from_str(response["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
        assert!(
            finalized
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some() && i.unknowns.is_empty())
        );
    }
}
