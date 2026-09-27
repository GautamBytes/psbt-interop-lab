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
    p.outputs[0].amount = Amount::from_sat(48_000);
    p.outputs[1].amount = Amount::from_sat(44_000);
    for (index, script) in [
        (1, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
        (
            2,
            "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ),
    ] {
        p.outputs.insert(
            index,
            Output::new(psbt_v2::bitcoin::TxOut {
                value: Amount::from_sat(48_000),
                script_pubkey: ScriptBuf::from_hex(script).unwrap(),
            }),
        );
    }
    p.global.output_count = 4;
    p
}
fn commitments(p: &Psbt) -> FixtureCommitments {
    let tx = Signer::new(p.clone()).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(&json!({"bip352-multi-receiver":format!("sha256:{:x}",Sha256::digest(consensus::serialize(&tx)))}).to_string())).unwrap()
}
#[test]
fn pays_two_independent_receivers_with_repeated_alice_outputs_in_both_layouts() {
    let p = fixture();
    for shuffle in [false, true] {
        let mut expected_scripts = None;
        for mode in ["per-input", "global"] {
            for reverse in [false, true] {
                let result = handle_value_with_commitments(
                    json!({"protocol":ADAPTER_PROTOCOL,"id":"two-receivers","operation":"silent-payment-send",
            "payload":{"psbt":STANDARD.encode(p.serialize()),"fixtureId":"bip352-multi-receiver","network":"regtest","shareMode":mode,"reverseInputs":reverse,"shuffleOutputs":shuffle}}),
                    DIGEST,
                    &commitments(&p),
                );
                assert_eq!(result["status"], "ok", "{result:#}");
                let signed = Psbt::from_str(result["output"]["psbt"].as_str().unwrap()).unwrap();
                assert_eq!(result["output"]["silentPaymentOutputs"], 3);
                let recipients: Vec<_> = signed
                    .outputs
                    .iter()
                    .filter(|o| o.sp_v0_info.is_some())
                    .collect();
                assert_eq!(recipients[0].sp_v0_info, recipients[2].sp_v0_info);
                assert_ne!(recipients[0].sp_v0_info, recipients[1].sp_v0_info);
                assert_ne!(recipients[0].script_pubkey, recipients[2].script_pubkey);
                assert_eq!(signed.outputs[if shuffle { 0 } else { 3 }], p.outputs[3]);
                assert!(signed.inputs.iter().all(|i| i.partial_sigs.len() == 1));
                if mode == "per-input" {
                    assert!(
                        signed
                            .inputs
                            .iter()
                            .all(|i| i.sp_ecdh_shares.len() == 2 && i.sp_dleq_proofs.len() == 2)
                    );
                } else {
                    assert_eq!(signed.global.sp_ecdh_shares.len(), 2);
                    assert_eq!(signed.global.sp_dleq_proofs.len(), 2);
                }
                if let Some(expected) = &expected_scripts {
                    assert_eq!(&result["output"]["outputScripts"], expected);
                } else {
                    expected_scripts = Some(result["output"]["outputScripts"].clone());
                }
            }
        }
    }
}

fn receive(f: &Value, v: &Value, child: &str, receiver: &str) -> Value {
    let template = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
    handle_value_with_commitments(
        json!({"protocol":ADAPTER_PROTOCOL,"id":"receive","operation":"silent-payment-spend",
        "payload":{"psbt":child,"parentPsbt":v["output"]["finalizedPsbt"],"templatePsbt":f["template"],"fixtureId":"bip352-multi-receiver","network":"regtest","receiver":"spdk","receiverId":receiver}}),
        DIGEST,
        &commitments(&template),
    )
}
#[test]
fn independent_wallets_spend_their_own_outputs_and_reject_each_others() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-receiver.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        for (i, name) in ["alice", "bob"].iter().enumerate() {
            let child = v["children"][i].as_str().unwrap();
            let response = receive(&f, v, child, name);
            assert_eq!(response["status"], "ok", "{response:#}");
            assert_eq!(
                response["output"]["signedInputs"],
                if i == 0 { 2 } else { 1 }
            );
            assert_eq!(
                response["output"]["receiverImplementation"],
                "spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7"
            );
            let other = receive(&f, v, v["children"][1 - i].as_str().unwrap(), name);
            assert_eq!(other["status"], "rejected", "{other:#}");
            assert_eq!(
                other["error"]["class"],
                "silent_payment.receiver_link_invalid"
            );
            assert!(other.get("output").is_none());
        }
    }
}

#[test]
fn rejects_foreign_outpoints_even_with_the_correct_shape_and_value() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-receiver.json")).unwrap();
    for v in f["variants"].as_array().unwrap() {
        for (i, name) in ["alice", "bob"].iter().enumerate() {
            let child = Psbt::from_str(v["children"][i].as_str().unwrap()).unwrap();
            let other = Psbt::from_str(v["children"][1 - i].as_str().unwrap()).unwrap();
            let mut changed = child.clone();
            changed.inputs[0].spent_output_index = other.inputs[0].spent_output_index;
            changed.inputs[0].witness_utxo = other.inputs[0].witness_utxo.clone();
            let result = receive(&f, v, &STANDARD.encode(changed.serialize()), name);
            assert_eq!(
                result["error"]["class"], "silent_payment.receiver_link_invalid",
                "{result:#}"
            );
            assert!(result.get("output").is_none());
            let mut changed = child.clone();
            changed.outputs[0].amount += Amount::from_sat(1);
            let result = receive(&f, v, &STANDARD.encode(changed.serialize()), name);
            assert_eq!(result["status"], "rejected", "{result:#}");
            assert!(result.get("output").is_none());
            let mut changed = child;
            changed.outputs[0].script_pubkey = other.outputs[0].script_pubkey.clone();
            let result = receive(&f, v, &STANDARD.encode(changed.serialize()), name);
            assert_eq!(result["status"], "rejected", "{result:#}");
            assert!(result.get("output").is_none());
        }
    }
}

#[test]
fn rejects_unknown_identity_network_and_uncommitted_template() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-receiver.json")).unwrap();
    let v = &f["variants"][0];
    let template = Psbt::from_str(f["template"].as_str().unwrap()).unwrap();
    let payload = json!({"psbt":v["children"][0],"parentPsbt":v["output"]["finalizedPsbt"],"templatePsbt":f["template"],"fixtureId":"bip352-multi-receiver","network":"regtest","receiver":"spdk","receiverId":"alice"});
    let mut identity = payload.clone();
    identity["receiverId"] = json!("mallory");
    let mut network = payload.clone();
    network["network"] = json!("mainnet");
    let mut missing = payload.clone();
    missing.as_object_mut().unwrap().remove("receiverId");
    for (payload, bound) in [
        (identity, commitments(&template)),
        (network, commitments(&template)),
        (missing, commitments(&template)),
        (payload, FixtureCommitments::from_json(None).unwrap()),
    ] {
        let result = handle_value_with_commitments(
            json!({"protocol":ADAPTER_PROTOCOL,"id":"guard","operation":"silent-payment-spend","payload":payload}),
            DIGEST,
            &bound,
        );
        assert_eq!(result["status"], "rejected", "{result:#}");
        assert!(result.get("output").is_none());
    }
}
