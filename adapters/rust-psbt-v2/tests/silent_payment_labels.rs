use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::{
    bitcoin::consensus,
    v2::{Psbt, Signer},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
fn commitments(template: &str) -> FixtureCommitments {
    let p = Psbt::from_str(template).unwrap();
    let tx = Signer::new(p).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(
        &json!({"bip352-labels":format!("sha256:{:x}",Sha256::digest(consensus::serialize(&tx)))})
            .to_string(),
    ))
    .unwrap()
}
#[test]
fn sends_to_label_one_in_both_layouts_and_share_modes() {
    let f: Value = serde_json::from_str(include_str!("fixtures/multi-output.json")).unwrap();
    for shuffle in [false, true] {
        let mut scripts = None;
        for mode in ["per-input", "global"] {
            for reverse in [false, true] {
                let result = handle_value_with_commitments(
                    json!({"protocol":ADAPTER_PROTOCOL,"id":"labels","operation":"silent-payment-send","payload":{"psbt":f["template"],"fixtureId":"bip352-labels","network":"regtest","shareMode":mode,"reverseInputs":reverse,"shuffleOutputs":shuffle}}),
                    DIGEST,
                    &commitments(f["template"].as_str().unwrap()),
                );
                assert_eq!(result["status"], "ok", "{result:#}");
                let p = Psbt::from_str(result["output"]["psbt"].as_str().unwrap()).unwrap();
                let recipients: Vec<_> = p
                    .outputs
                    .iter()
                    .filter_map(|o| o.sp_v0_info.as_ref())
                    .collect();
                assert_eq!(recipients.len(), 2);
                assert_eq!(recipients[0], recipients[1]);
                assert_ne!(
                    &recipients[0][33..],
                    &psbt_v2::bitcoin::secp256k1::PublicKey::from_str(
                        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    )
                    .unwrap()
                    .serialize()
                );
                if let Some(expected) = &scripts {
                    assert_eq!(&result["output"]["outputScripts"], expected);
                } else {
                    scripts = Some(result["output"]["outputScripts"].clone());
                }
            }
        }
    }
}

fn receive(f: &Value, v: &Value, child: &Psbt, network: &str, bound: &FixtureCommitments) -> Value {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    handle_value_with_commitments(
        json!({"protocol":ADAPTER_PROTOCOL,"id":"labels","operation":"silent-payment-spend","payload":{"psbt":STANDARD.encode(child.serialize()),"parentPsbt":v["output"]["finalizedPsbt"],"templatePsbt":f["template"],"fixtureId":"bip352-labels","network":network,"receiver":"spdk"}}),
        DIGEST,
        bound,
    )
}
#[test]
fn spends_labeled_outputs_and_rejects_missing_wrong_or_double_label_tweaks() {
    use psbt_v2::{
        bitcoin::secp256k1::{Scalar, SecretKey},
        raw,
    };
    let f: Value = serde_json::from_str(include_str!("fixtures/labels.json")).unwrap();
    let bound = commitments(f["template"].as_str().unwrap());
    let label = |m: u32| {
        let tag = Sha256::digest(b"BIP0352/Label");
        let mut scan = [0u8; 32];
        scan[31] = 2;
        let hash: [u8; 32] =
            Sha256::digest([tag.as_slice(), tag.as_slice(), &scan, &m.to_be_bytes()].concat())
                .into();
        SecretKey::from_slice(&hash).unwrap()
    };
    for v in f["variants"].as_array().unwrap() {
        let child = Psbt::from_str(v["child"].as_str().unwrap()).unwrap();
        let result = receive(&f, v, &child, "regtest", &bound);
        assert_eq!(result["status"], "ok", "{result:#}");
        assert_eq!(
            result["output"]["transaction"],
            v["receiverOutput"]["transaction"]
        );
        for i in 0..2 {
            let key = raw::Key {
                type_value: 0x20,
                key: vec![],
            };
            let combined = SecretKey::from_slice(&child.inputs[i].unknowns[&key]).unwrap();
            let base = combined
                .add_tweak(&Scalar::from(label(1).negate()))
                .unwrap();
            for tweak in [
                base,
                base.add_tweak(&Scalar::from(label(2))).unwrap(),
                combined.add_tweak(&Scalar::from(label(1))).unwrap(),
            ] {
                let mut changed = child.clone();
                changed.inputs[i]
                    .unknowns
                    .insert(key.clone(), tweak.secret_bytes().to_vec());
                let result = receive(&f, v, &changed, "regtest", &bound);
                assert_eq!(
                    result["error"]["class"], "silent_payment.receiver_link_invalid",
                    "{result:#}"
                );
                assert!(result.get("output").is_none());
            }
        }
        for (network, bound) in [
            ("mainnet", bound.clone()),
            ("regtest", FixtureCommitments::from_json(None).unwrap()),
        ] {
            let result = receive(&f, v, &child, network, &bound);
            assert_eq!(result["status"], "rejected", "{result:#}");
            assert!(result.get("output").is_none());
        }
    }
}
