use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_lab_rust_psbt_v2_adapter::{
    ADAPTER_PROTOCOL, FixtureCommitments, handle_value_with_commitments,
};
use psbt_v2::bitcoin::{
    Amount, Network, OutPoint, PrivateKey, ScriptBuf, TxOut, consensus,
    secp256k1::{Secp256k1, SecretKey},
};
use psbt_v2::v2::{Constructor, InputBuilder, Modifiable, Output, Psbt, Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
fn fixture() -> Psbt {
    let mut builder = Constructor::<Modifiable>::default();
    let mut scripts = Vec::new();
    for scalar in [1_u8, 2] {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let key = PrivateKey::new(SecretKey::from_slice(&bytes).unwrap(), Network::Regtest)
            .public_key(&Secp256k1::new());
        let script = ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap());
        builder = builder.input(
            InputBuilder::new(
                &OutPoint::from_str(&format!("{}:0", format!("{scalar:02x}").repeat(32))).unwrap(),
            )
            .segwit_fund(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: script.clone(),
            })
            .build(),
        );
        scripts.push(script);
    }
    for script in scripts {
        builder = builder.output(Output::new(TxOut {
            value: Amount::from_sat(94_000),
            script_pubkey: script,
        }));
    }
    builder.psbt().unwrap()
}
fn commitments(psbt: &Psbt) -> FixtureCommitments {
    let tx = Signer::new(psbt.clone()).unwrap().unsigned_tx();
    FixtureCommitments::from_json(Some(
        &json!({"bip375-multi": format!("sha256:{:x}", Sha256::digest(consensus::serialize(&tx)))})
            .to_string(),
    ))
    .unwrap()
}
fn request(psbt: &Psbt, mode: &str, reverse: bool) -> Value {
    json!({"protocol": ADAPTER_PROTOCOL, "id": "multi", "operation": "silent-payment-send", "payload": {"network": "regtest", "fixtureId": "bip375-multi", "psbt": STANDARD.encode(psbt.serialize()), "shareMode": mode, "reverseInputs": reverse}})
}
#[test]
fn four_variants_sign_both_keys_and_preserve_change() {
    let template = fixture();
    let bound = commitments(&template);
    let mut destination = None;
    let mut outputs = Vec::new();
    for mode in ["global", "per-input"] {
        for reverse in [false, true] {
            let response =
                handle_value_with_commitments(request(&template, mode, reverse), DIGEST, &bound);
            assert_eq!(response["status"], "ok", "{response:#}");
            let signed = Psbt::from_str(response["output"]["psbt"].as_str().unwrap()).unwrap();
            let mut finalized =
                Psbt::from_str(response["output"]["finalizedPsbt"].as_str().unwrap()).unwrap();
            assert_eq!(response["output"]["signedInputs"], 2);
            assert_eq!(signed.outputs[1], template.outputs[1]);
            assert_eq!(signed.outputs[0].amount, template.outputs[0].amount);
            assert_eq!(
                signed.inputs[0].previous_txid,
                template.inputs[usize::from(reverse)].previous_txid
            );
            assert!(signed.outputs[0].script_pubkey.is_p2tr());
            if let Some(script) = &destination {
                assert_eq!(script, &signed.outputs[0].script_pubkey);
            }
            destination = Some(signed.outputs[0].script_pubkey.clone());
            assert_eq!(
                signed.global.sp_ecdh_shares.len(),
                usize::from(mode == "global")
            );
            for input in &signed.inputs {
                assert_eq!(input.partial_sigs.len(), 1);
                assert_eq!(input.sp_ecdh_shares.len(), usize::from(mode == "per-input"));
            }
            for input in &finalized.inputs {
                assert_eq!(input.final_script_witness.as_ref().unwrap().len(), 2);
                assert!(input.partial_sigs.is_empty());
            }
            for input in &mut finalized.inputs {
                input.final_script_sig = Some(ScriptBuf::new());
            }
            finalized
                .interpreter_check(&Secp256k1::verification_only())
                .unwrap();
            outputs.push(json!({"mode": mode, "reverse": reverse, "output": response["output"]}));
        }
    }
    if let Ok(path) = std::env::var("PSBT_MULTI_TEST_EXPORT") {
        std::fs::write(
            path,
            serde_json::to_string_pretty(
                &json!({"template": STANDARD.encode(template.serialize()), "variants": outputs}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
#[test]
fn rejects_unsigned_intent_and_metadata_tampering_without_signatures() {
    let template = fixture();
    let bound = commitments(&template);
    let mut variants = Vec::new();
    let mut changed = template.clone();
    changed.inputs[1].spent_output_index += 1;
    variants.push(changed);
    let mut changed = template.clone();
    changed.outputs[0].amount = Amount::from_sat(94_001);
    variants.push(changed);
    let mut changed = template.clone();
    changed.outputs[1].script_pubkey = ScriptBuf::new();
    variants.push(changed);
    let mut changed = template.clone();
    changed.outputs[0].sp_v0_info = Some(vec![0; 66]);
    variants.push(changed);
    let mut changed = template.clone();
    changed.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(100_001);
    variants.push(changed);
    let mut changed = template.clone();
    changed.inputs[1]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = template.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    variants.push(changed);
    let mut changed = template.clone();
    changed.inputs.pop();
    variants.push(changed);
    for psbt in variants {
        let response =
            handle_value_with_commitments(request(&psbt, "per-input", false), DIGEST, &bound);
        assert_eq!(response["status"], "rejected", "{response:#}");
        assert!(response.get("output").is_none());
    }
}
#[test]
fn rejects_missing_commitment_network_and_unknown_options() {
    let psbt = fixture();
    let bound = commitments(&psbt);
    assert_eq!(
        handle_value_with_commitments(
            request(&psbt, "global", false),
            DIGEST,
            &FixtureCommitments::default()
        )["error"]["class"],
        "policy.fixture_commitment_missing"
    );
    for (field, value) in [
        ("network", json!("mainnet")),
        ("shareMode", json!("both")),
        ("reverseInputs", json!("true")),
        ("extra", json!(true)),
    ] {
        let mut req = request(&psbt, "global", false);
        req["payload"][field] = value;
        assert_eq!(
            handle_value_with_commitments(req, DIGEST, &bound)["status"],
            "rejected"
        );
    }
}

#[test]
fn rejects_preexisting_signatures_supplied_shares_and_unsafe_sighashes() {
    let template = fixture();
    let bound = commitments(&template);
    let response =
        handle_value_with_commitments(request(&template, "per-input", false), DIGEST, &bound);
    let signed = Psbt::from_str(response["output"]["psbt"].as_str().unwrap()).unwrap();
    for index in 0..2 {
        let mut variants = Vec::new();
        let mut changed = template.clone();
        changed.inputs[index].partial_sigs = signed.inputs[index].partial_sigs.clone();
        variants.push(changed);
        let mut changed = template.clone();
        changed.inputs[index].sp_ecdh_shares = signed.inputs[index].sp_ecdh_shares.clone();
        variants.push(changed);
        let mut changed = template.clone();
        changed.inputs[index].sp_dleq_proofs = signed.inputs[index].sp_dleq_proofs.clone();
        variants.push(changed);
        let mut changed = template.clone();
        changed.inputs[index].sp_ecdh_shares = signed.inputs[index].sp_ecdh_shares.clone();
        changed.inputs[index].sp_dleq_proofs = signed.inputs[index].sp_dleq_proofs.clone();
        variants.push(changed);
        let mut changed = template.clone();
        changed.inputs[index].sighash_type =
            Some(psbt_v2::bitcoin::sighash::EcdsaSighashType::None.into());
        variants.push(changed);
        let mut changed = template.clone();
        let previous: psbt_v2::bitcoin::Transaction = consensus::deserialize(&hex_bytes(
            response["output"]["transaction"].as_str().unwrap(),
        ))
        .unwrap();
        changed.inputs[index].non_witness_utxo = Some(previous);
        variants.push(changed);
        for (case, changed) in variants.into_iter().enumerate() {
            for mode in ["global", "per-input"] {
                let response =
                    handle_value_with_commitments(request(&changed, mode, false), DIGEST, &bound);
                assert_eq!(
                    response["error"]["class"],
                    if case == 1 || case == 2 {
                        "psbt.parse_failed"
                    } else {
                        "silent_payment.funded_template_invalid"
                    },
                    "case {case}: {response:#}"
                );
                assert!(response.get("output").is_none());
            }
        }
    }
}
fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rejects_duplicate_inputs_even_with_a_matching_commitment() {
    let mut template = fixture();
    template.inputs[1].previous_txid = template.inputs[0].previous_txid;
    template.inputs[1].spent_output_index = template.inputs[0].spent_output_index;
    let response = handle_value_with_commitments(
        request(&template, "global", false),
        DIGEST,
        &commitments(&template),
    );
    assert_eq!(
        response["error"]["class"],
        "silent_payment.funded_template_invalid"
    );
}
