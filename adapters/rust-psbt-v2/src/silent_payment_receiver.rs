use super::*;

pub(super) fn spend(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let count = if payload_string(&request.payload, "fixtureId") == Some("bip352-multi-output") {
        2
    } else {
        1
    };
    if !exact_fields(
        &request.payload,
        &["psbt", "parentPsbt", "templatePsbt", "network", "fixtureId"],
    ) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "Expected a receiver PSBT, its finalized parent and the committed original funding template",
        );
    }
    if payload_string(&request.payload, "network") != Some("regtest") {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.network_not_allowed",
            "Receiver discovery is restricted to regtest fixtures",
        );
    }
    let (Some(template), Some(parent), Some(child)) = (
        payload_string(&request.payload, "templatePsbt").and_then(parse_psbt),
        payload_string(&request.payload, "parentPsbt").and_then(parse_psbt),
        payload_string(&request.payload, "psbt").and_then(parse_psbt),
    ) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "Invalid receiver or parent PSBTv2",
        );
    };
    if let Some(response) = commitment_failure(
        request,
        digest,
        commitments,
        if count == 2 {
            "bip352-multi-output"
        } else {
            "bip375-multi"
        },
        &template.psbt,
    ) {
        return response;
    }
    if let Err(message) = validate_link(&template.psbt, &parent.psbt, &child.psbt, count) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "silent_payment.receiver_link_invalid",
            message,
        );
    }
    match complete_silent_payment_spend(child.psbt, count) {
        Ok((signed, finalized, transaction, keys)) => {
            let mut output = json!({
                "psbt":STANDARD.encode(signed.serialize()),"finalizedPsbt":STANDARD.encode(finalized.serialize()),
                "finalized":true,"signedInputs":count,
                "transaction":consensus::serialize(&transaction).to_lower_hex_string(),
                "transactionId":transaction.compute_txid().to_string()
            });
            if count == 2 {
                output["derivedOutputKeys"] = json!(keys);
            } else {
                output["derivedOutputKey"] = json!(keys[0]);
            }
            success(&request.id, digest, output)
        }
        Err(error) => failure(&request.id, digest, "rejected", error.class, &error.message),
    }
}

fn validate_link(
    template: &Psbt,
    parent: &Psbt,
    child: &Psbt,
    count: usize,
) -> Result<(), &'static str> {
    if template.inputs.len() != 2
        || template.outputs.len() != count + 1
        || parent.inputs.len() != 2
        || parent.outputs.len() != count + 1
        || child.inputs.len() != count
        || child.outputs.len() != 1
    {
        return Err("Unexpected payment lifecycle shape");
    }
    let public_keys = [
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .map_err(|_| "Invalid public fixture key")?,
        PublicKey::from_str(SCALAR_TWO_PUBLIC_KEY).map_err(|_| "Invalid public fixture key")?,
    ];
    let mut total = 0_u64;
    for (i, key) in public_keys.iter().enumerate() {
        let funding = template.inputs[i]
            .witness_utxo
            .as_ref()
            .ok_or("Missing funding UTXO")?;
        let script = ScriptBuf::new_p2wpkh(
            &key.wpubkey_hash()
                .map_err(|_| "Invalid public fixture key")?,
        );
        if funding.script_pubkey != script
            || parent.inputs[i].witness_utxo.as_ref() != Some(funding)
            || parent.inputs[i].non_witness_utxo != template.inputs[i].non_witness_utxo
        {
            return Err("Funding scripts or UTXOs differ from the committed fixture");
        }
        if let Some(previous) = &template.inputs[i].non_witness_utxo
            && (previous.compute_txid() != template.inputs[i].previous_txid
                || previous
                    .output
                    .get(template.inputs[i].spent_output_index as usize)
                    != Some(funding))
        {
            return Err("Full previous transaction disagrees with funding metadata");
        }
        total = total
            .checked_add(funding.value.to_sat())
            .ok_or("Funding overflow")?;
    }
    for (index, output) in template.outputs.iter().enumerate() {
        let key = &public_keys[usize::from(index == count)];
        let script = if count == 2 && index == 1 {
            ScriptBuf::new_p2pkh(&key.pubkey_hash())
        } else {
            ScriptBuf::new_p2wpkh(&key.wpubkey_hash().map_err(|_| "Invalid fixture key")?)
        };
        if output.script_pubkey != script {
            return Err("Invalid template destination");
        }
    }
    let outputs = template.outputs.iter().try_fold(0_u64, |sum, o| {
        sum.checked_add(o.amount.to_sat()).ok_or("Output overflow")
    })?;
    if total.checked_sub(outputs) != Some(12_000) {
        return Err("Unexpected sender fixture fee");
    }
    let finalized = native_extractable_psbt(parent.clone());
    if !finalized.is_finalized() {
        return Err("Parent is not finalized");
    }
    finalized
        .interpreter_check(&Secp256k1::verification_only())
        .map_err(|_| "Parent witnesses fail script verification")?;
    let parent_tx = Extractor::new(finalized)
        .map_err(|_| "Parent is not finalized")?
        .extract_tx()
        .map_err(|_| "Cannot extract parent")?;
    let mut original = Signer::new(template.clone())
        .map_err(|_| "Invalid original locktime")?
        .unsigned_tx();
    for (txin, input) in original.input.iter_mut().zip(&template.inputs) {
        txin.sequence = input.sequence.unwrap_or(Sequence::MAX);
    }
    let mut normalized = parent_tx.clone();
    for input in &mut normalized.input {
        input.witness = Witness::new();
        input.script_sig = ScriptBuf::new();
    }
    // The only permitted sender permutation is the committed layout or its reverse.
    let change_script = original.output[count].script_pubkey.clone();
    let shuffled = count == 2 && parent_tx.output[0].script_pubkey == change_script;
    if shuffled {
        original.output.reverse();
    }
    for (i, output) in normalized.output.iter_mut().enumerate() {
        if original.output[i].script_pubkey != change_script {
            output.script_pubkey = original.output[i].script_pubkey.clone();
        }
    }
    if normalized != original {
        return Err("Parent differs from the authorized sender template");
    }
    let discovered = discover_tweaks(&parent_tx, count)?;
    let mut total_received = 0_u64;
    for (input, (index, tweak)) in child.inputs.iter().zip(&discovered) {
        total_received = total_received
            .checked_add(parent_tx.output[*index].value.to_sat())
            .ok_or("Receiver value overflow")?;
        let spend_key = raw::Key {
            type_value: BIP376_SPEND_KEY_TYPE,
            key: public_keys[0].to_bytes(),
        };
        let tweak_key = raw::Key {
            type_value: BIP376_TWEAK_TYPE,
            key: vec![],
        };
        if input.unknowns.get(&spend_key) != Some(&vec![0; 4])
            || input.unknowns.get(&tweak_key).map(Vec::as_slice) != Some(tweak.as_slice())
        {
            return Err("Receiver key or tweak differs from independent discovery");
        }
        if input.previous_txid != parent_tx.compute_txid()
            || input.spent_output_index as usize != *index
            || input.witness_utxo.as_ref() != Some(&parent_tx.output[*index])
            || input.non_witness_utxo.is_some()
            || input.witness_script.is_some()
            || input.redeem_script.is_some()
            || input.tap_internal_key.is_some()
            || input.tap_merkle_root.is_some()
            || !input.tap_scripts.is_empty()
            || !input.tap_script_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.partial_sigs.is_empty()
            || input.final_script_witness.is_some()
            || input.final_script_sig.is_some()
            || input
                .taproot_hash_ty()
                .map_err(|_| "Invalid child sighash")?
                != psbt_v2::bitcoin::sighash::TapSighashType::Default
        {
            return Err("Receiver input is not a clean spend of the discovered output");
        }
    }
    let tx = Signer::new(child.clone())
        .map_err(|_| "Invalid receiver locktime")?
        .unsigned_tx();
    let amount = total_received
        .checked_sub(10_000)
        .filter(|v| *v > 330)
        .ok_or("Insufficient receiver output value")?;
    if tx.version != transaction::Version::TWO
        || tx.lock_time != absolute::LockTime::ZERO
        || tx
            .input
            .iter()
            .any(|i| i.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
        || child.global.tx_modifiable_flags != 0
        || child.outputs[0].script_pubkey != template.outputs[0].script_pubkey
        || child.outputs[0].amount.to_sat() != amount
        || child.outputs[0].sp_v0_info.is_some()
        || child.outputs[0].sp_v0_label.is_some()
    {
        return Err("Receiver destination, amount, fee or transaction flags changed");
    }
    Ok(())
}

// Receiver-side BIP352 derivation: only public input witnesses/outpoints and
// the receiver's scan key are used. Sender shares and recipient PSBT fields are ignored.
fn discover_tweaks(
    parent: &Transaction,
    count: usize,
) -> Result<Vec<(usize, [u8; 32])>, &'static str> {
    let mut keys = Vec::new();
    let mut outpoints = Vec::new();
    for input in &parent.input {
        if input.witness.len() != 2 || !input.script_sig.is_empty() {
            return Err("Expected P2WPKH parent inputs");
        }
        keys.push(
            SecpPublicKey::from_slice(input.witness.nth(1).ok_or("Missing input public key")?)
                .map_err(|_| "Invalid input public key")?,
        );
        outpoints.push(consensus::serialize(&input.previous_output));
    }
    outpoints.sort();
    if outpoints[0] == outpoints[1] {
        return Err("Duplicate parent input");
    }
    let aggregate = keys[0].combine(&keys[1]).map_err(|_| "Input keys cancel")?;
    let input_hash = scalar_from_hash(tagged_hash(
        "BIP0352/Inputs",
        &[outpoints[0].as_slice(), &aggregate.serialize()].concat(),
    ))?;
    let mut scan = [0_u8; 32];
    scan[31] = 2;
    let scan_scalar = Scalar::from_be_bytes(scan).map_err(|_| "Invalid receiver scan key")?;
    let secp = Secp256k1::new();
    let shared = aggregate
        .mul_tweak(&secp, &scan_scalar)
        .and_then(|p| p.mul_tweak(&secp, &input_hash))
        .map_err(|_| "Invalid receiver shared secret")?;
    let mut found = Vec::new();
    for k in 0..count {
        let tweak = tagged_hash(
            "BIP0352/SharedSecret",
            &[shared.serialize().as_slice(), &(k as u32).to_be_bytes()].concat(),
        );
        let tweak_secret =
            SecretKey::from_slice(&tweak).map_err(|_| "Invalid receiver output tweak")?;
        let spend = SecpPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .map_err(|_| "Invalid spend public key")?;
        let output = spend
            .combine(&SecpPublicKey::from_secret_key(&secp, &tweak_secret))
            .map_err(|_| "Invalid receiver output key")?;
        let script =
            ScriptBuf::new_p2tr_tweaked(output.x_only_public_key().0.dangerous_assume_tweaked());
        let matches = parent
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey == script)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        if matches.len() != 1 || found.iter().any(|(index, _)| *index == matches[0]) {
            return Err("No unique output for this receiver");
        }
        found.push((matches[0], tweak));
    }
    Ok(found)
}
