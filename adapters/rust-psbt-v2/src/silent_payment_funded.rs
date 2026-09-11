use super::*;

// This operation authorizes a Core-funded P2WPKH template, then replaces its
// destination with one fixed public test recipient. It is not arbitrary PSBT signing.
pub(super) fn send(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let (encoded, fixture_id) = match fixture_payload(request) {
        Ok(value) => value,
        Err((class, message)) => return failure(&request.id, digest, "rejected", class, message),
    };
    let Some(parsed) = parse_psbt(encoded) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "Invalid funded PSBTv2 template",
        );
    };
    if let Some(response) =
        commitment_failure(request, digest, commitments, fixture_id, &parsed.psbt)
    {
        return response;
    }
    let result = complete(parsed.psbt);
    match result {
        Ok((signed, finalized, transaction)) => success(
            &request.id,
            digest,
            json!({
                "psbt": STANDARD.encode(signed.serialize()),
                "finalizedPsbt": STANDARD.encode(finalized.serialize()),
                "finalized": true,
                "signedInputs": 1,
                "silentPaymentOutputs": 1,
                "outputScript": signed.outputs[0].script_pubkey.to_hex_string(),
                "transaction": consensus::serialize(&transaction).to_lower_hex_string(),
                "transactionId": transaction.compute_txid().to_string()
            }),
        ),
        Err(message) => failure(
            &request.id,
            digest,
            "rejected",
            "silent_payment.funded_template_invalid",
            message,
        ),
    }
}

fn complete(mut psbt: Psbt) -> Result<(Psbt, Psbt, Transaction), &'static str> {
    let (private_key, public_key) = fixture_key()?;
    validate_signing_scope(&psbt, "p2wpkh", &public_key)?;
    if psbt.inputs.len() != 1 || psbt.outputs.len() != 1 {
        return Err("The funded sender requires exactly one input and one output");
    }
    let input = &psbt.inputs[0];
    let output = &psbt.outputs[0];
    let funding = input.witness_utxo.as_ref().ok_or("Missing witness UTXO")?;
    if funding.value.to_sat().checked_sub(output.amount.to_sat()) != Some(11_000)
        || output.script_pubkey != funding.script_pubkey
        || !input.partial_sigs.is_empty()
        || input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.sp_ecdh_shares.is_empty()
        || !input.sp_dleq_proofs.is_empty()
        || !psbt.global.sp_ecdh_shares.is_empty()
        || !psbt.global.sp_dleq_proofs.is_empty()
        || output.sp_v0_info.is_some()
        || output.sp_v0_label.is_some()
    {
        return Err("Expected a clean P2WPKH template with the fixed fixture fee");
    }
    if let Some(previous) = &input.non_witness_utxo
        && (previous.compute_txid() != input.previous_txid
            || previous.output.get(input.spent_output_index as usize) != Some(funding))
    {
        return Err(
            "Full previous transaction disagrees with the funding outpoint or witness UTXO",
        );
    }
    let scan_key = SecpPublicKey::from_str(SCALAR_TWO_PUBLIC_KEY)
        .map_err(|_| "Invalid public fixture scan key")?;
    let mut info = scan_key.serialize().to_vec();
    info.extend_from_slice(&public_key.to_bytes());
    psbt.outputs[0].sp_v0_info = Some(info);
    let (share, proof) = bip375_dleq_proof(private_key.inner, scan_key)?;
    psbt.outputs[0].script_pubkey = bip375_output_script(&psbt, public_key.inner, share)?;
    psbt.inputs[0]
        .sp_ecdh_shares
        .insert(CompressedPublicKey(scan_key), CompressedPublicKey(share));
    psbt.inputs[0]
        .sp_dleq_proofs
        .insert(CompressedPublicKey(scan_key), proof);
    psbt.global.tx_modifiable_flags &= !0x03;
    psbt.inputs[0]
        .bip32_derivations
        .entry(public_key)
        .or_insert((Fingerprint::default(), DerivationPath::default()));
    let (signed, _) = native_sign(psbt, "p2wpkh")?;
    let mut finalized = finalize_preserving_intent(signed.clone(), "p2wpkh", &public_key)?;
    omit_empty_final_script_sigs(&mut finalized);
    let transaction = Extractor::new(native_extractable_psbt(finalized.clone()))
        .map_err(|_| "Funded sender is not extractable")?
        .extract_tx()
        .map_err(|_| "Funded sender extraction failed")?;
    Ok((signed, finalized, transaction))
}
