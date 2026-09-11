use super::*;

// A bounded test operation: authorize the original transaction before deriving
// its fixed recipient or applying the explicitly requested input permutation.
pub(super) fn send(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    if !exact_fields(
        &request.payload,
        &["psbt", "network", "fixtureId", "shareMode", "reverseInputs"],
    ) || !matches!(
        payload_string(&request.payload, "shareMode"),
        Some("global" | "per-input")
    ) || request
        .payload
        .get("reverseInputs")
        .and_then(Value::as_bool)
        .is_none()
    {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "Expected a global or per-input share mode and a boolean input permutation",
        );
    }
    if payload_string(&request.payload, "network") != Some("regtest") {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.network_not_allowed",
            "Funded fixtures require regtest",
        );
    }
    let Some(parsed) = payload_string(&request.payload, "psbt").and_then(parse_psbt) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "Invalid funded PSBTv2 template",
        );
    };
    if let Some(response) =
        commitment_failure(request, digest, commitments, "bip375-multi", &parsed.psbt)
    {
        return response;
    }
    let global = payload_string(&request.payload, "shareMode") == Some("global");
    let reverse = request.payload["reverseInputs"] == json!(true);
    match complete(parsed.psbt, global, reverse) {
        Ok((signed, finalized, transaction)) => success(
            &request.id,
            digest,
            json!({
                "psbt": STANDARD.encode(signed.serialize()), "finalizedPsbt": STANDARD.encode(finalized.serialize()),
                "finalized": true, "signedInputs": 2, "silentPaymentOutputs": 1,
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

fn keys() -> Result<Vec<(PrivateKey, PublicKey)>, &'static str> {
    [1_u8, 2]
        .into_iter()
        .map(|scalar| {
            let mut bytes = [0_u8; 32];
            bytes[31] = scalar;
            let secret = SecretKey::from_slice(&bytes).map_err(|_| "Invalid fixture scalar")?;
            let private = PrivateKey::new(secret, Network::Regtest);
            Ok((private, private.public_key(&Secp256k1::new())))
        })
        .collect()
}

fn validate(psbt: &Psbt, keys: &[(PrivateKey, PublicKey)]) -> Result<(), &'static str> {
    if psbt.inputs.len() != 2
        || psbt.outputs.len() != 2
        || psbt.global.tx_modifiable_flags & !3 != 0
    {
        return Err("Expected two inputs, recipient and change, and no reserved modifiable flags");
    }
    if psbt.inputs[0].previous_txid == psbt.inputs[1].previous_txid
        && psbt.inputs[0].spent_output_index == psbt.inputs[1].spent_output_index
    {
        return Err("Duplicate funding outpoint");
    }
    let mut total = 0_u64;
    for (input, (_, key)) in psbt.inputs.iter().zip(keys) {
        let funding = input.witness_utxo.as_ref().ok_or("Missing witness UTXO")?;
        if funding.script_pubkey
            != ScriptBuf::new_p2wpkh(&key.wpubkey_hash().map_err(|_| "Invalid fixture key")?)
            || input.ecdsa_hash_ty().map_err(|_| "Invalid sighash")? != EcdsaSighashType::All
            || input.witness_script.is_some()
            || input.redeem_script.is_some()
            || !input.partial_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || !input.sp_ecdh_shares.is_empty()
            || !input.sp_dleq_proofs.is_empty()
        {
            return Err("Expected clean distinct-key P2WPKH inputs with SIGHASH_ALL");
        }
        if let Some(previous) = &input.non_witness_utxo
            && (previous.compute_txid() != input.previous_txid
                || previous.output.get(input.spent_output_index as usize) != Some(funding))
        {
            return Err("Previous transaction disagrees with witness UTXO or outpoint");
        }
        total = total
            .checked_add(funding.value.to_sat())
            .ok_or("Input amount overflow")?;
    }
    let mut outputs = 0_u64;
    for (output, (_, key)) in psbt.outputs.iter().zip(keys) {
        if output.sp_v0_info.is_some()
            || output.sp_v0_label.is_some()
            || output.script_pubkey
                != ScriptBuf::new_p2wpkh(
                    &key.wpubkey_hash()
                        .map_err(|_| "Invalid output fixture key")?,
                )
            || output.amount.to_sat() < 330
        {
            return Err("Expected fixed recipient template and ordinary change");
        }
        outputs = outputs
            .checked_add(output.amount.to_sat())
            .ok_or("Output amount overflow")?;
    }
    if total.checked_sub(outputs) != Some(12_000)
        || !psbt.global.sp_ecdh_shares.is_empty()
        || !psbt.global.sp_dleq_proofs.is_empty()
    {
        return Err("Expected the fixed 12000 sat fee and no supplied shares or proofs");
    }
    Ok(())
}

fn complete(
    mut psbt: Psbt,
    global: bool,
    reverse: bool,
) -> Result<(Psbt, Psbt, Transaction), &'static str> {
    let mut keys = keys()?;
    validate(&psbt, &keys)?;
    if reverse {
        psbt.inputs.reverse();
        keys.reverse();
    }
    let scan = CompressedPublicKey(
        SecpPublicKey::from_str(SCALAR_TWO_PUBLIC_KEY).map_err(|_| "Invalid scan key")?,
    );
    let (_, spend) = fixture_key()?;
    psbt.outputs[0].sp_v0_info =
        Some([scan.to_bytes().as_slice(), spend.to_bytes().as_slice()].concat());
    let secrets = keys
        .iter()
        .map(|(private, _)| private.inner)
        .collect::<Vec<_>>();
    let aggregate = aggregate_secret(&secrets)?;
    let aggregate_public = SecpPublicKey::from_secret_key(&Secp256k1::new(), &aggregate);
    let (aggregate_share, aggregate_proof) = bip375_dleq_proof(aggregate, scan.0)?;
    if global {
        psbt.global
            .sp_ecdh_shares
            .insert(scan, CompressedPublicKey(aggregate_share));
        psbt.global.sp_dleq_proofs.insert(scan, aggregate_proof);
    } else {
        let mut shares = Vec::new();
        for (input, (private, _)) in psbt.inputs.iter_mut().zip(&keys) {
            let (share, proof) = bip375_dleq_proof(private.inner, scan.0)?;
            input
                .sp_ecdh_shares
                .insert(scan, CompressedPublicKey(share));
            input.sp_dleq_proofs.insert(scan, proof);
            shares.push(share);
        }
        if shares[0]
            .combine(&shares[1])
            .map_err(|_| "Invalid aggregate share")?
            != aggregate_share
        {
            return Err("Per-input shares do not match the aggregate");
        }
    }
    advanced_bip375_output_scripts(
        &mut psbt,
        aggregate_public,
        &BTreeMap::from([(scan, CompressedPublicKey(aggregate_share))]),
    )?;
    psbt.global.tx_modifiable_flags = 0;
    for (input, (_, key)) in psbt.inputs.iter_mut().zip(&keys) {
        input
            .bip32_derivations
            .entry(*key)
            .or_insert((Fingerprint::default(), DerivationPath::default()));
    }
    let key_map = keys
        .iter()
        .map(|(private, public)| (*public, *private))
        .collect::<BTreeMap<_, _>>();
    let (signed, _) = Signer::new(psbt)
        .map_err(|_| "Invalid locktime")?
        .sign(&key_map, &Secp256k1::new())
        .map_err(|_| "Cannot sign both inputs")?;
    let mut finalized = signed.clone();
    for (input, (_, key)) in finalized.inputs.iter_mut().zip(&keys) {
        let signature = input
            .partial_sigs
            .get(key)
            .ok_or("Missing input signature")?;
        if input.partial_sigs.len() != 1 {
            return Err("Unexpected input signatures");
        }
        input.final_script_witness =
            Some(Witness::from_slice(&[signature.to_vec(), key.to_bytes()]));
        input.final_script_sig = Some(ScriptBuf::new());
        clear_non_final_fields(input);
    }
    finalized
        .interpreter_check(&Secp256k1::verification_only())
        .map_err(|_| "Finalized inputs fail script verification")?;
    omit_empty_final_script_sigs(&mut finalized);
    let transaction = Extractor::new(native_extractable_psbt(finalized.clone()))
        .map_err(|_| "Not extractable")?
        .extract_tx()
        .map_err(|_| "Extraction failed")?;
    Ok((signed, finalized, transaction))
}
