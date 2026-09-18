use super::*;
use spdk_wallet::client::{SilentPaymentUnsignedTransaction, SpClient, SpendKey};
use spdk_wallet::silentpayments::{
    SpVersion,
    receiving::{Label, Receiver},
    utils::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input},
};
use spdk_wallet::updater::DiscoveredOutput;

pub(super) const ID: &str = "spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7";

fn key(scalar: u8) -> Result<SecretKey, &'static str> {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    SecretKey::from_slice(&bytes).map_err(|_| "Invalid fixed receiver key")
}

// Called only after the shared funding/parent/child authorization checks. SPDK
// receives public parent data and fixed receiver keys, never sender shares/tweaks.
fn discover(
    parent: &Psbt,
    scan_scalar: u8,
) -> Result<Vec<(OutPoint, DiscoveredOutput)>, &'static str> {
    let tx = Extractor::new(native_extractable_psbt(parent.clone()))
        .map_err(|_| "Parent is not finalized")?
        .extract_tx()
        .map_err(|_| "Cannot extract parent")?;
    let mut keys = Vec::new();
    let mut outpoints = Vec::new();
    for (input, metadata) in tx.input.iter().zip(&parent.inputs) {
        let prevout = metadata
            .witness_utxo
            .as_ref()
            .ok_or("Missing parent UTXO")?;
        let witness = input.witness.iter().map(|v| v.to_vec()).collect::<Vec<_>>();
        keys.push(
            get_pubkey_from_input(
                input.script_sig.as_bytes(),
                &witness,
                prevout.script_pubkey.as_bytes(),
            )
            .map_err(|_| "SPDK input classification failed")?
            .ok_or("SPDK input is not eligible")?,
        );
        outpoints.push(
            spdk_wallet::silentpayments::utils::OutPoint::from_txid_and_vout(
                input.previous_output.txid.to_string(),
                input.previous_output.vout,
            )
            .map_err(|_| "Invalid SPDK outpoint")?,
        );
    }
    let tweak_data = calculate_tweak_data(&keys.iter().collect::<Vec<_>>(), &outpoints)
        .map_err(|_| "SPDK input aggregation failed")?;
    let scan = key(scan_scalar)?;
    let spend = key(1)?.public_key(&Secp256k1::new());
    let receiver = Receiver::new(
        SpVersion::ZERO,
        scan.public_key(&Secp256k1::new()),
        spend,
        Label::new(scan, 0),
        spdk_wallet::silentpayments::Network::Regtest,
    )
    .map_err(|_| "Cannot create SPDK receiver")?;
    let outputs = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| psbt_v2::bitcoin::XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid Taproot output key")?;
    let matches = receiver
        .scan_transaction(&calculate_ecdh_shared_secret(&tweak_data, &scan), &outputs)
        .map_err(|_| "SPDK discovery failed")?;
    let txid = tx.compute_txid();
    let mut discovered = Vec::new();
    for (label, matches) in matches {
        if label.is_some() {
            return Err("Labeled outputs are outside this fixture");
        }
        for (output_key, tweak) in matches {
            let script = ScriptBuf::new_p2tr_tweaked(output_key.dangerous_assume_tweaked());
            let positions = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| o.script_pubkey == script)
                .collect::<Vec<_>>();
            if positions.len() != 1 {
                return Err("SPDK output is not unique");
            }
            let (vout, output) = positions[0];
            discovered.push((
                OutPoint::new(txid, vout as u32),
                DiscoveredOutput {
                    tweak,
                    value: output.value,
                    script_pubkey: script,
                    label: None,
                },
            ));
        }
    }
    discovered.sort_by_key(|(outpoint, _)| outpoint.vout);
    Ok(discovered)
}

pub(super) fn spend(
    parent: &Psbt,
    mut child: Psbt,
) -> Result<(Psbt, Psbt, Transaction, Vec<String>), SilentPaymentSpendError> {
    let fail = |message| SilentPaymentSpendError::new("silent_payment.spdk_invalid", message);
    let found = discover(parent, 2).map_err(fail)?;
    if found.len() != 2 || child.inputs.len() != 2 {
        return Err(fail("SPDK must discover both recipient outputs"));
    }
    let mut selected = Vec::new();
    let mut output_keys = Vec::new();
    for input in &child.inputs {
        let outpoint = OutPoint::new(input.previous_txid, input.spent_output_index);
        let (_, output) = found
            .iter()
            .find(|(p, _)| *p == outpoint)
            .ok_or_else(|| fail("Child output was not discovered by SPDK"))?;
        if input
            .unknowns
            .get(&raw::Key {
                type_value: BIP376_TWEAK_TYPE,
                key: vec![],
            })
            .map(Vec::as_slice)
            != Some(output.tweak.to_be_bytes().as_slice())
            || input.witness_utxo.as_ref()
                != Some(&TxOut {
                    value: output.value,
                    script_pubkey: output.script_pubkey.clone(),
                })
        {
            return Err(fail("SPDK discovery disagrees with child tweak or value"));
        }
        output_keys.push(output.script_pubkey.as_bytes()[2..].to_lower_hex_string());
        selected.push((outpoint, output.clone()));
    }
    let wallet = SpClient::new(
        key(2).map_err(fail)?,
        SpendKey::Secret(key(1).map_err(fail)?),
        Network::Regtest,
    )
    .map_err(|_| fail("Cannot create SPDK wallet"))?;
    let partial_secret = wallet
        .partial_secret_for_selected_utxos(&selected)
        .map_err(|_| fail("SPDK input selection failed"))?;
    let unsigned_tx = Signer::new(child.clone())
        .map_err(|_| fail("Invalid child locktime"))?
        .unsigned_tx();
    let signed = wallet
        .sign_transaction(
            SilentPaymentUnsignedTransaction {
                selected_utxos: selected,
                recipients: vec![],
                partial_secret,
                unsigned_tx: Some(unsigned_tx),
                network: Network::Regtest,
            },
            &[0; 32],
        )
        .map_err(|_| fail("SPDK signing failed"))?;
    if signed.input.len() != child.inputs.len() {
        return Err(fail("Unexpected SPDK input count"));
    }
    for (input, signed_input) in child.inputs.iter_mut().zip(&signed.input) {
        if signed_input.witness.len() != 1 {
            return Err(fail("Unexpected SPDK witness"));
        }
        input.tap_key_sig = Some(
            taproot::Signature::from_slice(
                signed_input
                    .witness
                    .nth(0)
                    .ok_or_else(|| fail("Missing SPDK signature"))?,
            )
            .map_err(|_| fail("Invalid SPDK signature"))?,
        );
    }
    finalize_silent_payment_spend(child, output_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spdk_discovers_from_public_inputs_and_wrong_scan_key_finds_nothing() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/multi-output.json")).unwrap();
        for variant in fixture["variants"].as_array().unwrap() {
            let parent = parse_psbt(variant["output"]["finalizedPsbt"].as_str().unwrap())
                .unwrap()
                .psbt;
            let found = discover(&parent, 2).unwrap();
            assert_eq!(found.len(), 2);
            assert!(discover(&parent, 3).unwrap().is_empty());
            assert_eq!(
                found.iter().map(|(_, o)| o.value.to_sat()).sum::<u64>(),
                128_000
            );
        }
    }
}
