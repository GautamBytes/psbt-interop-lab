use std::collections::BTreeSet;

use bdk_wallet::Wallet;
use bdk_wallet::bitcoin::key::{PrivateKey, TapTweak};
use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG};
use bdk_wallet::bitcoin::script::Builder;
use bdk_wallet::bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bdk_wallet::bitcoin::{Network, Psbt, PublicKey, ScriptBuf, TxOut, ecdsa, taproot};
use bdk_wallet::signer::{SignOptions, TapLeavesOptions};

const FIXTURE_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const SCALAR_TWO_PUBLIC_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SCALAR_THREE_PUBLIC_KEY: &str =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileKind {
    P2wpkh,
    P2wshSingle,
    P2wshMultisig,
    P2trKeypath,
}

#[derive(Clone, Debug)]
struct FixtureProfile {
    kind: ProfileKind,
    descriptor: String,
    script_pubkey: ScriptBuf,
    witness_script: Option<ScriptBuf>,
    fixture_public_key: PublicKey,
    allowed_public_keys: BTreeSet<PublicKey>,
    tap_internal_key: Option<XOnlyPublicKey>,
}

#[derive(Debug)]
pub(crate) enum WalletOperationError {
    Policy(&'static str),
    InvalidSignature(&'static str),
    Signing(String),
    Incomplete,
    Internal(String),
}

impl FixtureProfile {
    fn for_fixture(fixture_id: &str) -> Result<Self, WalletOperationError> {
        let private_key = PrivateKey::from_wif(FIXTURE_WIF)
            .map_err(|error| WalletOperationError::Internal(error.to_string()))?;
        let secp = Secp256k1::new();
        let fixture_public_key = private_key.public_key(&secp);
        let scalar_two = SCALAR_TWO_PUBLIC_KEY
            .parse::<PublicKey>()
            .map_err(|error| WalletOperationError::Internal(error.to_string()))?;
        let scalar_three = SCALAR_THREE_PUBLIC_KEY
            .parse::<PublicKey>()
            .map_err(|error| WalletOperationError::Internal(error.to_string()))?;

        let (kind, descriptor, script_pubkey, witness_script, tap_internal_key, allowed) =
            match fixture_id {
                "happy-path" | "bdk-finalize-regression" | "p2wsh-single-key" => {
                    let witness_script = Builder::new()
                        .push_key(&fixture_public_key)
                        .push_opcode(OP_CHECKSIG)
                        .into_script();
                    (
                        ProfileKind::P2wshSingle,
                        format!("wsh(pk({FIXTURE_WIF}))"),
                        witness_script.to_p2wsh(),
                        Some(witness_script),
                        None,
                        BTreeSet::from([fixture_public_key]),
                    )
                }
                "p2wpkh" | "intent-rich-p2wpkh" => (
                    ProfileKind::P2wpkh,
                    format!("wpkh({FIXTURE_WIF})"),
                    ScriptBuf::new_p2wpkh(
                        &fixture_public_key
                            .wpubkey_hash()
                            .map_err(|error| WalletOperationError::Internal(error.to_string()))?,
                    ),
                    None,
                    None,
                    BTreeSet::from([fixture_public_key]),
                ),
                "p2wsh-2-of-3" => {
                    let witness_script = Builder::new()
                        .push_int(2)
                        .push_key(&fixture_public_key)
                        .push_key(&scalar_two)
                        .push_key(&scalar_three)
                        .push_int(3)
                        .push_opcode(OP_CHECKMULTISIG)
                        .into_script();
                    (
                        ProfileKind::P2wshMultisig,
                        format!(
                            "wsh(multi(2,{FIXTURE_WIF},{SCALAR_TWO_PUBLIC_KEY},{SCALAR_THREE_PUBLIC_KEY}))"
                        ),
                        witness_script.to_p2wsh(),
                        Some(witness_script),
                        None,
                        BTreeSet::from([fixture_public_key, scalar_two, scalar_three]),
                    )
                }
                "p2tr-keypath" => {
                    let internal_key = Keypair::from_secret_key(&secp, &private_key.inner)
                        .x_only_public_key()
                        .0;
                    (
                        ProfileKind::P2trKeypath,
                        format!("tr({FIXTURE_WIF})"),
                        ScriptBuf::new_p2tr(&secp, internal_key, None),
                        None,
                        Some(internal_key),
                        BTreeSet::new(),
                    )
                }
                _ => return Err(WalletOperationError::Policy("Unknown signing fixture")),
            };

        Ok(Self {
            kind,
            descriptor,
            script_pubkey,
            witness_script,
            fixture_public_key,
            allowed_public_keys: allowed,
            tap_internal_key,
        })
    }

    fn wallet(&self) -> Result<Wallet, WalletOperationError> {
        Wallet::create_single(self.descriptor.clone())
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .map_err(|error| WalletOperationError::Internal(error.to_string()))
    }

    fn validate(&self, psbt: &Psbt) -> Result<(), WalletOperationError> {
        if psbt.inputs.is_empty() || psbt.inputs.len() != psbt.unsigned_tx.input.len() {
            return Err(WalletOperationError::Policy(
                "PSBT has no signable fixture inputs",
            ));
        }

        for (index, input) in psbt.inputs.iter().enumerate() {
            let funding = validated_funding_output(psbt, index)?;
            if funding.script_pubkey != self.script_pubkey || input.final_script_sig.is_some() {
                return Err(WalletOperationError::Policy(
                    "PSBT does not spend the selected fixture script",
                ));
            }
            let finalized = input.final_script_witness.is_some();
            if finalized
                && (!input.partial_sigs.is_empty()
                    || input.tap_key_sig.is_some()
                    || !input.tap_script_sigs.is_empty())
            {
                return Err(WalletOperationError::Policy(
                    "Finalized inputs must not retain partial signatures",
                ));
            }

            match self.kind {
                ProfileKind::P2wpkh => {
                    if input.witness_script.is_some()
                        || input.redeem_script.is_some()
                        || has_any_taproot_metadata(input)
                        || input
                            .sighash_type
                            .is_some_and(|value| value != EcdsaSighashType::All.into())
                        || input
                            .partial_sigs
                            .keys()
                            .any(|key| !self.allowed_public_keys.contains(key))
                    {
                        return Err(WalletOperationError::Policy(
                            "P2WPKH input metadata is outside the fixture policy",
                        ));
                    }
                }
                ProfileKind::P2wshSingle | ProfileKind::P2wshMultisig => {
                    if (!finalized && input.witness_script.as_ref() != self.witness_script.as_ref())
                        || input.redeem_script.is_some()
                        || has_any_taproot_metadata(input)
                        || input
                            .sighash_type
                            .is_some_and(|value| value != EcdsaSighashType::All.into())
                        || input
                            .partial_sigs
                            .keys()
                            .any(|key| !self.allowed_public_keys.contains(key))
                    {
                        return Err(WalletOperationError::Policy(
                            "P2WSH input metadata is outside the fixture policy",
                        ));
                    }
                    if finalized {
                        let witness = input.final_script_witness.as_ref().expect("checked above");
                        if witness.last()
                            != self.witness_script.as_ref().map(|script| script.as_bytes())
                        {
                            return Err(WalletOperationError::Policy(
                                "Finalized P2WSH witness does not match the fixture script",
                            ));
                        }
                    }
                }
                ProfileKind::P2trKeypath => {
                    let has_script_path_origin = input
                        .tap_key_origins
                        .values()
                        .any(|(leaf_hashes, _)| !leaf_hashes.is_empty());
                    if input.witness_script.is_some()
                        || input.redeem_script.is_some()
                        || !input.partial_sigs.is_empty()
                        || (!finalized && input.tap_internal_key != self.tap_internal_key)
                        || (finalized && input.tap_internal_key.is_some())
                        || input.tap_merkle_root.is_some()
                        || !input.tap_scripts.is_empty()
                        || !input.tap_script_sigs.is_empty()
                        || has_script_path_origin
                        || input
                            .sighash_type
                            .is_some_and(|value| value != TapSighashType::Default.into())
                    {
                        return Err(WalletOperationError::Policy(
                            "Taproot input metadata is outside the key-path fixture policy",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_signatures(&self, psbt: &Psbt) -> Result<(), WalletOperationError> {
        let prevouts = (0..psbt.inputs.len())
            .map(|index| validated_funding_output(psbt, index))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, input) in psbt.inputs.iter().enumerate() {
            if let Some(witness) = input.final_script_witness.as_ref() {
                if !self.verify_final_witness(psbt, &prevouts, index, witness) {
                    return Err(WalletOperationError::InvalidSignature(
                        "A finalized fixture witness contains an invalid signature",
                    ));
                }
                continue;
            }
            for (public_key, signature) in &input.partial_sigs {
                if !self.verify_ecdsa_signature(
                    psbt,
                    index,
                    &prevouts[index],
                    public_key,
                    signature,
                ) {
                    return Err(WalletOperationError::InvalidSignature(
                        "A partial fixture signature is invalid",
                    ));
                }
            }
            if let Some(signature) = input.tap_key_sig.as_ref()
                && !self.verify_taproot_signature(psbt, &prevouts, index, signature)
            {
                return Err(WalletOperationError::InvalidSignature(
                    "A Taproot key-path signature is invalid",
                ));
            }
        }
        Ok(())
    }

    fn verify_ecdsa_signature(
        &self,
        psbt: &Psbt,
        index: usize,
        funding: &TxOut,
        public_key: &PublicKey,
        signature: &ecdsa::Signature,
    ) -> bool {
        if signature.sighash_type != EcdsaSighashType::All
            || !self.allowed_public_keys.contains(public_key)
        {
            return false;
        }
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = match self.kind {
            ProfileKind::P2wpkh => cache
                .p2wpkh_signature_hash(
                    index,
                    &funding.script_pubkey,
                    funding.value,
                    signature.sighash_type,
                )
                .ok(),
            ProfileKind::P2wshSingle | ProfileKind::P2wshMultisig => cache
                .p2wsh_signature_hash(
                    index,
                    self.witness_script.as_ref().expect("P2WSH profile"),
                    funding.value,
                    signature.sighash_type,
                )
                .ok(),
            ProfileKind::P2trKeypath => return false,
        };
        let Some(sighash) = sighash else {
            return false;
        };
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from(sighash),
                &signature.signature,
                &public_key.inner,
            )
            .is_ok()
    }

    fn verify_taproot_signature(
        &self,
        psbt: &Psbt,
        prevouts: &[TxOut],
        index: usize,
        signature: &taproot::Signature,
    ) -> bool {
        if self.kind != ProfileKind::P2trKeypath
            || signature.sighash_type != TapSighashType::Default
        {
            return false;
        }
        let Ok(sighash) = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(prevouts),
            signature.sighash_type,
        ) else {
            return false;
        };
        let secp = Secp256k1::verification_only();
        let output_key = self
            .tap_internal_key
            .expect("Taproot profile")
            .tap_tweak(&secp, None)
            .0
            .to_x_only_public_key();
        secp.verify_schnorr(&signature.signature, &Message::from(sighash), &output_key)
            .is_ok()
    }

    fn verify_final_witness(
        &self,
        psbt: &Psbt,
        prevouts: &[TxOut],
        index: usize,
        witness: &bdk_wallet::bitcoin::Witness,
    ) -> bool {
        let items = witness.iter().collect::<Vec<_>>();
        match self.kind {
            ProfileKind::P2wpkh => {
                if items.len() != 2 {
                    return false;
                }
                let Ok(signature) = ecdsa::Signature::from_slice(items[0]) else {
                    return false;
                };
                let Ok(public_key) = PublicKey::from_slice(items[1]) else {
                    return false;
                };
                public_key == self.fixture_public_key
                    && self.verify_ecdsa_signature(
                        psbt,
                        index,
                        &prevouts[index],
                        &public_key,
                        &signature,
                    )
            }
            ProfileKind::P2wshSingle => {
                if items.len() != 2
                    || Some(items[1])
                        != self.witness_script.as_ref().map(|script| script.as_bytes())
                {
                    return false;
                }
                let Ok(signature) = ecdsa::Signature::from_slice(items[0]) else {
                    return false;
                };
                self.verify_ecdsa_signature(
                    psbt,
                    index,
                    &prevouts[index],
                    &self.fixture_public_key,
                    &signature,
                )
            }
            ProfileKind::P2wshMultisig => {
                if items.len() != 4
                    || !items[0].is_empty()
                    || Some(items[3])
                        != self.witness_script.as_ref().map(|script| script.as_bytes())
                {
                    return false;
                }
                let mut matched_keys = BTreeSet::new();
                for bytes in &items[1..3] {
                    let Ok(signature) = ecdsa::Signature::from_slice(bytes) else {
                        return false;
                    };
                    let Some(public_key) = self.allowed_public_keys.iter().find(|public_key| {
                        !matched_keys.contains(*public_key)
                            && self.verify_ecdsa_signature(
                                psbt,
                                index,
                                &prevouts[index],
                                public_key,
                                &signature,
                            )
                    }) else {
                        return false;
                    };
                    matched_keys.insert(*public_key);
                }
                matched_keys.len() == 2
            }
            ProfileKind::P2trKeypath => {
                if items.len() != 1 {
                    return false;
                }
                let Ok(signature) = taproot::Signature::from_slice(items[0]) else {
                    return false;
                };
                self.verify_taproot_signature(psbt, prevouts, index, &signature)
            }
        }
    }

    fn has_fixture_signature(&self, psbt: &Psbt, index: usize) -> bool {
        match self.kind {
            ProfileKind::P2wpkh | ProfileKind::P2wshSingle | ProfileKind::P2wshMultisig => psbt
                .inputs[index]
                .partial_sigs
                .contains_key(&self.fixture_public_key),
            ProfileKind::P2trKeypath => psbt.inputs[index].tap_key_sig.is_some(),
        }
    }
}

fn validated_funding_output(psbt: &Psbt, index: usize) -> Result<TxOut, WalletOperationError> {
    let input = &psbt.inputs[index];
    let previous_output = &psbt.unsigned_tx.input[index].previous_output;
    let non_witness = if let Some(transaction) = input.non_witness_utxo.as_ref() {
        if transaction.compute_txid() != previous_output.txid {
            return Err(WalletOperationError::Policy(
                "Non-witness UTXO does not match the previous-output txid",
            ));
        }
        Some(
            transaction
                .output
                .get(previous_output.vout as usize)
                .ok_or(WalletOperationError::Policy(
                    "Non-witness UTXO lacks the referenced output",
                ))?,
        )
    } else {
        None
    };
    match (input.witness_utxo.as_ref(), non_witness) {
        (Some(witness), Some(full)) if witness != full => Err(WalletOperationError::Policy(
            "Witness and non-witness UTXO data disagree",
        )),
        (Some(witness), _) => Ok(witness.clone()),
        (None, Some(full)) => Ok(full.clone()),
        (None, None) => Err(WalletOperationError::Policy(
            "Every fixture input must provide its referenced UTXO",
        )),
    }
}

fn has_any_taproot_metadata(input: &bdk_wallet::bitcoin::psbt::Input) -> bool {
    input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || !input.tap_scripts.is_empty()
        || !input.tap_key_origins.is_empty()
        || input.tap_internal_key.is_some()
        || input.tap_merkle_root.is_some()
}

fn signing_options() -> SignOptions {
    SignOptions {
        trust_witness_utxo: true,
        try_finalize: false,
        tap_leaves_options: TapLeavesOptions::None,
        ..SignOptions::default()
    }
}

fn finalizing_options() -> SignOptions {
    SignOptions {
        tap_leaves_options: TapLeavesOptions::None,
        ..SignOptions::default()
    }
}

pub(crate) fn sign(
    psbt: &mut Psbt,
    fixture_id: &str,
    input_indexes: &[usize],
) -> Result<usize, WalletOperationError> {
    let profile = FixtureProfile::for_fixture(fixture_id)?;
    profile.validate(psbt)?;
    profile.verify_signatures(psbt)?;
    if input_indexes
        .iter()
        .any(|index| *index >= psbt.inputs.len())
    {
        return Err(WalletOperationError::Policy(
            "Selected input is outside the PSBT",
        ));
    }

    let original_inputs = psbt.inputs.clone();
    let wallet = profile.wallet()?;
    wallet
        .sign(psbt, signing_options())
        .map_err(|error| WalletOperationError::Signing(error.to_string()))?;
    let selected = input_indexes.iter().copied().collect::<BTreeSet<_>>();
    for (index, original) in original_inputs.into_iter().enumerate() {
        if !selected.contains(&index) {
            psbt.inputs[index] = original;
        }
    }
    profile.validate(psbt)?;
    profile.verify_signatures(psbt)?;
    let signed = input_indexes
        .iter()
        .filter(|&&index| profile.has_fixture_signature(psbt, index))
        .count();
    if signed != input_indexes.len() {
        return Err(WalletOperationError::Signing(
            "The fixture key did not sign every selected input".to_owned(),
        ));
    }
    Ok(signed)
}

pub(crate) fn finalize(
    psbt: &mut Psbt,
    fixture_id: &str,
) -> Result<Vec<usize>, WalletOperationError> {
    let profile = FixtureProfile::for_fixture(fixture_id)?;
    profile.validate(psbt)?;
    profile.verify_signatures(psbt)?;
    let candidates = psbt
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| {
            input.final_script_sig.is_none() && input.final_script_witness.is_none()
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let wallet = profile.wallet()?;
    let complete = wallet
        .finalize_psbt(psbt, finalizing_options())
        .map_err(|error| WalletOperationError::Signing(error.to_string()))?;
    if !complete {
        return Err(WalletOperationError::Incomplete);
    }
    profile.validate(psbt)?;
    profile.verify_signatures(psbt)?;
    Ok(candidates
        .into_iter()
        .filter(|index| {
            psbt.inputs[*index].final_script_sig.is_some()
                || psbt.inputs[*index].final_script_witness.is_some()
        })
        .collect())
}
