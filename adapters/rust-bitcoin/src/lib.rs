use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource};
use bitcoin::hashes::Hash;
use bitcoin::key::{PrivateKey, TapTweak};
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG};
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{PublicKey, ScriptBuf, Transaction, TxOut, Witness, ecdsa, taproot};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_COMMITMENTS_BYTES: usize = 4 * 1024;
const TEST_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const SCALAR_TWO_PUBLIC_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SCALAR_THREE_PUBLIC_KEY: &str =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const ALLOWED_FIXTURES: [&str; 11] = [
    "happy-path",
    "bdk-finalize-regression",
    "p2pkh",
    "p2wpkh",
    "intent-rich-p2wpkh",
    "p2sh-p2wsh-2-of-3",
    "p2wsh-2-of-3",
    "p2tr-keypath",
    "p2tr-scriptpath",
    "sighash-p2wpkh",
    "sighash-p2tr-keypath",
];

#[derive(Clone, Debug)]
pub struct FixtureCommitments {
    values: BTreeMap<String, [u8; 32]>,
    valid: bool,
}

impl Default for FixtureCommitments {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            valid: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureCommitmentError {
    InvalidConfiguration,
    Missing,
    Mismatch,
}

impl FixtureCommitments {
    pub fn from_json(raw: Option<&str>) -> Result<Self, &'static str> {
        let Some(raw) = raw else {
            return Ok(Self::default());
        };
        if raw.len() > MAX_COMMITMENTS_BYTES {
            return Err("fixture commitment configuration exceeds its size limit");
        }
        let object = serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .ok_or("fixture commitment configuration must be a JSON object")?;
        if object.len() > ALLOWED_FIXTURES.len() {
            return Err("fixture commitment configuration has too many entries");
        }
        let mut values = BTreeMap::new();
        for (fixture_id, value) in object {
            if !ALLOWED_FIXTURES.contains(&fixture_id.as_str()) {
                return Err("fixture commitment configuration has an unknown fixture");
            }
            let encoded = value
                .as_str()
                .ok_or("fixture commitment must be a string")?;
            values.insert(
                fixture_id,
                parse_commitment(encoded).ok_or("fixture commitment is invalid")?,
            );
        }
        Ok(Self {
            values,
            valid: true,
        })
    }

    pub fn invalid() -> Self {
        Self {
            values: BTreeMap::new(),
            valid: false,
        }
    }

    fn verify(&self, fixture_id: &str, psbt: &Psbt) -> Result<(), FixtureCommitmentError> {
        if !self.valid {
            return Err(FixtureCommitmentError::InvalidConfiguration);
        }
        let expected = self
            .values
            .get(fixture_id)
            .ok_or(FixtureCommitmentError::Missing)?;
        let transaction = bitcoin::consensus::serialize(&psbt.unsigned_tx);
        let actual: [u8; 32] = Sha256::digest(transaction).into();
        let difference = actual
            .iter()
            .zip(expected)
            .fold(0_u8, |accumulator, (left, right)| {
                accumulator | (left ^ right)
            });
        if difference == 0 {
            Ok(())
        } else {
            Err(FixtureCommitmentError::Mismatch)
        }
    }
}

fn parse_commitment(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    operation: String,
    payload: Map<String, Value>,
}

fn implementation(digest: &str) -> Value {
    json!({
        "name": "rust-bitcoin",
        "version": env!("CARGO_PKG_VERSION"),
        "artifactDigest": digest,
        "sourceRevision": "bitcoin-crate-0.32.102"
    })
}

fn success(id: &str, digest: &str, output: Value) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": id,
        "status": "ok",
        "implementation": implementation(digest),
        "output": output
    })
}

fn failure(id: &str, digest: &str, status: &str, class: &str, message: &str) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": id,
        "status": status,
        "implementation": implementation(digest),
        "error": {
            "class": class,
            "message": message,
            "retryable": false
        }
    })
}

fn safe_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
    })
}

fn fallback_id(value: &Value) -> &str {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| safe_id(id))
        .unwrap_or("invalid-1")
}

fn exact_fields(payload: &Map<String, Value>, fields: &[&str]) -> bool {
    let expected: BTreeSet<&str> = fields.iter().copied().collect();
    let actual: BTreeSet<&str> = payload.keys().map(String::as_str).collect();
    actual == expected
}

fn payload_string<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn decode_psbt_bytes(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() > 4 * 1024 * 1024 * 4 / 3 + 4 {
        return Err("PSBT exceeds the encoded adapter limit".to_owned());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "PSBT is not valid base64".to_owned())?;
    if bytes.len() > 4 * 1024 * 1024 || STANDARD.encode(&bytes) != encoded {
        return Err("PSBT exceeds the 4 MiB adapter limit".to_owned());
    }
    Ok(bytes)
}

fn parse_psbt(encoded: &str) -> Result<(Vec<u8>, Psbt), String> {
    let bytes = decode_psbt_bytes(encoded)?;
    let psbt = Psbt::deserialize(&bytes).map_err(|error| format!("Invalid PSBT: {error}"))?;
    if psbt.version != 0 {
        return Err("The Rust signer supports PSBTv0 only".to_owned());
    }
    Ok((bytes, psbt))
}

fn native_parse(request: &Request, digest: &str) -> Value {
    if !exact_fields(&request.payload, &["psbt"]) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "native-parse expects only a psbt field",
        );
    }
    let Some(encoded) = payload_string(&request.payload, "psbt") else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "psbt must be a base64 string",
        );
    };
    let parsed = decode_psbt_bytes(encoded).and_then(|bytes| {
        Psbt::deserialize(&bytes).map_err(|error| format!("Invalid PSBT: {error}"))
    });
    match parsed {
        Ok(psbt) => success(
            &request.id,
            digest,
            json!({
                "nativeParser": "rust-bitcoin",
                "psbtVersion": psbt.version,
                "inputs": psbt.inputs.len(),
                "outputs": psbt.outputs.len()
            }),
        ),
        Err(_) => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.native_parse_failed",
            "rust-bitcoin rejected the PSBT",
        ),
    }
}

fn encoded_psbt(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

fn fixture_key() -> Result<(PrivateKey, PublicKey), String> {
    let private_key =
        PrivateKey::from_wif(TEST_WIF).map_err(|_| "Built-in fixture key is invalid".to_owned())?;
    let secp = Secp256k1::new();
    let public_key = private_key.public_key(&secp);
    Ok((private_key, public_key))
}

fn validate_fixture_payload<'a>(
    request: &'a Request,
    expected_fields: &[&str],
) -> Result<(&'a str, &'a str), (&'static str, &'static str)> {
    if !exact_fields(&request.payload, expected_fields) {
        return Err((
            "protocol.invalid_payload",
            "Payload has missing or unknown fields",
        ));
    }
    let network = payload_string(&request.payload, "network")
        .ok_or(("protocol.invalid_payload", "network must be a string"))?;
    if network != "regtest" {
        return Err((
            "policy.network_not_allowed",
            "Signing is restricted to regtest fixtures",
        ));
    }
    let fixture_id = payload_string(&request.payload, "fixtureId")
        .ok_or(("protocol.invalid_payload", "fixtureId must be a string"))?;
    if !ALLOWED_FIXTURES.contains(&fixture_id) {
        return Err(("policy.fixture_not_allowed", "Unknown signing fixture"));
    }
    let encoded = payload_string(&request.payload, "psbt")
        .ok_or(("protocol.invalid_payload", "psbt must be a base64 string"))?;
    Ok((encoded, fixture_id))
}

fn commitment_failure(
    request: &Request,
    digest: &str,
    commitments: &FixtureCommitments,
    fixture_id: &str,
    psbt: &Psbt,
) -> Option<Value> {
    match commitments.verify(fixture_id, psbt) {
        Ok(()) => None,
        Err(FixtureCommitmentError::InvalidConfiguration) => Some(failure(
            &request.id,
            digest,
            "crashed",
            "adapter.invalid_configuration",
            "Fixture commitment configuration is invalid",
        )),
        Err(FixtureCommitmentError::Missing) => Some(failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_commitment_missing",
            "The selected fixture has no run-scoped transaction commitment",
        )),
        Err(FixtureCommitmentError::Mismatch) => Some(failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_commitment_mismatch",
            "The PSBT does not match the selected run-scoped fixture transaction",
        )),
    }
}

fn expected_witness_script(public_key: &PublicKey) -> bitcoin::ScriptBuf {
    Builder::new()
        .push_key(public_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn expected_multisig_witness_script(public_key: &PublicKey) -> Result<ScriptBuf, String> {
    let scalar_two = SCALAR_TWO_PUBLIC_KEY
        .parse::<PublicKey>()
        .map_err(|_| "Built-in scalar-2 public key is invalid".to_owned())?;
    let scalar_three = SCALAR_THREE_PUBLIC_KEY
        .parse::<PublicKey>()
        .map_err(|_| "Built-in scalar-3 public key is invalid".to_owned())?;
    Ok(Builder::new()
        .push_int(2)
        .push_key(public_key)
        .push_key(&scalar_two)
        .push_key(&scalar_three)
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script())
}

fn scalar_two_private_key() -> Result<PrivateKey, String> {
    let mut bytes = [0_u8; 32];
    bytes[31] = 2;
    SecretKey::from_slice(&bytes)
        .map(|secret_key| PrivateKey::new(secret_key, bitcoin::NetworkKind::Test))
        .map_err(|_| "Built-in scalar-2 private key is invalid".to_owned())
}

fn expected_taproot_script_path(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<
    (
        ScriptBuf,
        XOnlyPublicKey,
        XOnlyPublicKey,
        ScriptBuf,
        ControlBlock,
        TapLeafHash,
    ),
    String,
> {
    let internal_key = Keypair::from_secret_key(secp, &fixture_key()?.0.inner)
        .x_only_public_key()
        .0;
    let leaf_private_key = scalar_two_private_key()?;
    let leaf_key = Keypair::from_secret_key(secp, &leaf_private_key.inner)
        .x_only_public_key()
        .0;
    let leaf_script = Builder::new()
        .push_x_only_key(&leaf_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .map_err(|error| format!("Built-in Taproot leaf is invalid: {error}"))?
        .finalize(secp, internal_key)
        .map_err(|_| "Built-in Taproot tree is incomplete".to_owned())?;
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| "Built-in Taproot control block is unavailable".to_owned())?;
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    Ok((
        ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        internal_key,
        leaf_key,
        leaf_script,
        control_block,
        leaf_hash,
    ))
}

#[derive(Clone, Debug)]
enum SigningProfile {
    P2pkh {
        script_pubkey: ScriptBuf,
    },
    P2wpkh {
        script_pubkey: ScriptBuf,
    },
    P2wsh {
        script_pubkey: ScriptBuf,
        redeem_script: Option<ScriptBuf>,
        witness_script: ScriptBuf,
    },
    P2trKeypath {
        script_pubkey: ScriptBuf,
        internal_key: XOnlyPublicKey,
    },
    P2trScriptpath {
        script_pubkey: ScriptBuf,
        internal_key: XOnlyPublicKey,
        leaf_key: XOnlyPublicKey,
        leaf_script: ScriptBuf,
        control_block: Box<ControlBlock>,
        leaf_hash: TapLeafHash,
        leaf_private_key: PrivateKey,
    },
}

fn permits_taproot_scriptpath_origins(
    input: &bitcoin::psbt::Input,
    internal_key: XOnlyPublicKey,
    leaf_key: XOnlyPublicKey,
    leaf_hash: TapLeafHash,
) -> bool {
    if input.tap_key_origins.is_empty() {
        return true;
    }
    if input.tap_key_origins.len() != 2 {
        return false;
    }
    let Some((internal_hashes, _)) = input.tap_key_origins.get(&internal_key) else {
        return false;
    };
    let Some((leaf_hashes, _)) = input.tap_key_origins.get(&leaf_key) else {
        return false;
    };
    internal_hashes.is_empty() && leaf_hashes.as_slice() == [leaf_hash]
}

fn key_source(public_key: &PublicKey) -> KeySource {
    let hash = public_key.pubkey_hash().to_byte_array();
    (
        Fingerprint::from([hash[0], hash[1], hash[2], hash[3]]),
        DerivationPath::master(),
    )
}

fn permits_bip32_origins(input: &bitcoin::psbt::Input, public_keys: &[PublicKey]) -> bool {
    input.bip32_derivation.is_empty()
        || (input.bip32_derivation.len() == public_keys.len()
            && public_keys.iter().all(|public_key| {
                input.bip32_derivation.get(&public_key.inner) == Some(&key_source(public_key))
            }))
}

fn multisig_public_keys(public_key: &PublicKey) -> Result<[PublicKey; 3], String> {
    let scalar_two = SCALAR_TWO_PUBLIC_KEY
        .parse::<PublicKey>()
        .map_err(|_| "Built-in scalar-2 public key is invalid".to_owned())?;
    let scalar_three = SCALAR_THREE_PUBLIC_KEY
        .parse::<PublicKey>()
        .map_err(|_| "Built-in scalar-3 public key is invalid".to_owned())?;
    Ok([*public_key, scalar_two, scalar_three])
}

impl SigningProfile {
    fn for_fixture(
        fixture_id: &str,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Self, String> {
        match fixture_id {
            "happy-path" | "bdk-finalize-regression" => {
                let witness_script = expected_witness_script(public_key);
                Ok(Self::P2wsh {
                    script_pubkey: witness_script.to_p2wsh(),
                    redeem_script: None,
                    witness_script,
                })
            }
            "p2pkh" => Ok(Self::P2pkh {
                script_pubkey: ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
            }),
            "p2wpkh" | "intent-rich-p2wpkh" | "sighash-p2wpkh" => Ok(Self::P2wpkh {
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &public_key
                        .wpubkey_hash()
                        .map_err(|_| "Built-in fixture key must be compressed".to_owned())?,
                ),
            }),
            "p2wsh-2-of-3" => {
                let witness_script = expected_multisig_witness_script(public_key)?;
                Ok(Self::P2wsh {
                    script_pubkey: witness_script.to_p2wsh(),
                    redeem_script: None,
                    witness_script,
                })
            }
            "p2sh-p2wsh-2-of-3" => {
                let witness_script = expected_multisig_witness_script(public_key)?;
                let redeem_script = witness_script.to_p2wsh();
                Ok(Self::P2wsh {
                    script_pubkey: redeem_script.to_p2sh(),
                    redeem_script: Some(redeem_script),
                    witness_script,
                })
            }
            "p2tr-keypath" | "sighash-p2tr-keypath" => {
                let internal_key = Keypair::from_secret_key(secp, &private_key.inner)
                    .x_only_public_key()
                    .0;
                Ok(Self::P2trKeypath {
                    script_pubkey: ScriptBuf::new_p2tr(secp, internal_key, None),
                    internal_key,
                })
            }
            "p2tr-scriptpath" => {
                let (script_pubkey, internal_key, leaf_key, leaf_script, control_block, leaf_hash) =
                    expected_taproot_script_path(secp)?;
                Ok(Self::P2trScriptpath {
                    script_pubkey,
                    internal_key,
                    leaf_key,
                    leaf_script,
                    control_block: Box::new(control_block),
                    leaf_hash,
                    leaf_private_key: scalar_two_private_key()?,
                })
            }
            _ => Err("Unknown signing fixture".to_owned()),
        }
    }

    fn has_fixture_signature(&self, psbt: &Psbt, index: usize, public_key: &PublicKey) -> bool {
        match self {
            Self::P2pkh { .. } | Self::P2wpkh { .. } | Self::P2wsh { .. } => {
                psbt.inputs[index].partial_sigs.contains_key(public_key)
            }
            Self::P2trKeypath { .. } => psbt.inputs[index].tap_key_sig.is_some(),
            Self::P2trScriptpath {
                leaf_key,
                leaf_hash,
                ..
            } => psbt.inputs[index]
                .tap_script_sigs
                .contains_key(&(*leaf_key, *leaf_hash)),
        }
    }
}

fn validated_prevouts(psbt: &Psbt) -> Result<Vec<TxOut>, &'static str> {
    if psbt.inputs.is_empty() || psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err("PSBT has no signable fixture inputs");
    }

    let mut prevouts = Vec::with_capacity(psbt.inputs.len());
    for (index, input) in psbt.inputs.iter().enumerate() {
        let previous_output = &psbt.unsigned_tx.input[index].previous_output;
        let non_witness_output = if let Some(transaction) = input.non_witness_utxo.as_ref() {
            if transaction.compute_txid() != previous_output.txid {
                return Err("A non-witness UTXO does not match its PSBT previous-output txid");
            }
            Some(
                transaction
                    .output
                    .get(previous_output.vout as usize)
                    .ok_or("A non-witness UTXO does not contain the referenced output")?,
            )
        } else {
            None
        };
        let funding_output = match (input.witness_utxo.as_ref(), non_witness_output) {
            (Some(witness), Some(full)) if witness != full => {
                return Err("Witness and non-witness UTXO data disagree");
            }
            (Some(witness), _) => Some(witness),
            (None, full) => full,
        };
        prevouts.push(
            funding_output
                .ok_or("Every input must provide its referenced UTXO")?
                .clone(),
        );
    }
    Ok(prevouts)
}

fn expected_fixture_fee(fixture_id: &str) -> Option<u64> {
    match fixture_id {
        "p2pkh" => Some(10_500),
        "p2wpkh" => Some(11_000),
        "p2sh-p2wsh-2-of-3" => Some(12_500),
        "p2wsh-2-of-3" => Some(13_000),
        "p2tr-keypath" => Some(14_000),
        "p2tr-scriptpath" => Some(14_500),
        "intent-rich-p2wpkh" => Some(15_000),
        "sighash-p2wpkh" => Some(22_000),
        "sighash-p2tr-keypath" => Some(28_000),
        _ => None,
    }
}

fn validate_profile_signing_scope(
    psbt: &Psbt,
    profile: &SigningProfile,
    fixture_id: &str,
    public_key: &PublicKey,
) -> Result<Vec<TxOut>, &'static str> {
    let prevouts = validated_prevouts(psbt)?;
    if let Some(expected_fee) = expected_fixture_fee(fixture_id) {
        let input_value = prevouts
            .iter()
            .try_fold(0_u64, |total, output| {
                total.checked_add(output.value.to_sat())
            })
            .ok_or("Fixture input amount overflowed")?;
        let output_value = psbt
            .unsigned_tx
            .output
            .iter()
            .try_fold(0_u64, |total, output| {
                total.checked_add(output.value.to_sat())
            })
            .ok_or("Fixture output amount overflowed")?;
        if input_value.checked_sub(output_value) != Some(expected_fee) {
            return Err("PSBT funding amounts do not match the authorized fixture fee");
        }
    }
    for (input, funding_output) in psbt.inputs.iter().zip(&prevouts) {
        match profile {
            SigningProfile::P2pkh { script_pubkey } => {
                if &funding_output.script_pubkey != script_pubkey
                    || input.non_witness_utxo.is_none()
                    || input.witness_utxo.is_some()
                    || input.witness_script.is_some()
                    || input.redeem_script.is_some()
                    || !permits_bip32_origins(input, &[*public_key])
                {
                    return Err(
                        "Every P2PKH input must spend the exact scalar-1 non-witness fixture",
                    );
                }
                if input
                    .sighash_type
                    .is_some_and(|sighash_type| sighash_type != EcdsaSighashType::All.into())
                {
                    return Err("P2PKH fixture inputs require SIGHASH_ALL");
                }
            }
            SigningProfile::P2wpkh { script_pubkey } => {
                if &funding_output.script_pubkey != script_pubkey
                    || input.witness_script.is_some()
                    || input.redeem_script.is_some()
                    || !permits_bip32_origins(input, &[*public_key])
                {
                    return Err("Every P2WPKH input must spend the exact scalar-1 fixture script");
                }
                let valid_sighash = if fixture_id == "sighash-p2wpkh" {
                    input.ecdsa_hash_ty().is_ok()
                } else {
                    input
                        .sighash_type
                        .is_none_or(|sighash_type| sighash_type == EcdsaSighashType::All.into())
                };
                if !valid_sighash {
                    return Err("P2WPKH fixture inputs require SIGHASH_ALL");
                }
            }
            SigningProfile::P2wsh {
                script_pubkey,
                redeem_script,
                witness_script,
            } => {
                if &funding_output.script_pubkey != script_pubkey
                    || input.witness_script.as_ref() != Some(witness_script)
                    || input.redeem_script.as_ref() != redeem_script.as_ref()
                {
                    return Err(
                        "Every P2WSH input must spend its exact fixture redeem and witness scripts",
                    );
                }
                if fixture_id != "happy-path" && fixture_id != "bdk-finalize-regression" {
                    let public_keys =
                        multisig_public_keys(public_key).map_err(|_| "Fixture keys are invalid")?;
                    if !permits_bip32_origins(input, &public_keys) {
                        return Err("P2WSH BIP32 origins do not match the fixture keys");
                    }
                }
                if input
                    .sighash_type
                    .is_some_and(|sighash_type| sighash_type != EcdsaSighashType::All.into())
                {
                    return Err("P2WSH fixture inputs require SIGHASH_ALL");
                }
            }
            SigningProfile::P2trKeypath {
                script_pubkey,
                internal_key,
            } => {
                let has_script_path_origin = input
                    .tap_key_origins
                    .values()
                    .any(|(leaf_hashes, _)| !leaf_hashes.is_empty());
                if &funding_output.script_pubkey != script_pubkey
                    || input.tap_internal_key != Some(*internal_key)
                    || input.tap_merkle_root.is_some()
                    || !input.tap_scripts.is_empty()
                    || !input.tap_script_sigs.is_empty()
                    || has_script_path_origin
                    || input.witness_script.is_some()
                    || input.redeem_script.is_some()
                    || !input.bip32_derivation.is_empty()
                {
                    return Err("Every Taproot input must be the exact scalar-1 key-path fixture");
                }
                let valid_sighash = if fixture_id == "sighash-p2tr-keypath" {
                    input.taproot_hash_ty().is_ok()
                } else {
                    input
                        .sighash_type
                        .is_none_or(|sighash_type| sighash_type == TapSighashType::Default.into())
                };
                if !valid_sighash {
                    return Err("Taproot key-path fixture inputs require SIGHASH_DEFAULT");
                }
            }
            SigningProfile::P2trScriptpath {
                script_pubkey,
                internal_key,
                leaf_key,
                leaf_script,
                control_block,
                leaf_hash,
                ..
            } => {
                let exact_leaf = input.tap_scripts.len() == 1
                    && input.tap_scripts.get(control_block.as_ref())
                        == Some(&(leaf_script.clone(), LeafVersion::TapScript));
                let exact_signatures = input
                    .tap_script_sigs
                    .keys()
                    .all(|key| key == &(*leaf_key, *leaf_hash));
                let exact_origins =
                    permits_taproot_scriptpath_origins(input, *internal_key, *leaf_key, *leaf_hash);
                let exact_merkle_root = input
                    .tap_merkle_root
                    .is_none_or(|root| root == bitcoin::TapNodeHash::from(*leaf_hash));
                if &funding_output.script_pubkey != script_pubkey {
                    return Err("Taproot script-path funding script does not match the fixture");
                }
                if input.tap_internal_key != Some(*internal_key) {
                    return Err("Taproot script-path internal key does not match the fixture");
                }
                if !exact_merkle_root {
                    return Err("Taproot script-path merkle root does not match the fixture leaf");
                }
                if !exact_origins {
                    return Err("Taproot script-path key origins do not match the fixture keys");
                }
                if !exact_leaf {
                    return Err(
                        "Taproot script-path leaf or control block does not match the fixture",
                    );
                }
                if !exact_signatures
                    || input.tap_key_sig.is_some()
                    || !input.partial_sigs.is_empty()
                {
                    return Err("Taproot script-path input contains an unexpected signature");
                }
                if input.witness_script.is_some() || input.redeem_script.is_some() {
                    return Err("Taproot script-path input contains legacy script metadata");
                }
                if !input.bip32_derivation.is_empty() {
                    return Err("Taproot script-path input contains legacy BIP32 origins");
                }
                if input
                    .sighash_type
                    .is_some_and(|sighash_type| sighash_type != TapSighashType::Default.into())
                {
                    return Err("Taproot script-path fixture inputs require SIGHASH_DEFAULT");
                }
            }
        }
    }
    Ok(prevouts)
}

fn validate_legacy_finalization_scope(
    psbt: &Psbt,
    public_key: &PublicKey,
) -> Result<(), &'static str> {
    let prevouts = validated_prevouts(psbt)?;
    let expected_script = expected_witness_script(public_key);
    let expected_script_pubkey = expected_script.to_p2wsh();
    for (input, funding_output) in psbt.inputs.iter().zip(prevouts) {
        if input.witness_script.as_ref() != Some(&expected_script) {
            return Err("Every input must use the lab wsh(pk(fixture-key)) witness script");
        }
        if funding_output.script_pubkey != expected_script_pubkey {
            return Err("Every input must spend the lab fixture script");
        }
    }
    Ok(())
}

fn manually_sign_inputs(
    psbt: &mut Psbt,
    profile: &SigningProfile,
    prevouts: &[TxOut],
    input_indexes: &[usize],
    private_key: &PrivateKey,
    public_key: &PublicKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<usize, String> {
    let transaction = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&transaction);
    match profile {
        SigningProfile::P2pkh { script_pubkey } => {
            let mut signatures = Vec::with_capacity(input_indexes.len());
            for &index in input_indexes {
                let sighash_type = psbt.inputs[index]
                    .ecdsa_hash_ty()
                    .map_err(|error| format!("Input {index} ECDSA sighash is invalid: {error}"))?;
                let sighash = cache
                    .legacy_signature_hash(index, script_pubkey, sighash_type.to_u32())
                    .map_err(|error| format!("Input {index} P2PKH sighash failed: {error}"))?;
                signatures.push((
                    index,
                    ecdsa::Signature {
                        signature: secp.sign_ecdsa(&Message::from(sighash), &private_key.inner),
                        sighash_type,
                    },
                ));
            }
            for (index, signature) in signatures {
                psbt.inputs[index]
                    .partial_sigs
                    .insert(*public_key, signature);
            }
        }
        SigningProfile::P2wpkh { script_pubkey } => {
            let mut signatures = Vec::with_capacity(input_indexes.len());
            for &index in input_indexes {
                let sighash_type = psbt.inputs[index]
                    .ecdsa_hash_ty()
                    .map_err(|error| format!("Input {index} ECDSA sighash is invalid: {error}"))?;
                let sighash = cache
                    .p2wpkh_signature_hash(
                        index,
                        script_pubkey,
                        prevouts[index].value,
                        sighash_type,
                    )
                    .map_err(|error| format!("Input {index} P2WPKH sighash failed: {error}"))?;
                signatures.push((
                    index,
                    ecdsa::Signature {
                        signature: secp.sign_ecdsa(&Message::from(sighash), &private_key.inner),
                        sighash_type,
                    },
                ));
            }
            for (index, signature) in signatures {
                psbt.inputs[index]
                    .partial_sigs
                    .insert(*public_key, signature);
            }
        }
        SigningProfile::P2wsh { witness_script, .. } => {
            let mut signatures = Vec::with_capacity(input_indexes.len());
            for &index in input_indexes {
                let sighash_type = psbt.inputs[index]
                    .ecdsa_hash_ty()
                    .map_err(|error| format!("Input {index} ECDSA sighash is invalid: {error}"))?;
                let sighash = cache
                    .p2wsh_signature_hash(
                        index,
                        witness_script,
                        prevouts[index].value,
                        sighash_type,
                    )
                    .map_err(|error| format!("Input {index} P2WSH sighash failed: {error}"))?;
                signatures.push((
                    index,
                    ecdsa::Signature {
                        signature: secp.sign_ecdsa(&Message::from(sighash), &private_key.inner),
                        sighash_type,
                    },
                ));
            }
            for (index, signature) in signatures {
                psbt.inputs[index]
                    .partial_sigs
                    .insert(*public_key, signature);
            }
        }
        SigningProfile::P2trKeypath { .. } => {
            let keypair = Keypair::from_secret_key(secp, &private_key.inner)
                .tap_tweak(secp, None)
                .to_keypair();
            let mut signatures = Vec::with_capacity(input_indexes.len());
            for &index in input_indexes {
                let sighash_type = psbt.inputs[index].taproot_hash_ty().map_err(|error| {
                    format!("Input {index} Taproot sighash is invalid: {error}")
                })?;
                let sighash = cache
                    .taproot_key_spend_signature_hash(index, &Prevouts::All(prevouts), sighash_type)
                    .map_err(|error| format!("Input {index} Taproot sighash failed: {error}"))?;
                signatures.push((
                    index,
                    taproot::Signature {
                        signature: secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &keypair),
                        sighash_type,
                    },
                ));
            }
            for (index, signature) in signatures {
                psbt.inputs[index].tap_key_sig = Some(signature);
            }
        }
        SigningProfile::P2trScriptpath {
            leaf_key,
            leaf_hash,
            leaf_private_key,
            ..
        } => {
            let keypair = Keypair::from_secret_key(secp, &leaf_private_key.inner);
            let mut signatures = Vec::with_capacity(input_indexes.len());
            for &index in input_indexes {
                let sighash_type = psbt.inputs[index].taproot_hash_ty().map_err(|error| {
                    format!("Input {index} Taproot sighash is invalid: {error}")
                })?;
                let sighash = cache
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(prevouts),
                        *leaf_hash,
                        sighash_type,
                    )
                    .map_err(|error| {
                        format!("Input {index} Taproot script-path sighash failed: {error}")
                    })?;
                signatures.push((
                    index,
                    taproot::Signature {
                        signature: secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &keypair),
                        sighash_type,
                    },
                ));
            }
            for (index, signature) in signatures {
                psbt.inputs[index]
                    .tap_script_sigs
                    .insert((*leaf_key, *leaf_hash), signature);
            }
        }
    }

    Ok(input_indexes
        .iter()
        .filter(|&&index| profile.has_fixture_signature(psbt, index, public_key))
        .count())
}

fn sighash_signature_is_valid(
    psbt: &Psbt,
    profile: &SigningProfile,
    prevouts: &[TxOut],
    public_key: &PublicKey,
    transaction: &Transaction,
) -> bool {
    let input_index = 0;
    match profile {
        SigningProfile::P2wpkh { script_pubkey } => {
            let Some(signature) = psbt.inputs[input_index].partial_sigs.get(public_key) else {
                return false;
            };
            let Ok(sighash) = SighashCache::new(transaction).p2wpkh_signature_hash(
                input_index,
                script_pubkey,
                prevouts[input_index].value,
                signature.sighash_type,
            ) else {
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
        SigningProfile::P2trKeypath { internal_key, .. } => {
            let Some(signature) = psbt.inputs[input_index].tap_key_sig.as_ref() else {
                return false;
            };
            let Ok(sighash) = SighashCache::new(transaction).taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(prevouts),
                signature.sighash_type,
            ) else {
                return false;
            };
            let secp = Secp256k1::verification_only();
            let output_key = internal_key.tap_tweak(&secp, None).0.to_x_only_public_key();
            secp.verify_schnorr(&signature.signature, &Message::from(sighash), &output_key)
                .is_ok()
        }
        _ => false,
    }
}

fn sighash_mutation_checks(
    psbt: &Psbt,
    profile: &SigningProfile,
    prevouts: &[TxOut],
    public_key: &PublicKey,
) -> Option<Value> {
    if psbt.inputs.len() < 2
        || psbt.unsigned_tx.input.len() < 2
        || psbt.unsigned_tx.output.len() < 2
    {
        return None;
    }
    let verify = |transaction: &Transaction| {
        sighash_signature_is_valid(psbt, profile, prevouts, public_key, transaction)
    };

    let mut signed_input_sequence = psbt.unsigned_tx.clone();
    let sequence = signed_input_sequence.input[0].sequence.to_consensus_u32();
    signed_input_sequence.input[0].sequence = bitcoin::Sequence::from_consensus(sequence ^ 1);

    let mut other_input_outpoint = psbt.unsigned_tx.clone();
    other_input_outpoint.input[1].previous_output.vout ^= 1;

    let mut other_input_sequence = psbt.unsigned_tx.clone();
    let sequence = other_input_sequence.input[1].sequence.to_consensus_u32();
    other_input_sequence.input[1].sequence = bitcoin::Sequence::from_consensus(sequence ^ 1);

    let output_value_valid = (0..psbt.unsigned_tx.output.len())
        .map(|index| {
            let mut transaction = psbt.unsigned_tx.clone();
            let value = transaction.output[index].value.to_sat();
            transaction.output[index].value = bitcoin::Amount::from_sat(value + 1);
            verify(&transaction)
        })
        .collect::<Vec<_>>();

    Some(json!({
        "signedInputSequenceValid": verify(&signed_input_sequence),
        "otherInputOutpointValid": verify(&other_input_outpoint),
        "otherInputSequenceValid": verify(&other_input_sequence),
        "outputValueValid": output_value_valid
    }))
}

fn roundtrip(request: &Request, digest: &str) -> Value {
    if !exact_fields(&request.payload, &["psbt"]) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "roundtrip expects only a psbt field",
        );
    }
    let Some(encoded) = payload_string(&request.payload, "psbt") else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "psbt must be a base64 string",
        );
    };
    match parse_psbt(encoded) {
        Ok((bytes, psbt)) => {
            let serialized = psbt.serialize();
            success(
                &request.id,
                digest,
                json!({
                    "psbt": STANDARD.encode(&serialized),
                    "byteIdentical": serialized == bytes,
                    "psbtVersion": psbt.version
                }),
            )
        }
        Err(message) => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            &message,
        ),
    }
}

fn sign(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let has_input_indexes = request.payload.contains_key("inputIndexes");
    let has_sighash_type = request.payload.contains_key("sighashType");
    let expected_fields = match (has_input_indexes, has_sighash_type) {
        (true, true) => &[
            "psbt",
            "network",
            "fixtureId",
            "inputIndexes",
            "sighashType",
        ][..],
        (true, false) => &["psbt", "network", "fixtureId", "inputIndexes"][..],
        (false, true) => &["psbt", "network", "fixtureId", "sighashType"][..],
        (false, false) => &["psbt", "network", "fixtureId"][..],
    };
    let (encoded, fixture_id) = match validate_fixture_payload(request, expected_fields) {
        Ok(values) => values,
        Err((class, message)) => {
            return failure(&request.id, digest, "rejected", class, message);
        }
    };
    let (_, mut psbt) = match parse_psbt(encoded) {
        Ok(value) => value,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.parse_failed",
                &message,
            );
        }
    };
    let input_indexes = if has_input_indexes {
        match requested_input_indexes(&request.payload, psbt.inputs.len()) {
            Ok(indexes) => indexes,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "protocol.invalid_payload",
                    message,
                );
            }
        }
    } else {
        (0..psbt.inputs.len()).collect()
    };
    let requested_sighash_type = if has_sighash_type {
        match request
            .payload
            .get("sighashType")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
        {
            Some(value) => Some(value),
            None => {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "protocol.invalid_payload",
                    "sighashType must be an unsigned 32-bit integer",
                );
            }
        }
    } else {
        None
    };
    if let Some(response) = commitment_failure(request, digest, commitments, fixture_id, &psbt) {
        return response;
    }
    let (private_key, public_key) = match fixture_key() {
        Ok(value) => value,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "crashed",
                "adapter.fixture_key_invalid",
                &message,
            );
        }
    };
    let secp = Secp256k1::new();
    let profile = match SigningProfile::for_fixture(fixture_id, &public_key, &private_key, &secp) {
        Ok(profile) => profile,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "crashed",
                "adapter.fixture_key_invalid",
                &message,
            );
        }
    };
    if let Some(requested) = requested_sighash_type {
        let matches_psbt = input_indexes.iter().all(|&index| {
            let input = &psbt.inputs[index];
            match &profile {
                SigningProfile::P2trKeypath { .. } | SigningProfile::P2trScriptpath { .. } => input
                    .taproot_hash_ty()
                    .is_ok_and(|sighash_type| sighash_type as u32 == requested),
                _ => input
                    .ecdsa_hash_ty()
                    .is_ok_and(|sighash_type| sighash_type.to_u32() == requested),
            }
        });
        if !matches_psbt {
            return failure(
                &request.id,
                digest,
                "rejected",
                "policy.psbt_not_authorized",
                "Requested sighashType does not match every selected PSBT input",
            );
        }
    }
    let prevouts = match validate_profile_signing_scope(&psbt, &profile, fixture_id, &public_key) {
        Ok(prevouts) => prevouts,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "policy.psbt_not_authorized",
                message,
            );
        }
    };
    let signed_inputs = match manually_sign_inputs(
        &mut psbt,
        &profile,
        &prevouts,
        &input_indexes,
        &private_key,
        &public_key,
        &secp,
    ) {
        Ok(signed_inputs) => signed_inputs,
        Err(message) => {
            return failure(&request.id, digest, "rejected", "signing.failed", &message);
        }
    };
    if signed_inputs != input_indexes.len() {
        return failure(
            &request.id,
            digest,
            "rejected",
            "signing.no_matching_key",
            "The fixture key did not sign every selected input",
        );
    }
    let mutation_checks = if requested_sighash_type.is_some() {
        match sighash_mutation_checks(&psbt, &profile, &prevouts, &public_key) {
            Some(checks) => Some(checks),
            None => {
                return failure(
                    &request.id,
                    digest,
                    "crashed",
                    "adapter.mutation_evidence_unavailable",
                    "Sighash matrix fixture could not produce mutation evidence",
                );
            }
        }
    } else {
        None
    };
    let mut output = json!({
        "psbt": encoded_psbt(&psbt),
        "signedInputs": signed_inputs
    });
    if let Some(checks) = mutation_checks {
        output
            .as_object_mut()
            .expect("sign output is an object")
            .insert("mutationChecks".to_owned(), checks);
    }
    success(&request.id, digest, output)
}

fn finalize_inputs(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let (encoded, fixture_id) = match validate_fixture_payload(
        request,
        &["psbt", "network", "fixtureId", "inputIndexes"],
    ) {
        Ok(values) => values,
        Err((class, message)) => {
            return failure(&request.id, digest, "rejected", class, message);
        }
    };
    if fixture_id != "bdk-finalize-regression" && fixture_id != "p2tr-scriptpath" {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_not_allowed",
            "Selected-input finalization is not available for this fixture",
        );
    }
    let (_, mut psbt) = match parse_psbt(encoded) {
        Ok(value) => value,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.parse_failed",
                &message,
            );
        }
    };
    let input_indexes = match requested_input_indexes(&request.payload, psbt.inputs.len()) {
        Ok(indexes) => indexes,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                message,
            );
        }
    };
    if let Some(response) = commitment_failure(request, digest, commitments, fixture_id, &psbt) {
        return response;
    }
    if fixture_id == "p2tr-scriptpath" {
        let (private_key, public_key) = match fixture_key() {
            Ok(value) => value,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    "crashed",
                    "adapter.fixture_key_invalid",
                    &message,
                );
            }
        };
        let secp = Secp256k1::new();
        let profile =
            match SigningProfile::for_fixture(fixture_id, &public_key, &private_key, &secp) {
                Ok(profile) => profile,
                Err(message) => {
                    return failure(
                        &request.id,
                        digest,
                        "crashed",
                        "adapter.fixture_key_invalid",
                        &message,
                    );
                }
            };
        let prevouts =
            match validate_profile_signing_scope(&psbt, &profile, fixture_id, &public_key) {
                Ok(prevouts) => prevouts,
                Err(message) => {
                    return failure(
                        &request.id,
                        digest,
                        "rejected",
                        "policy.psbt_not_authorized",
                        message,
                    );
                }
            };
        let SigningProfile::P2trScriptpath {
            leaf_key,
            leaf_script,
            control_block,
            leaf_hash,
            ..
        } = profile
        else {
            unreachable!("fixture selected a Taproot script-path profile")
        };
        let mut final_witnesses = Vec::with_capacity(input_indexes.len());
        for &index in &input_indexes {
            let Some(signature) = psbt.inputs[index]
                .tap_script_sigs
                .get(&(leaf_key, leaf_hash))
                .cloned()
            else {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "finalize.missing_signature",
                    &format!("Input {index} does not contain the scalar-2 leaf signature"),
                );
            };
            let sighash = match SighashCache::new(&psbt.unsigned_tx)
                .taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    signature.sighash_type,
                ) {
                Ok(sighash) => sighash,
                Err(error) => {
                    return failure(
                        &request.id,
                        digest,
                        "rejected",
                        "finalize.signature_invalid",
                        &format!("Input {index} Taproot sighash failed: {error}"),
                    );
                }
            };
            if signature.sighash_type != TapSighashType::Default
                || secp
                    .verify_schnorr(&signature.signature, &Message::from(sighash), &leaf_key)
                    .is_err()
            {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "finalize.signature_invalid",
                    &format!("Input {index} contains an invalid scalar-2 leaf signature"),
                );
            }
            final_witnesses.push(Witness::from_slice(&[
                signature.to_vec(),
                leaf_script.as_bytes().to_vec(),
                control_block.serialize(),
            ]));
        }
        for (&index, witness) in input_indexes.iter().zip(final_witnesses) {
            let input = &mut psbt.inputs[index];
            input.final_script_witness = Some(witness);
            input.partial_sigs.clear();
            input.sighash_type = None;
            input.redeem_script = None;
            input.witness_script = None;
            input.bip32_derivation.clear();
            input.tap_key_sig = None;
            input.tap_script_sigs.clear();
            input.tap_scripts.clear();
            input.tap_key_origins.clear();
            input.tap_internal_key = None;
            input.tap_merkle_root = None;
        }
        return success(
            &request.id,
            digest,
            json!({
                "psbt": encoded_psbt(&psbt),
                "finalizedInputs": input_indexes,
                "remainingPartialInputs": psbt.inputs.iter().filter(|item| {
                    !item.partial_sigs.is_empty()
                        || item.tap_key_sig.is_some()
                        || !item.tap_script_sigs.is_empty()
                }).count()
            }),
        );
    }
    let (_, public_key) = match fixture_key() {
        Ok(value) => value,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "crashed",
                "adapter.fixture_key_invalid",
                &message,
            );
        }
    };
    if let Err(message) = validate_legacy_finalization_scope(&psbt, &public_key) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.psbt_not_authorized",
            message,
        );
    }
    let mut final_witnesses = Vec::with_capacity(input_indexes.len());
    for &index in &input_indexes {
        let input = &psbt.inputs[index];
        let Some(signature) = input.partial_sigs.get(&public_key).cloned() else {
            return failure(
                &request.id,
                digest,
                "rejected",
                "finalize.missing_signature",
                &format!("Input {index} does not contain the fixture signature"),
            );
        };
        let Some(witness_script) = input.witness_script.clone() else {
            return failure(
                &request.id,
                digest,
                "rejected",
                "finalize.missing_witness_script",
                &format!("Input {index} does not contain its fixture witness script"),
            );
        };
        final_witnesses.push(Witness::from_slice(&[
            signature.to_vec(),
            witness_script.as_bytes().to_vec(),
        ]));
    }

    for (&index, witness) in input_indexes.iter().zip(final_witnesses) {
        let input = &mut psbt.inputs[index];
        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation.clear();
    }

    success(
        &request.id,
        digest,
        json!({
            "psbt": encoded_psbt(&psbt),
            "finalizedInputs": input_indexes,
            "remainingPartialInputs": psbt.inputs.iter().filter(|item| !item.partial_sigs.is_empty()).count()
        }),
    )
}

fn requested_input_indexes(
    payload: &Map<String, Value>,
    input_count: usize,
) -> Result<Vec<usize>, &'static str> {
    let values = payload
        .get("inputIndexes")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or("inputIndexes must be a non-empty array")?;
    let mut unique = BTreeSet::new();
    let mut indexes = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .as_u64()
            .filter(|index| *index <= MAX_SAFE_INTEGER)
            .ok_or("inputIndexes must contain non-negative safe integers")?;
        let index = usize::try_from(raw)
            .ok()
            .filter(|index| *index < input_count)
            .ok_or("inputIndexes contains an out-of-range input")?;
        if !unique.insert(index) {
            return Err("inputIndexes must not contain duplicates");
        }
        indexes.push(index);
    }
    Ok(indexes)
}

pub fn handle_value(value: Value, digest: &str) -> Value {
    let commitments = FixtureCommitments::from_json(None)
        .expect("an absent fixture commitment configuration is valid");
    handle_value_with_commitments(value, digest, &commitments)
}

pub fn handle_value_with_commitments(
    value: Value,
    digest: &str,
    commitments: &FixtureCommitments,
) -> Value {
    let fallback = fallback_id(&value).to_owned();
    let request: Request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(_) => {
            return failure(
                &fallback,
                digest,
                "rejected",
                "protocol.invalid_request",
                "Request does not match the adapter protocol",
            );
        }
    };
    if request.protocol != ADAPTER_PROTOCOL || !safe_id(&request.id) {
        return failure(
            &fallback,
            digest,
            "rejected",
            "protocol.invalid_request",
            "Unsupported protocol version or unsafe request id",
        );
    }

    match request.operation.as_str() {
        "hello" if exact_fields(&request.payload, &[]) => success(
            &request.id,
            digest,
            json!({
                "operations": ["hello", "native-parse", "roundtrip", "sign", "finalize-inputs"],
                "roles": ["parser", "signer", "finalizer"],
                "psbtVersions": [0],
                "scriptTypes": ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                "operationScriptTypes": {
                    "roundtrip": ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                    "sign": ["p2pkh", "p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                    "finalize-inputs": ["p2wsh", "p2tr-scriptpath"]
                },
                "features": [
                    "fixture-commitment-sha256",
                    "sighash-matrix-v1",
                    "adversarial-signer-inputs-v1"
                ]
            }),
        ),
        "hello" => failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "hello expects an empty payload",
        ),
        "native-parse" => native_parse(&request, digest),
        "roundtrip" => roundtrip(&request, digest),
        "sign" => sign(&request, digest, commitments),
        "finalize-inputs" => finalize_inputs(&request, digest, commitments),
        _ => failure(
            &request.id,
            digest,
            "unsupported",
            "operation.unsupported",
            "Operation is not implemented by the rust-bitcoin adapter",
        ),
    }
}
