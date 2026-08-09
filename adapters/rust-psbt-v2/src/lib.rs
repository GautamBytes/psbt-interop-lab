use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_v2::bitcoin::bip32::{DerivationPath, Fingerprint};
use psbt_v2::bitcoin::consensus;
use psbt_v2::bitcoin::hex::{DisplayHex as _, FromHex as _};
use psbt_v2::bitcoin::opcodes::all::OP_CHECKMULTISIG;
use psbt_v2::bitcoin::script::{Builder, PushBytesBuf};
use psbt_v2::bitcoin::secp256k1::{PublicKey as SecpPublicKey, Scalar, Secp256k1, SecretKey};
use psbt_v2::bitcoin::sighash::EcdsaSighashType;
use psbt_v2::bitcoin::{
    Amount, CompressedPublicKey, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence,
    Transaction, TxOut, Txid, Witness, absolute, transaction,
};
use psbt_v2::v2::{
    Constructor, Creator, DleqProof, Extractor, Finalizer, Input, InputsOnlyModifiable, Modifiable,
    Output, OutputsOnlyModifiable, Psbt, Signer, Updater,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const JSON_ENVELOPE_ALLOWANCE: usize = 4096;
const MAX_PSBT_BYTES: usize = (MAX_LINE_BYTES - JSON_ENVELOPE_ALLOWANCE) * 3 / 4;
const MAX_MAP_COUNT: usize = 4096;
const MAX_MAP_ENTRIES: usize = 16_384;
const MAX_COMMITMENTS_BYTES: usize = 4 * 1024;
const SOURCE_REVISION: &str = "rust-psbt/psbt-v2-0.3.0@8ca657c333b6b391f2501e8b31627ccbb6a67f66";
const ALLOWED_FIXTURES: [&str; 3] = ["p2wpkh", "intent-rich-p2wpkh", "p2wsh-2-of-3"];
const SCALAR_ONE_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const SCALAR_TWO_PUBLIC_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SCALAR_THREE_PUBLIC_KEY: &str =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const BIP375_FIXTURE_ID: &str = "bip375-valid-01";
const BIP375_FIXTURE_PSBT_SHA256: [u8; 32] = [
    0x5a, 0x9c, 0x02, 0xc4, 0xfc, 0x20, 0xcc, 0x1c, 0x22, 0xe8, 0x43, 0x3b, 0x01, 0x1e, 0x03, 0xbe,
    0x01, 0x54, 0x44, 0x21, 0xe4, 0x58, 0x4b, 0x7f, 0x05, 0xcc, 0x91, 0xa3, 0xcc, 0x14, 0x7d, 0xd5,
];
const BIP375_PRIVATE_KEY: [u8; 32] = [
    0x7e, 0x31, 0xee, 0xeb, 0x1a, 0xa2, 0x59, 0x7b, 0x6d, 0x63, 0xb3, 0x57, 0x54, 0x14, 0x61, 0xd7,
    0x5d, 0xda, 0xe7, 0x6b, 0x76, 0x03, 0xd2, 0x46, 0x19, 0xf5, 0xeb, 0xed, 0x9e, 0x88, 0xec, 0x31,
];
const BIP375_SCAN_KEY: [u8; 33] = [
    0x02, 0x7a, 0x48, 0x7f, 0xc1, 0x9f, 0xb7, 0x69, 0x87, 0x7b, 0x87, 0x42, 0xd6, 0xea, 0x18, 0x11,
    0x8f, 0x3c, 0x4e, 0x72, 0xb1, 0xea, 0x8c, 0x6d, 0xe6, 0x02, 0xa7, 0xad, 0x4a, 0x41, 0xdb, 0xe0,
    0x68,
];
const BIP375_AUX: [u8; 32] = [0x42; 32];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    operation: String,
    payload: Map<String, Value>,
}

fn default_true() -> bool {
    true
}

fn default_transaction_version() -> i32 {
    2
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum ConstructPayload {
    Create {
        #[serde(default = "default_true", rename = "inputsModifiable")]
        inputs_modifiable: bool,
        #[serde(default = "default_true", rename = "outputsModifiable")]
        outputs_modifiable: bool,
        #[serde(default, rename = "sighashSingle")]
        sighash_single: bool,
        #[serde(default = "default_transaction_version", rename = "transactionVersion")]
        transaction_version: i32,
        #[serde(default, rename = "fallbackLocktime")]
        fallback_locktime: u32,
    },
    AddInput {
        psbt: String,
        #[serde(rename = "previousTxid")]
        previous_txid: String,
        #[serde(rename = "outputIndex")]
        output_index: u32,
        sequence: Option<u32>,
        #[serde(rename = "requiredHeightLocktime")]
        required_height_locktime: Option<u32>,
        #[serde(rename = "requiredTimeLocktime")]
        required_time_locktime: Option<u32>,
    },
    AddOutput {
        psbt: String,
        #[serde(rename = "amountSats")]
        amount_sats: u64,
        #[serde(rename = "scriptHex")]
        script_hex: String,
    },
    RemoveInput {
        psbt: String,
        index: usize,
    },
    RemoveOutput {
        psbt: String,
        index: usize,
    },
    SetSequence {
        psbt: String,
        index: usize,
        sequence: u32,
    },
    Seal {
        psbt: String,
        scope: SealScope,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum SealScope {
    Inputs,
    Outputs,
    All,
}

struct ParsedPsbt {
    bytes: Vec<u8>,
    psbt: Psbt,
}

struct TransactionIdentity {
    transaction_id: String,
    bip370_unique_id: String,
    unsigned_tx_sha256: String,
}

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
        let actual = unsigned_tx_digest(psbt).ok_or(FixtureCommitmentError::Mismatch)?;
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

fn unsigned_tx_digest(psbt: &Psbt) -> Option<[u8; 32]> {
    let transaction = Signer::new(psbt.clone()).ok()?.unsigned_tx();
    Some(Sha256::digest(consensus::serialize(&transaction)).into())
}

fn transaction_identity(psbt: &Psbt) -> Option<TransactionIdentity> {
    let signer = Signer::new(psbt.clone()).ok()?;
    let bip370_unique_id = signer.id().ok()?.to_string();
    let transaction = signer.unsigned_tx();
    let transaction_id = transaction.compute_txid().to_string();
    let unsigned_tx_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(consensus::serialize(&transaction))
    );
    Some(TransactionIdentity {
        transaction_id,
        bip370_unique_id,
        unsigned_tx_sha256,
    })
}

fn implementation(digest: &str) -> Value {
    json!({
        "name": "rust-psbt-v2",
        "version": env!("CARGO_PKG_VERSION"),
        "artifactDigest": digest,
        "sourceRevision": SOURCE_REVISION
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

fn read_compact_size(bytes: &[u8], position: &mut usize) -> Option<u64> {
    let prefix = *bytes.get(*position)?;
    *position += 1;
    match prefix {
        0x00..=0xfc => Some(u64::from(prefix)),
        0xfd => {
            let raw = bytes.get(*position..position.checked_add(2)?)?;
            *position += 2;
            let value = u64::from(u16::from_le_bytes(raw.try_into().ok()?));
            (value >= 0xfd).then_some(value)
        }
        0xfe => {
            let raw = bytes.get(*position..position.checked_add(4)?)?;
            *position += 4;
            let value = u64::from(u32::from_le_bytes(raw.try_into().ok()?));
            (value > u64::from(u16::MAX)).then_some(value)
        }
        0xff => {
            let raw = bytes.get(*position..position.checked_add(8)?)?;
            *position += 8;
            let value = u64::from_le_bytes(raw.try_into().ok()?);
            (value > u64::from(u32::MAX)).then_some(value)
        }
    }
}

#[derive(Default)]
struct GlobalCounts {
    inputs: Option<usize>,
    outputs: Option<usize>,
}

fn count_value(raw: &[u8]) -> Option<usize> {
    let mut position = 0;
    let count = usize::try_from(read_compact_size(raw, &mut position)?).ok()?;
    (position == raw.len() && count <= MAX_MAP_COUNT).then_some(count)
}

fn read_map(bytes: &[u8], position: &mut usize, collect_counts: bool) -> Option<GlobalCounts> {
    let mut entries = 0;
    let mut counts = GlobalCounts::default();
    loop {
        let key_length = usize::try_from(read_compact_size(bytes, position)?).ok()?;
        if key_length == 0 {
            return Some(counts);
        }
        entries += 1;
        if entries > MAX_MAP_ENTRIES {
            return None;
        }
        let key_end = position.checked_add(key_length)?;
        let key = bytes.get(*position..key_end)?;
        *position = key_end;

        let value_length = usize::try_from(read_compact_size(bytes, position)?).ok()?;
        let value_end = position.checked_add(value_length)?;
        let value = bytes.get(*position..value_end)?;
        *position = value_end;

        if collect_counts && key.len() == 1 {
            match key[0] {
                0x04 => {
                    if counts.inputs.is_some() {
                        return None;
                    }
                    counts.inputs = Some(count_value(value)?);
                }
                0x05 => {
                    if counts.outputs.is_some() {
                        return None;
                    }
                    counts.outputs = Some(count_value(value)?);
                }
                _ => {}
            }
        }
    }
}

fn preflight_map_framing(bytes: &[u8]) -> bool {
    if bytes.get(0..5) != Some(b"psbt\xff") {
        return false;
    }
    let mut position = 5;
    let Some(global) = read_map(bytes, &mut position, true) else {
        return false;
    };
    let Some(input_count) = global.inputs else {
        return false;
    };
    let Some(output_count) = global.outputs else {
        return false;
    };
    let Some(map_count) = input_count.checked_add(output_count) else {
        return false;
    };
    for _ in 0..map_count {
        if read_map(bytes, &mut position, false).is_none() {
            return false;
        }
    }
    position == bytes.len()
}

fn decode_psbt(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() > MAX_LINE_BYTES - JSON_ENVELOPE_ALLOWANCE {
        return None;
    }
    let bytes = STANDARD.decode(encoded).ok()?;
    if bytes.len() > MAX_PSBT_BYTES || STANDARD.encode(&bytes) != encoded {
        return None;
    }
    preflight_map_framing(&bytes).then_some(bytes)
}

fn parse_psbt(encoded: &str) -> Option<ParsedPsbt> {
    let bytes = decode_psbt(encoded)?;
    let psbt = Psbt::deserialize(&bytes).ok()?;
    Some(ParsedPsbt { bytes, psbt })
}

fn silent_payment_fields(psbt: &Psbt) -> Value {
    json!({
        "globalEcdhShares": psbt.global.sp_ecdh_shares.len(),
        "globalDleqProofs": psbt.global.sp_dleq_proofs.len(),
        "inputEcdhShares": psbt.inputs.iter().map(|input| input.sp_ecdh_shares.len()).sum::<usize>(),
        "inputDleqProofs": psbt.inputs.iter().map(|input| input.sp_dleq_proofs.len()).sum::<usize>(),
        "outputsWithInfo": psbt.outputs.iter().filter(|output| output.sp_v0_info.is_some()).count(),
        "outputsWithLabel": psbt.outputs.iter().filter(|output| output.sp_v0_label.is_some()).count()
    })
}

fn psbt_payload(request: &Request) -> Option<&str> {
    if !exact_fields(&request.payload, &["psbt"]) {
        return None;
    }
    request.payload.get("psbt").and_then(Value::as_str)
}

fn payload_string<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn fixture_payload(request: &Request) -> Result<(&str, &str), (&'static str, &'static str)> {
    if !exact_fields(&request.payload, &["psbt", "network", "fixtureId"]) {
        return Err((
            "protocol.invalid_payload",
            "sign expects psbt, network, and fixtureId",
        ));
    }
    if payload_string(&request.payload, "network") != Some("regtest") {
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

fn fixture_key() -> Result<(PrivateKey, PublicKey), &'static str> {
    let private_key =
        PrivateKey::from_wif(SCALAR_ONE_WIF).map_err(|_| "Built-in fixture key is invalid")?;
    let public_key = private_key.public_key(&Secp256k1::new());
    Ok((private_key, public_key))
}

fn expected_multisig_witness_script(public_key: &PublicKey) -> Result<ScriptBuf, &'static str> {
    let scalar_two = PublicKey::from_str(SCALAR_TWO_PUBLIC_KEY)
        .map_err(|_| "Built-in scalar-2 public key is invalid")?;
    let scalar_three = PublicKey::from_str(SCALAR_THREE_PUBLIC_KEY)
        .map_err(|_| "Built-in scalar-3 public key is invalid")?;
    Ok(Builder::new()
        .push_int(2)
        .push_key(public_key)
        .push_key(&scalar_two)
        .push_key(&scalar_three)
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script())
}

fn validate_signing_scope(
    psbt: &Psbt,
    fixture_id: &str,
    public_key: &PublicKey,
) -> Result<(), &'static str> {
    if psbt.inputs.is_empty() {
        return Err("PSBT has no signable fixture inputs");
    }
    let expected_p2wpkh = ScriptBuf::new_p2wpkh(
        &public_key
            .wpubkey_hash()
            .map_err(|_| "Built-in fixture key must be compressed")?,
    );
    let expected_witness_script = expected_multisig_witness_script(public_key)?;
    for input in &psbt.inputs {
        if input
            .ecdsa_hash_ty()
            .map_err(|_| "Fixture inputs require a standard sighash")?
            != EcdsaSighashType::All
        {
            return Err("Fixture inputs require SIGHASH_ALL");
        }
        let funding = input
            .funding_utxo()
            .map_err(|_| "Every fixture input must provide its referenced UTXO")?;
        let valid = match fixture_id {
            "p2wpkh" | "intent-rich-p2wpkh" => {
                funding.script_pubkey == expected_p2wpkh
                    && input.witness_script.is_none()
                    && input.redeem_script.is_none()
            }
            "p2wsh-2-of-3" => {
                funding.script_pubkey == expected_witness_script.to_p2wsh()
                    && input.witness_script.as_ref() == Some(&expected_witness_script)
                    && input.redeem_script.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err("PSBT inputs do not match the authorized fixture script");
        }
    }
    Ok(())
}

fn native_sign(mut psbt: Psbt, fixture_id: &str) -> Result<(Psbt, usize), &'static str> {
    let (private_key, public_key) = fixture_key()?;
    validate_signing_scope(&psbt, fixture_id, &public_key)?;

    let mut inserted_origins = Vec::new();
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if let std::collections::btree_map::Entry::Vacant(entry) =
            input.bip32_derivations.entry(public_key)
        {
            entry.insert((Fingerprint::default(), DerivationPath::default()));
            inserted_origins.push(index);
        }
    }

    let mut keys = BTreeMap::new();
    keys.insert(public_key, private_key);
    let secp = Secp256k1::new();
    let signer = Signer::new(psbt).map_err(|_| "PSBT locktime cannot be determined")?;
    let (signed, signing_keys) = signer
        .sign(&keys, &secp)
        .map_err(|_| "Native signer could not sign every fixture input")?;
    let signed_inputs = signing_keys
        .values()
        .filter(|public_keys| public_keys.contains(&public_key))
        .count();
    if signed_inputs != signed.inputs.len() {
        return Err("Fixture key did not sign every input");
    }

    let mut signer = Signer::new(signed).map_err(|_| "Signed PSBT locktime is invalid")?;
    signer.ecdsa_clear_tx_modifiable(EcdsaSighashType::All);
    let mut signed = signer.psbt();
    for index in inserted_origins {
        signed.inputs[index].bip32_derivations.remove(&public_key);
    }
    Ok((signed, signed_inputs))
}

fn sign(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
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
            "PSBTv2 could not be parsed",
        );
    };
    if let Some(response) =
        commitment_failure(request, digest, commitments, fixture_id, &parsed.psbt)
    {
        return response;
    }
    match native_sign(parsed.psbt, fixture_id) {
        Ok((psbt, signed_inputs)) => success(
            &request.id,
            digest,
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "signedInputs": signed_inputs
            }),
        ),
        Err(message) => failure(&request.id, digest, "rejected", "signing.failed", message),
    }
}

fn combine(request: &Request, digest: &str) -> Value {
    if !exact_fields(&request.payload, &["psbts"]) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "combine expects only a psbts array",
        );
    }
    let Some(values) = request
        .payload
        .get("psbts")
        .and_then(Value::as_array)
        .filter(|values| (2..=16).contains(&values.len()))
    else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "psbts must contain between two and sixteen PSBTv2 strings",
        );
    };
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let Some(encoded) = value.as_str() else {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "psbts must contain only PSBTv2 strings",
            );
        };
        let Some(psbt) = parse_psbt(encoded).map(|parsed| parsed.psbt) else {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.parse_failed",
                "A combined PSBTv2 could not be parsed",
            );
        };
        parsed.push(psbt);
    }
    let mut psbts = parsed.into_iter();
    let mut combined = psbts.next().expect("bounded non-empty PSBT list");
    for source in psbts {
        combined = match combined.combine_with(source) {
            Ok(psbt) => psbt,
            Err(_) => {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "combine.incompatible_psbts",
                    "PSBTv2 sources do not describe the same transaction",
                );
            }
        };
    }
    let Some(identity) = transaction_identity(&combined) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.identity_failed",
            "Combined PSBTv2 identity could not be determined",
        );
    };
    success(
        &request.id,
        digest,
        json!({
            "psbt": STANDARD.encode(combined.serialize()),
            "combinedPsbtCount": values.len(),
            "bip370UniqueId": identity.bip370_unique_id
        }),
    )
}

fn native_finalization_preserves_intent(before: &Psbt, after: &Psbt) -> bool {
    let before_identity = transaction_identity(before);
    let after_identity = transaction_identity(after);
    before_identity
        .zip(after_identity)
        .is_some_and(|(before, after)| before.unsigned_tx_sha256 == after.unsigned_tx_sha256)
        && before
            .inputs
            .iter()
            .zip(&after.inputs)
            .all(|(before, after)| {
                before.sequence == after.sequence
                    && before.min_time == after.min_time
                    && before.min_height == after.min_height
                    && before.proprietaries == after.proprietaries
                    && before.unknowns == after.unknowns
            })
}

fn clear_non_final_fields(input: &mut Input) {
    input.partial_sigs.clear();
    input.sighash_type = None;
    input.redeem_script = None;
    input.witness_script = None;
    input.bip32_derivations.clear();
    input.ripemd160_preimages.clear();
    input.sha256_preimages.clear();
    input.hash160_preimages.clear();
    input.hash256_preimages.clear();
    input.tap_key_sig = None;
    input.tap_script_sigs.clear();
    input.tap_scripts.clear();
    input.tap_key_origins.clear();
    input.tap_internal_key = None;
    input.tap_merkle_root = None;
}

fn final_script_sig_is_empty(input: &Input) -> bool {
    input
        .final_script_sig
        .as_ref()
        .is_some_and(|script| script.is_empty())
}

fn input_has_final_script_data(input: &Input) -> bool {
    input.final_script_witness.is_some()
        || input
            .final_script_sig
            .as_ref()
            .is_some_and(|script| !script.is_empty())
}

fn finalized_input_count(psbt: &Psbt) -> usize {
    psbt.inputs
        .iter()
        .filter(|input| input_has_final_script_data(input))
        .count()
}

fn omit_empty_final_script_sigs(psbt: &mut Psbt) {
    for input in &mut psbt.inputs {
        if final_script_sig_is_empty(input) {
            input.final_script_sig = None;
        }
    }
}

fn native_extractable_psbt(mut psbt: Psbt) -> Psbt {
    for input in &mut psbt.inputs {
        if input.final_script_sig.is_none() && input.final_script_witness.is_some() {
            input.final_script_sig = Some(ScriptBuf::new());
        }
    }
    psbt
}

fn finalize_preserving_intent(
    mut psbt: Psbt,
    fixture_id: &str,
    public_key: &PublicKey,
) -> Result<Psbt, &'static str> {
    let witness_script = expected_multisig_witness_script(public_key)?;
    let scalar_two = PublicKey::from_str(SCALAR_TWO_PUBLIC_KEY)
        .map_err(|_| "Built-in scalar-2 public key is invalid")?;
    let scalar_three = PublicKey::from_str(SCALAR_THREE_PUBLIC_KEY)
        .map_err(|_| "Built-in scalar-3 public key is invalid")?;

    for input in &mut psbt.inputs {
        let witness = match fixture_id {
            "p2wpkh" | "intent-rich-p2wpkh" => {
                let signature = input
                    .partial_sigs
                    .get(public_key)
                    .ok_or("P2WPKH input lacks its fixture signature")?;
                Witness::from_slice(&[signature.to_vec(), public_key.to_bytes()])
            }
            "p2wsh-2-of-3" => {
                let mut signatures = Vec::new();
                for key in [public_key, &scalar_two, &scalar_three] {
                    if let Some(signature) = input.partial_sigs.get(key) {
                        signatures.push(signature.to_vec());
                    }
                }
                if signatures.len() < 2 {
                    return Err("2-of-3 input lacks two fixture signatures");
                }
                Witness::from_slice(&[
                    Vec::new(),
                    signatures[0].clone(),
                    signatures[1].clone(),
                    witness_script.as_bytes().to_vec(),
                ])
            }
            _ => return Err("Unknown finalization fixture"),
        };
        input.final_script_sig = Some(ScriptBuf::new());
        input.final_script_witness = Some(witness);
        clear_non_final_fields(input);
    }

    psbt.interpreter_check(&Secp256k1::verification_only())
        .map_err(|_| "Finalized PSBTv2 did not satisfy its fixture scripts")?;
    Ok(psbt)
}

fn finalize(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
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
            "PSBTv2 could not be parsed",
        );
    };
    if let Some(response) =
        commitment_failure(request, digest, commitments, fixture_id, &parsed.psbt)
    {
        return response;
    }
    let public_key = match fixture_key() {
        Ok((_, public_key)) => public_key,
        Err(message) => {
            return failure(
                &request.id,
                digest,
                "crashed",
                "adapter.fixture_key_invalid",
                message,
            );
        }
    };
    if let Err(message) = validate_signing_scope(&parsed.psbt, fixture_id, &public_key) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.psbt_not_authorized",
            message,
        );
    }
    let finalizer = match Finalizer::new(parsed.psbt.clone()) {
        Ok(finalizer) => finalizer,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "finalize.incomplete_psbt",
                "PSBTv2 does not contain enough valid data to finalize",
            );
        }
    };
    let secp = Secp256k1::verification_only();
    let native = finalizer.finalize(&secp).ok();
    let mut finalized = match native
        .filter(|candidate| native_finalization_preserves_intent(&parsed.psbt, candidate))
        .map(Ok)
        .unwrap_or_else(|| finalize_preserving_intent(parsed.psbt, fixture_id, &public_key))
    {
        Ok(psbt) => psbt,
        Err(message) => {
            return failure(&request.id, digest, "rejected", "finalize.failed", message);
        }
    };
    omit_empty_final_script_sigs(&mut finalized);
    let finalized_inputs = finalized_input_count(&finalized);
    success(
        &request.id,
        digest,
        json!({
            "psbt": STANDARD.encode(finalized.serialize()),
            "finalized": finalized_inputs == finalized.inputs.len(),
            "finalizedInputs": finalized_inputs
        }),
    )
}

fn extract(request: &Request, digest: &str) -> Value {
    let Some(encoded) = psbt_payload(request) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "extract expects only a psbt string field",
        );
    };
    let Some(parsed) = parse_psbt(encoded) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "PSBTv2 could not be parsed",
        );
    };
    let Some(identity) = transaction_identity(&parsed.psbt) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.identity_failed",
            "PSBTv2 transaction identity could not be determined",
        );
    };
    let extractor = match Extractor::new(native_extractable_psbt(parsed.psbt)) {
        Ok(extractor) => extractor,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "extract.not_finalized",
                "PSBTv2 must be fully finalized before extraction",
            );
        }
    };
    let transaction = match extractor.extract_tx() {
        Ok(transaction) => transaction,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "extract.failed",
                "Native PSBTv2 extraction failed",
            );
        }
    };
    success(
        &request.id,
        digest,
        json!({
            "transaction": consensus::serialize(&transaction).to_lower_hex_string(),
            "transactionId": transaction.compute_txid().to_string(),
            "witnessTransactionId": transaction.compute_wtxid().to_string(),
            "bip370UniqueId": identity.bip370_unique_id,
            "unsignedTxSha256": identity.unsigned_tx_sha256
        }),
    )
}

fn native_parse(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Some(encoded) => encoded,
        None => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "native-parse expects only a psbt string field",
            );
        }
    };
    match parse_psbt(encoded) {
        Some(parsed) => success(
            &request.id,
            digest,
            json!({
                "nativeParser": "rust-psbt-v2",
                "psbtVersion": 2,
                "inputs": parsed.psbt.inputs.len(),
                "outputs": parsed.psbt.outputs.len(),
                "silentPaymentFields": silent_payment_fields(&parsed.psbt)
            }),
        ),
        None => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.native_parse_failed",
            "rust-psbt rejected the PSBTv2 payload",
        ),
    }
}

fn inspect(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Some(encoded) => encoded,
        None => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "inspect expects only a psbt string field",
            );
        }
    };
    let Some(parsed) = parse_psbt(encoded) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "PSBTv2 could not be parsed",
        );
    };
    let finalized_inputs = parsed
        .psbt
        .inputs
        .iter()
        .filter(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some())
        .count();
    let partial_signature_inputs = parsed
        .psbt
        .inputs
        .iter()
        .filter(|input| {
            !input.partial_sigs.is_empty()
                || input.tap_key_sig.is_some()
                || !input.tap_script_sigs.is_empty()
        })
        .count();
    let Some(identity) = transaction_identity(&parsed.psbt) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.identity_failed",
            "PSBTv2 transaction identity could not be determined",
        );
    };
    success(
        &request.id,
        digest,
        json!({
            "psbtVersion": 2,
            "inputs": parsed.psbt.inputs.len(),
            "outputs": parsed.psbt.outputs.len(),
            "finalizedInputs": finalized_inputs,
            "partialSignatureInputs": partial_signature_inputs,
            "transactionId": identity.transaction_id,
            "unsignedTxSha256": identity.unsigned_tx_sha256,
            "bip370UniqueId": identity.bip370_unique_id,
            "transactionModifiableFlags": parsed.psbt.global.tx_modifiable_flags
        }),
    )
}

fn construct_payload(request: &Request) -> Option<ConstructPayload> {
    serde_json::from_value(Value::Object(request.payload.clone())).ok()
}

fn parsed_construct_psbt(encoded: &str) -> Option<Psbt> {
    parse_psbt(encoded).map(|parsed| parsed.psbt)
}

fn psbt_has_signatures(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
    })
}

fn canonical_lower_hex(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.len() / 2 <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn construct_success(request: &Request, digest: &str, psbt: Psbt) -> Value {
    let locktime = match psbt.determine_lock_time() {
        Ok(locktime) => locktime,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.locktime_conflict",
                "PSBTv2 input locktime requirements are incompatible",
            );
        }
    };
    let locktime_value = locktime.to_consensus_u32();
    let locktime_type = if locktime_value == 0 {
        "none"
    } else if locktime.is_block_height() {
        "height"
    } else {
        "time"
    };
    success(
        &request.id,
        digest,
        json!({
            "psbt": STANDARD.encode(psbt.serialize()),
            "psbtVersion": 2,
            "inputs": psbt.inputs.len(),
            "outputs": psbt.outputs.len(),
            "transactionModifiableFlags": psbt.global.tx_modifiable_flags,
            "locktime": locktime_value,
            "locktimeType": locktime_type
        }),
    )
}

fn construct_parse_failure(request: &Request, digest: &str) -> Value {
    failure(
        &request.id,
        digest,
        "rejected",
        "psbt.parse_failed",
        "PSBTv2 could not be parsed",
    )
}

fn reject_not_modifiable(request: &Request, digest: &str, scope: &str) -> Value {
    failure(
        &request.id,
        digest,
        "rejected",
        "psbt.not_modifiable",
        &format!("PSBTv2 {scope} are sealed"),
    )
}

fn reject_sighash_single_pairing(request: &Request, digest: &str) -> Value {
    failure(
        &request.id,
        digest,
        "rejected",
        "psbt.sighash_single_pairing",
        "Signed SIGHASH_SINGLE input/output pairing cannot be changed",
    )
}

struct ConstructInputArgs<'a> {
    encoded: &'a str,
    previous_txid: &'a str,
    output_index: u32,
    sequence: Option<u32>,
    required_height_locktime: Option<u32>,
    required_time_locktime: Option<u32>,
}

fn add_construct_input(request: &Request, digest: &str, input: ConstructInputArgs<'_>) -> Value {
    let ConstructInputArgs {
        encoded,
        previous_txid,
        output_index,
        sequence,
        required_height_locktime,
        required_time_locktime,
    } = input;
    if previous_txid.len() != 64
        || !previous_txid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "previousTxid must be 32-byte lowercase display-order hex",
        );
    }
    if required_height_locktime.is_some_and(|value| value == 0 || value >= 500_000_000)
        || required_time_locktime.is_some_and(|value| value < 500_000_000)
    {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "Required locktime is outside its BIP370 domain",
        );
    }
    let Some(psbt) = parsed_construct_psbt(encoded) else {
        return construct_parse_failure(request, digest);
    };
    if psbt.global.tx_modifiable_flags & 0x01 == 0 {
        return reject_not_modifiable(request, digest, "inputs");
    }
    if psbt.global.tx_modifiable_flags & 0x04 != 0 && psbt_has_signatures(&psbt) {
        return reject_sighash_single_pairing(request, digest);
    }
    let before_locktime = psbt.determine_lock_time().ok();
    let signed = psbt_has_signatures(&psbt);
    let outputs_modifiable = psbt.global.tx_modifiable_flags & 0x02 != 0;
    let Ok(txid) = Txid::from_str(previous_txid) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "previousTxid is not a valid transaction id",
        );
    };
    let mut input = Input::new(&OutPoint {
        txid,
        vout: output_index,
    });
    input.sequence = sequence.map(Sequence);
    input.min_height =
        required_height_locktime.and_then(|value| absolute::Height::from_consensus(value).ok());
    input.min_time =
        required_time_locktime.and_then(|value| absolute::Time::from_consensus(value).ok());

    let constructed = if outputs_modifiable {
        Constructor::<Modifiable>::new(psbt)
            .ok()
            .and_then(|constructor| constructor.input(input).psbt().ok())
    } else {
        Constructor::<InputsOnlyModifiable>::new(psbt)
            .ok()
            .and_then(|constructor| constructor.input(input).psbt().ok())
    };
    let Some(constructed) = constructed else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.locktime_conflict",
            "Input locktime requirements conflict with the existing PSBTv2",
        );
    };
    if signed && before_locktime != constructed.determine_lock_time().ok() {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.locktime_change_after_signature",
            "A signed PSBTv2 cannot change its selected locktime",
        );
    }
    construct_success(request, digest, constructed)
}

fn add_construct_output(
    request: &Request,
    digest: &str,
    encoded: &str,
    amount_sats: u64,
    script_hex: &str,
) -> Value {
    if amount_sats == 0 {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.zero_amount_unsupported",
            "The pinned psbt-v2 0.3.0 constructor cannot represent a zero-valued output",
        );
    }
    if amount_sats > 2_100_000_000_000_000 || !canonical_lower_hex(script_hex, 10_000) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "Output amount or script is outside the bounded constructor format",
        );
    }
    let Some(psbt) = parsed_construct_psbt(encoded) else {
        return construct_parse_failure(request, digest);
    };
    if psbt.global.tx_modifiable_flags & 0x02 == 0 {
        return reject_not_modifiable(request, digest, "outputs");
    }
    if psbt.global.tx_modifiable_flags & 0x04 != 0 && psbt_has_signatures(&psbt) {
        return reject_sighash_single_pairing(request, digest);
    }
    let inputs_modifiable = psbt.global.tx_modifiable_flags & 0x01 != 0;
    let script = ScriptBuf::from_bytes(
        Vec::<u8>::from_hex(script_hex).expect("canonical hex was validated"),
    );
    let output = Output::new(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: script,
    });
    let constructed = if inputs_modifiable {
        Constructor::<Modifiable>::new(psbt)
            .ok()
            .and_then(|constructor| constructor.output(output).psbt().ok())
    } else {
        Constructor::<OutputsOnlyModifiable>::new(psbt)
            .ok()
            .and_then(|constructor| constructor.output(output).psbt().ok())
    };
    match constructed {
        Some(psbt) => construct_success(request, digest, psbt),
        None => reject_not_modifiable(request, digest, "outputs"),
    }
}

fn construct(request: &Request, digest: &str) -> Value {
    let Some(payload) = construct_payload(request) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "construct payload does not match a supported action",
        );
    };

    match payload {
        ConstructPayload::Create {
            inputs_modifiable,
            outputs_modifiable,
            sighash_single,
            transaction_version,
            fallback_locktime,
        } => {
            if transaction_version < 2 {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "protocol.invalid_payload",
                    "transactionVersion must be at least 2",
                );
            }
            let mut creator = Creator::new()
                .transaction_version(transaction::Version(transaction_version))
                .fallback_lock_time(absolute::LockTime::from_consensus(fallback_locktime));
            if inputs_modifiable {
                creator = creator.inputs_modifiable();
            }
            if outputs_modifiable {
                creator = creator.outputs_modifiable();
            }
            if sighash_single {
                creator = creator.sighash_single();
            }
            construct_success(request, digest, creator.psbt())
        }
        ConstructPayload::AddInput {
            psbt,
            previous_txid,
            output_index,
            sequence,
            required_height_locktime,
            required_time_locktime,
        } => add_construct_input(
            request,
            digest,
            ConstructInputArgs {
                encoded: &psbt,
                previous_txid: &previous_txid,
                output_index,
                sequence,
                required_height_locktime,
                required_time_locktime,
            },
        ),
        ConstructPayload::AddOutput {
            psbt,
            amount_sats,
            script_hex,
        } => add_construct_output(request, digest, &psbt, amount_sats, &script_hex),
        ConstructPayload::RemoveInput { psbt, index } => {
            let Some(mut psbt) = parsed_construct_psbt(&psbt) else {
                return construct_parse_failure(request, digest);
            };
            if psbt.global.tx_modifiable_flags & 0x01 == 0 {
                return reject_not_modifiable(request, digest, "inputs");
            }
            if psbt.global.tx_modifiable_flags & 0x04 != 0 && psbt_has_signatures(&psbt) {
                return reject_sighash_single_pairing(request, digest);
            }
            if index >= psbt.inputs.len() {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "psbt.index_out_of_bounds",
                    "Input index is outside the PSBTv2",
                );
            }
            let before_locktime = psbt.determine_lock_time().ok();
            let signed = psbt_has_signatures(&psbt);
            psbt.inputs.remove(index);
            psbt.global.input_count -= 1;
            if psbt.determine_lock_time().is_err() {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "psbt.locktime_conflict",
                    "Removing the input left incompatible locktime requirements",
                );
            }
            if signed && before_locktime != psbt.determine_lock_time().ok() {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "psbt.locktime_change_after_signature",
                    "A signed PSBTv2 cannot change its selected locktime",
                );
            }
            construct_success(request, digest, psbt)
        }
        ConstructPayload::RemoveOutput { psbt, index } => {
            let Some(mut psbt) = parsed_construct_psbt(&psbt) else {
                return construct_parse_failure(request, digest);
            };
            if psbt.global.tx_modifiable_flags & 0x02 == 0 {
                return reject_not_modifiable(request, digest, "outputs");
            }
            if psbt.global.tx_modifiable_flags & 0x04 != 0 && psbt_has_signatures(&psbt) {
                return reject_sighash_single_pairing(request, digest);
            }
            if index >= psbt.outputs.len() {
                return failure(
                    &request.id,
                    digest,
                    "rejected",
                    "psbt.index_out_of_bounds",
                    "Output index is outside the PSBTv2",
                );
            }
            psbt.outputs.remove(index);
            psbt.global.output_count -= 1;
            construct_success(request, digest, psbt)
        }
        ConstructPayload::SetSequence {
            psbt,
            index,
            sequence,
        } => {
            let Some(psbt) = parsed_construct_psbt(&psbt) else {
                return construct_parse_failure(request, digest);
            };
            let updater = match Updater::new(psbt) {
                Ok(updater) => updater,
                Err(_) => {
                    return failure(
                        &request.id,
                        digest,
                        "rejected",
                        "psbt.locktime_conflict",
                        "PSBTv2 locktime cannot be determined",
                    );
                }
            };
            match updater.set_sequence(Sequence(sequence), index) {
                Ok(updater) => construct_success(request, digest, updater.psbt()),
                Err(_) => failure(
                    &request.id,
                    digest,
                    "rejected",
                    "psbt.index_out_of_bounds",
                    "Input index is outside the PSBTv2",
                ),
            }
        }
        ConstructPayload::Seal { psbt, scope } => {
            let Some(mut psbt) = parsed_construct_psbt(&psbt) else {
                return construct_parse_failure(request, digest);
            };
            match scope {
                SealScope::Inputs => psbt.global.tx_modifiable_flags &= !0x01,
                SealScope::Outputs => psbt.global.tx_modifiable_flags &= !0x02,
                SealScope::All => psbt.global.tx_modifiable_flags &= !0x03,
            }
            construct_success(request, digest, psbt)
        }
    }
}

fn roundtrip(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Some(encoded) => encoded,
        None => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "roundtrip expects only a psbt string field",
            );
        }
    };
    let Some(parsed) = parse_psbt(encoded) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "PSBTv2 could not be parsed",
        );
    };
    let serialized = parsed.psbt.serialize();
    let silent_payment_fields = silent_payment_fields(&parsed.psbt);
    success(
        &request.id,
        digest,
        json!({
            "psbt": STANDARD.encode(&serialized),
            "byteIdentical": serialized == parsed.bytes,
            "psbtVersion": 2,
            "silentPaymentFields": silent_payment_fields
        }),
    )
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(message);
    engine.finalize().into()
}

fn scalar_from_hash(bytes: [u8; 32]) -> Result<Scalar, &'static str> {
    Scalar::from_be_bytes(bytes).map_err(|_| "Tagged hash is outside the secp256k1 scalar range")
}

fn bip375_dleq_proof(
    secret: SecretKey,
    scan_key: SecpPublicKey,
) -> Result<(SecpPublicKey, DleqProof), &'static str> {
    let secp = Secp256k1::new();
    let input_key = SecpPublicKey::from_secret_key(&secp, &secret);
    let secret_scalar = Scalar::from_be_bytes(secret.secret_bytes())
        .map_err(|_| "Silent Payment fixture secret is invalid")?;
    let share = scan_key
        .mul_tweak(&secp, &secret_scalar)
        .map_err(|_| "Silent Payment ECDH share is invalid")?;

    let aux_hash = tagged_hash("BIP0374/aux", &BIP375_AUX);
    let mut masked_secret = secret.secret_bytes();
    for (byte, mask) in masked_secret.iter_mut().zip(aux_hash) {
        *byte ^= mask;
    }
    let mut nonce_message = Vec::with_capacity(32 + 33 + 33);
    nonce_message.extend_from_slice(&masked_secret);
    nonce_message.extend_from_slice(&input_key.serialize());
    nonce_message.extend_from_slice(&share.serialize());
    let nonce = SecretKey::from_slice(&tagged_hash("BIP0374/nonce", &nonce_message))
        .map_err(|_| "Deterministic BIP374 nonce is invalid")?;
    let nonce_scalar = Scalar::from_be_bytes(nonce.secret_bytes())
        .map_err(|_| "Deterministic BIP374 nonce is invalid")?;
    let r1 = SecpPublicKey::from_secret_key(&secp, &nonce);
    let r2 = scan_key
        .mul_tweak(&secp, &nonce_scalar)
        .map_err(|_| "BIP374 nonce point is invalid")?;
    let generator = SecpPublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .map_err(|_| "secp256k1 generator scalar is invalid")?,
    );
    let mut challenge_message = Vec::with_capacity(33 * 6);
    for point in [input_key, scan_key, share, generator, r1, r2] {
        challenge_message.extend_from_slice(&point.serialize());
    }
    let challenge = tagged_hash("BIP0374/challenge", &challenge_message);
    let challenge_scalar = scalar_from_hash(challenge)?;
    let response = secret
        .mul_tweak(&challenge_scalar)
        .and_then(|value| value.add_tweak(&nonce_scalar))
        .map_err(|_| "BIP374 response scalar is invalid")?;
    let mut proof = [0_u8; 64];
    proof[..32].copy_from_slice(&challenge);
    proof[32..].copy_from_slice(&response.secret_bytes());
    Ok((share, DleqProof::from(proof)))
}

fn bip375_output_script(
    psbt: &Psbt,
    input_key: SecpPublicKey,
    ecdh_share: SecpPublicKey,
) -> Result<ScriptBuf, &'static str> {
    let output = psbt
        .outputs
        .first()
        .ok_or("Silent Payment fixture has no output")?;
    let info = output
        .sp_v0_info
        .as_ref()
        .filter(|value| value.len() == 66)
        .ok_or("Silent Payment output info is invalid")?;
    let spend_key = SecpPublicKey::from_slice(&info[33..])
        .map_err(|_| "Silent Payment spend key is invalid")?;
    let input = psbt
        .inputs
        .first()
        .ok_or("Silent Payment fixture has no input")?;
    let mut outpoint = Vec::with_capacity(36);
    outpoint.extend_from_slice(&consensus::serialize(&input.previous_txid));
    outpoint.extend_from_slice(&input.spent_output_index.to_le_bytes());
    let mut input_hash_message = outpoint;
    input_hash_message.extend_from_slice(&input_key.serialize());
    let input_hash = scalar_from_hash(tagged_hash("BIP0352/Inputs", &input_hash_message))?;
    let shared_secret = ecdh_share
        .mul_tweak(&Secp256k1::new(), &input_hash)
        .map_err(|_| "Silent Payment shared secret is invalid")?;
    let mut output_message = Vec::with_capacity(37);
    output_message.extend_from_slice(&shared_secret.serialize());
    output_message.extend_from_slice(&0_u32.to_be_bytes());
    let output_tweak_bytes = tagged_hash("BIP0352/SharedSecret", &output_message);
    let _output_tweak = scalar_from_hash(output_tweak_bytes)?;
    let tweak_secret = SecretKey::from_slice(&output_tweak_bytes)
        .map_err(|_| "Silent Payment output tweak is invalid")?;
    let tweak_key = SecpPublicKey::from_secret_key(&Secp256k1::new(), &tweak_secret);
    let output_key = spend_key
        .combine(&tweak_key)
        .map_err(|_| "Silent Payment output key is invalid")?;
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&output_key.serialize()[1..]);
    Ok(ScriptBuf::from_bytes(script))
}

fn finalize_silent_payment_p2pkh(
    mut psbt: Psbt,
    public_key: &PublicKey,
) -> Result<Psbt, &'static str> {
    let input = psbt
        .inputs
        .first_mut()
        .ok_or("Silent Payment fixture has no input")?;
    let signature = input
        .partial_sigs
        .get(public_key)
        .ok_or("Silent Payment input lacks its fixture signature")?;
    let signature = PushBytesBuf::try_from(signature.to_vec())
        .map_err(|_| "Silent Payment signature is too large for scriptSig")?;
    input.final_script_sig = Some(
        Builder::new()
            .push_slice(signature)
            .push_key(public_key)
            .into_script(),
    );
    input.final_script_witness = Some(Witness::default());
    clear_non_final_fields(input);
    psbt.interpreter_check(&Secp256k1::verification_only())
        .map_err(|_| "Finalized Silent Payment P2PKH script did not verify")?;
    Ok(psbt)
}

fn silent_payment_send(request: &Request, digest: &str) -> Value {
    if !exact_fields(&request.payload, &["psbt", "network", "fixtureId"]) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "silent-payment-send expects psbt, network, and fixtureId",
        );
    }
    if payload_string(&request.payload, "network") != Some("regtest") {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.network_not_allowed",
            "Silent Payment sender proofs are restricted to regtest fixtures",
        );
    }
    if payload_string(&request.payload, "fixtureId") != Some(BIP375_FIXTURE_ID) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_not_allowed",
            "Unknown Silent Payment sender fixture",
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
    let Some(parsed) = parse_psbt(encoded) else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "Silent Payment PSBTv2 could not be parsed",
        );
    };
    let actual: [u8; 32] = Sha256::digest(&parsed.bytes).into();
    if actual
        .iter()
        .zip(BIP375_FIXTURE_PSBT_SHA256)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        != 0
    {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_commitment_mismatch",
            "The PSBT does not match the pinned BIP375 sender fixture",
        );
    }

    let result = (|| -> Result<(Psbt, Psbt, Transaction), &'static str> {
        let mut psbt = parsed.psbt;
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&BIP375_PRIVATE_KEY)
            .map_err(|_| "Silent Payment fixture key is invalid")?;
        let private_key = PrivateKey::new(secret, Network::Regtest);
        let public_key = private_key.public_key(&secp);
        let scan_key = SecpPublicKey::from_slice(&BIP375_SCAN_KEY)
            .map_err(|_| "Silent Payment scan key is invalid")?;
        let (share, proof) = bip375_dleq_proof(secret, scan_key)?;
        let script = bip375_output_script(&psbt, public_key.inner, share)?;
        let compressed_scan = CompressedPublicKey(scan_key);
        psbt.inputs[0]
            .sp_ecdh_shares
            .insert(compressed_scan, CompressedPublicKey(share));
        psbt.inputs[0].sp_dleq_proofs.insert(compressed_scan, proof);
        psbt.outputs[0].script_pubkey = script;
        psbt.global.tx_modifiable_flags &= !0x03;

        let mut keys = BTreeMap::new();
        keys.insert(public_key, private_key);
        let signer = Signer::new(psbt).map_err(|_| "Silent Payment PSBT locktime is invalid")?;
        let (signed, signing_keys) = signer
            .sign(&keys, &secp)
            .map_err(|_| "Native signer could not sign the Silent Payment input")?;
        if signing_keys
            .values()
            .filter(|keys| keys.contains(&public_key))
            .count()
            != 1
        {
            return Err("Fixture key did not sign the Silent Payment input");
        }
        let signed_copy = signed.clone();
        let mut finalized = finalize_silent_payment_p2pkh(signed, &public_key)?;
        omit_empty_final_script_sigs(&mut finalized);
        let transaction = Extractor::new(native_extractable_psbt(finalized.clone()))
            .map_err(|_| "Finalized Silent Payment PSBT is not extractable")?
            .extract_tx()
            .map_err(|_| "Native Silent Payment extraction failed")?;
        Ok((signed_copy, finalized, transaction))
    })();

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
                "transactionId": transaction.compute_txid().to_string(),
                "witnessTransactionId": transaction.compute_wtxid().to_string()
            }),
        ),
        Err(message) => failure(
            &request.id,
            digest,
            "rejected",
            "silent_payment.send_failed",
            message,
        ),
    }
}

pub fn handle_value(value: Value, digest: &str) -> Value {
    handle_value_with_commitments(value, digest, &FixtureCommitments::default())
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
                "operations": ["hello", "native-parse", "inspect", "roundtrip", "sign", "combine", "finalize", "extract", "construct", "silent-payment-send"],
                "roles": ["parser", "updater", "signer", "combiner", "finalizer", "extractor", "constructor"],
                "psbtVersions": [2],
                "scriptTypes": ["p2pkh", "p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                "operationScriptTypes": {
                    "inspect": ["p2pkh", "p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                    "roundtrip": ["p2pkh", "p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
                    "sign": ["p2wpkh", "p2wsh"],
                    "combine": ["p2wpkh", "p2wsh"],
                    "finalize": ["p2wpkh", "p2wsh"],
                    "extract": ["p2wpkh", "p2wsh"],
                    "construct": ["p2wpkh", "p2wsh"],
                    "silent-payment-send": ["p2pkh"]
                },
                "features": [
                    "bip370-official-vectors",
                    "bounded-map-counts",
                    "fixture-commitment-sha256",
                    "bip370-unique-id",
                    "unsigned-tx-sha256",
                    "bip370-constructor",
                    "bip370-locktime",
                    "bip371-taproot-roundtrip",
                    "bip375-silent-payments",
                    "bip375-sender-workflow"
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
        "inspect" => inspect(&request, digest),
        "roundtrip" => roundtrip(&request, digest),
        "sign" => sign(&request, digest, commitments),
        "combine" => combine(&request, digest),
        "finalize" => finalize(&request, digest, commitments),
        "extract" => extract(&request, digest),
        "construct" => construct(&request, digest),
        "silent-payment-send" => silent_payment_send(&request, digest),
        "convert" => failure(
            &request.id,
            digest,
            "unsupported",
            "conversion.native_api_unavailable",
            "psbt-v2 0.3.0 does not expose PSBT version conversion",
        ),
        _ => failure(
            &request.id,
            digest,
            "unsupported",
            "operation.unsupported",
            "Operation is outside this adapter's declared capabilities",
        ),
    }
}

pub fn invalid_json_response(digest: &str) -> Value {
    failure(
        "invalid-1",
        digest,
        "rejected",
        "protocol.invalid_json",
        "Request line is not valid JSON",
    )
}
