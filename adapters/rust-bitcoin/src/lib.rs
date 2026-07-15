use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::key::PrivateKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::psbt::{Psbt, SigningKeys};
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{PublicKey, Witness};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_COMMITMENTS_BYTES: usize = 4 * 1024;
const TEST_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const ALLOWED_FIXTURES: [&str; 2] = ["happy-path", "bdk-finalize-regression"];

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

fn parse_psbt(encoded: &str) -> Result<(Vec<u8>, Psbt), String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "PSBT is not valid base64".to_owned())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("PSBT exceeds the 4 MiB adapter limit".to_owned());
    }
    let psbt = Psbt::deserialize(&bytes).map_err(|error| format!("Invalid PSBT: {error}"))?;
    if psbt.version != 0 {
        return Err("The Rust signer supports PSBTv0 only".to_owned());
    }
    Ok((bytes, psbt))
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

fn validate_signing_scope(psbt: &Psbt, public_key: &PublicKey) -> Result<(), &'static str> {
    if psbt.inputs.is_empty() || psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err("PSBT has no signable fixture inputs");
    }
    let expected_script = expected_witness_script(public_key);
    let expected_script_pubkey = expected_script.to_p2wsh();

    for (index, input) in psbt.inputs.iter().enumerate() {
        let previous_output = &psbt.unsigned_tx.input[index].previous_output;
        if input.witness_script.as_ref() != Some(&expected_script) {
            return Err("Every input must use the lab wsh(pk(fixture-key)) witness script");
        }
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
        if funding_output.map(|output| &output.script_pubkey) != Some(&expected_script_pubkey) {
            return Err("Every input must spend the lab fixture script");
        }
    }
    Ok(())
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
    let expected_fields = if has_input_indexes {
        &["psbt", "network", "fixtureId", "inputIndexes"][..]
    } else {
        &["psbt", "network", "fixtureId"][..]
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
            Ok(indexes) => Some(indexes),
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
    if let Err(message) = validate_signing_scope(&psbt, &public_key) {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.psbt_not_authorized",
            message,
        );
    }

    let secp = Secp256k1::new();
    let mut keys = BTreeMap::new();
    keys.insert(public_key, private_key);
    if let Some(input_indexes) = input_indexes {
        let selected: BTreeSet<usize> = input_indexes.iter().copied().collect();
        let mut skipped_derivations = Vec::new();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            if !selected.contains(&index) {
                skipped_derivations.push((index, std::mem::take(&mut input.bip32_derivation)));
            }
        }

        let signing_result = psbt.sign(&keys, &secp);
        for (index, derivation) in skipped_derivations {
            psbt.inputs[index].bip32_derivation = derivation;
        }

        let (signing_keys, signing_errors) = match signing_result {
            Ok(signing_keys) => (signing_keys, BTreeMap::new()),
            Err((signing_keys, signing_errors)) => (signing_keys, signing_errors),
        };
        let signed_inputs = signing_keys
            .iter()
            .filter(|(index, signing_keys)| {
                selected.contains(index)
                    && match signing_keys {
                        SigningKeys::Ecdsa(keys) => !keys.is_empty(),
                        SigningKeys::Schnorr(keys) => !keys.is_empty(),
                    }
            })
            .count();
        let failed_inputs = signing_errors
            .keys()
            .filter(|index| selected.contains(*index))
            .count();

        if failed_inputs > 0 {
            return failure(
                &request.id,
                digest,
                "rejected",
                "signing.failed",
                &format!(
                    "Signing completed {signed_inputs} input(s) but {failed_inputs} input(s) failed"
                ),
            );
        }
        if signed_inputs != input_indexes.len() {
            return failure(
                &request.id,
                digest,
                "rejected",
                "signing.no_matching_key",
                "The fixture key did not sign every selected input",
            );
        }
        return success(
            &request.id,
            digest,
            json!({
                "psbt": encoded_psbt(&psbt),
                "signedInputs": signed_inputs
            }),
        );
    }

    match psbt.sign(&keys, &secp) {
        Ok(signing_keys) if !signing_keys.is_empty() => success(
            &request.id,
            digest,
            json!({
                "psbt": encoded_psbt(&psbt),
                "signedInputs": signing_keys.len()
            }),
        ),
        Ok(_) => failure(
            &request.id,
            digest,
            "rejected",
            "signing.no_matching_key",
            "The fixture key did not sign any input",
        ),
        Err((signing_keys, errors)) => failure(
            &request.id,
            digest,
            "rejected",
            "signing.failed",
            &format!(
                "Signing completed {} input(s) but {} input(s) failed",
                signing_keys.len(),
                errors.len()
            ),
        ),
    }
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
    if fixture_id != "bdk-finalize-regression" {
        return failure(
            &request.id,
            digest,
            "rejected",
            "policy.fixture_not_allowed",
            "Selected-input finalization is reserved for the BDK regression fixture",
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
    if let Err(message) = validate_signing_scope(&psbt, &public_key) {
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
                "operations": ["hello", "roundtrip", "sign", "finalize-inputs"],
                "roles": ["parser", "signer", "finalizer"],
                "psbtVersions": [0],
                "scriptTypes": ["p2wsh"],
                "features": ["fixture-commitment-sha256"]
            }),
        ),
        "hello" => failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "hello expects an empty payload",
        ),
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
