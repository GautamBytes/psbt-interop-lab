use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bdk_wallet::bitcoin::Psbt;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

mod wallet;

use wallet::WalletOperationError;

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const RESPONSE_LINE_RESERVE: usize = 4 * 1024;
const MAX_PSBT_BYTES: usize = (MAX_LINE_BYTES - RESPONSE_LINE_RESERVE) * 3 / 4;
const MAX_COMMITMENTS_BYTES: usize = 4 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const SOURCE_REVISION: &str = "bdk-wallet-v3.1.0+bitcoin-0.32.102+miniscript-12.3.7";
const ALLOWED_FIXTURES: [&str; 7] = [
    "happy-path",
    "bdk-finalize-regression",
    "p2wpkh",
    "intent-rich-p2wpkh",
    "p2wsh-single-key",
    "p2wsh-2-of-3",
    "p2tr-keypath",
];

#[derive(Clone, Debug)]
pub struct FixtureCommitments {
    values: BTreeMap<String, [u8; 32]>,
    valid: bool,
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
            return Ok(Self {
                values: BTreeMap::new(),
                valid: true,
            });
        };
        if raw.len() > MAX_COMMITMENTS_BYTES {
            return Err("fixture commitment configuration exceeds its size limit");
        }
        let object = serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .filter(|object| !object.is_empty() && object.len() <= ALLOWED_FIXTURES.len())
            .ok_or("fixture commitment configuration must be a non-empty bounded JSON object")?;
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
        let transaction = bdk_wallet::bitcoin::consensus::serialize(&psbt.unsigned_tx);
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
        "name": "bdk-wallet-current",
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

pub fn invalid_json_response(digest: &str) -> Value {
    failure(
        "invalid-1",
        digest,
        "rejected",
        "protocol.invalid_json",
        "Request line is not valid JSON",
    )
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
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    let actual = payload.keys().map(String::as_str).collect::<BTreeSet<_>>();
    actual == expected
}

fn payload_string<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn decode_psbt_bytes(encoded: &str) -> Result<Vec<u8>, ()> {
    if encoded.len() > base64::encoded_len(MAX_PSBT_BYTES, true).unwrap_or(usize::MAX) {
        return Err(());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| ())?;
    if bytes.len() > MAX_PSBT_BYTES || STANDARD.encode(&bytes) != encoded {
        return Err(());
    }
    Ok(bytes)
}

fn parse_psbt(encoded: &str) -> Result<(Vec<u8>, Psbt), ()> {
    let bytes = decode_psbt_bytes(encoded)?;
    let psbt = Psbt::deserialize(&bytes).map_err(|_| ())?;
    if psbt.version != 0 {
        return Err(());
    }
    Ok((bytes, psbt))
}

fn psbt_payload(request: &Request) -> Result<&str, ()> {
    if !exact_fields(&request.payload, &["psbt"]) {
        return Err(());
    }
    payload_string(&request.payload, "psbt").ok_or(())
}

fn native_parse(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Ok(encoded) => encoded,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "native-parse expects only a psbt field",
            );
        }
    };
    match parse_psbt(encoded) {
        Ok((_, psbt)) => success(
            &request.id,
            digest,
            json!({
                "nativeParser": "bdk_wallet::bitcoin::Psbt",
                "psbtVersion": psbt.version,
                "inputs": psbt.inputs.len(),
                "outputs": psbt.outputs.len()
            }),
        ),
        Err(()) => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.native_parse_failed",
            "BDK's rust-bitcoin parser rejected the PSBT",
        ),
    }
}

fn inspect(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Ok(encoded) => encoded,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "inspect expects only a psbt field",
            );
        }
    };
    match parse_psbt(encoded) {
        Ok((_, psbt)) => {
            let finalized_inputs = psbt
                .inputs
                .iter()
                .filter(|input| {
                    input.final_script_sig.is_some() || input.final_script_witness.is_some()
                })
                .count();
            let partial_signature_inputs = psbt
                .inputs
                .iter()
                .filter(|input| {
                    !input.partial_sigs.is_empty()
                        || input.tap_key_sig.is_some()
                        || !input.tap_script_sigs.is_empty()
                })
                .count();
            success(
                &request.id,
                digest,
                json!({
                    "psbtVersion": psbt.version,
                    "inputs": psbt.inputs.len(),
                    "outputs": psbt.outputs.len(),
                    "finalizedInputs": finalized_inputs,
                    "partialSignatureInputs": partial_signature_inputs
                }),
            )
        }
        Err(()) => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "PSBT must be canonical PSBTv0 base64 within the adapter limit",
        ),
    }
}

fn roundtrip(request: &Request, digest: &str) -> Value {
    let encoded = match psbt_payload(request) {
        Ok(encoded) => encoded,
        Err(_) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "roundtrip expects only a psbt field",
            );
        }
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
        Err(()) => failure(
            &request.id,
            digest,
            "rejected",
            "psbt.parse_failed",
            "PSBT must be canonical PSBTv0 base64 within the adapter limit",
        ),
    }
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
    let encoded = payload_string(&request.payload, "psbt")
        .ok_or(("protocol.invalid_payload", "psbt must be a base64 string"))?;
    let network = payload_string(&request.payload, "network")
        .ok_or(("protocol.invalid_payload", "network must be a string"))?;
    if network != "regtest" {
        return Err((
            "policy.network_not_allowed",
            "Signing and finalization are restricted to regtest fixtures",
        ));
    }
    let fixture_id = payload_string(&request.payload, "fixtureId")
        .ok_or(("protocol.invalid_payload", "fixtureId must be a string"))?;
    if !ALLOWED_FIXTURES.contains(&fixture_id) {
        return Err(("policy.fixture_not_allowed", "Unknown signing fixture"));
    }
    Ok((encoded, fixture_id))
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

fn wallet_failure(
    request: &Request,
    digest: &str,
    operation: &str,
    error: WalletOperationError,
) -> Value {
    match error {
        WalletOperationError::Policy(message) => failure(
            &request.id,
            digest,
            "rejected",
            "policy.psbt_not_authorized",
            message,
        ),
        WalletOperationError::InvalidSignature(message) if operation == "sign" => failure(
            &request.id,
            digest,
            "rejected",
            "policy.psbt_not_authorized",
            message,
        ),
        WalletOperationError::InvalidSignature(message) => failure(
            &request.id,
            digest,
            "rejected",
            "finalize.signature_invalid",
            message,
        ),
        WalletOperationError::Signing(message) if operation == "sign" => {
            failure(&request.id, digest, "rejected", "signing.failed", &message)
        }
        WalletOperationError::Signing(message) => {
            failure(&request.id, digest, "rejected", "finalize.failed", &message)
        }
        WalletOperationError::Incomplete => failure(
            &request.id,
            digest,
            "rejected",
            "finalize.failed",
            "The authorized PSBT does not yet have enough valid signatures",
        ),
        WalletOperationError::Internal(message) => failure(
            &request.id,
            digest,
            "crashed",
            "adapter.fixture_wallet_invalid",
            &message,
        ),
    }
}

fn sign(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let has_input_indexes = request.payload.contains_key("inputIndexes");
    let fields = if has_input_indexes {
        &["psbt", "network", "fixtureId", "inputIndexes"][..]
    } else {
        &["psbt", "network", "fixtureId"][..]
    };
    let (encoded, fixture_id) = match validate_fixture_payload(request, fields) {
        Ok(values) => values,
        Err((class, message)) => {
            return failure(&request.id, digest, "rejected", class, message);
        }
    };
    let (_, mut psbt) = match parse_psbt(encoded) {
        Ok(parsed) => parsed,
        Err(()) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.parse_failed",
                "PSBT must be canonical PSBTv0 base64 within the adapter limit",
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
    if let Some(response) = commitment_failure(request, digest, commitments, fixture_id, &psbt) {
        return response;
    }
    match wallet::sign(&mut psbt, fixture_id, &input_indexes) {
        Ok(signed_inputs) => success(
            &request.id,
            digest,
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "signedInputs": signed_inputs
            }),
        ),
        Err(error) => wallet_failure(request, digest, "sign", error),
    }
}

fn finalize(request: &Request, digest: &str, commitments: &FixtureCommitments) -> Value {
    let (encoded, fixture_id) =
        match validate_fixture_payload(request, &["psbt", "network", "fixtureId"]) {
            Ok(values) => values,
            Err((class, message)) => {
                return failure(&request.id, digest, "rejected", class, message);
            }
        };
    let (_, mut psbt) = match parse_psbt(encoded) {
        Ok(parsed) => parsed,
        Err(()) => {
            return failure(
                &request.id,
                digest,
                "rejected",
                "psbt.parse_failed",
                "PSBT must be canonical PSBTv0 base64 within the adapter limit",
            );
        }
    };
    if let Some(response) = commitment_failure(request, digest, commitments, fixture_id, &psbt) {
        return response;
    }
    match wallet::finalize(&mut psbt, fixture_id) {
        Ok(finalized_inputs) => success(
            &request.id,
            digest,
            json!({
                "psbt": STANDARD.encode(psbt.serialize()),
                "finalizedInputs": finalized_inputs
            }),
        ),
        Err(error) => wallet_failure(request, digest, "finalize", error),
    }
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
    let request = match serde_json::from_value::<Request>(value) {
        Ok(request) if request.protocol == ADAPTER_PROTOCOL && safe_id(&request.id) => request,
        _ => {
            return failure(
                &fallback,
                digest,
                "rejected",
                "protocol.invalid_request",
                "Request does not match the adapter protocol",
            );
        }
    };

    match request.operation.as_str() {
        "hello" if request.payload.is_empty() => success(
            &request.id,
            digest,
            json!({
                "operations": ["hello", "native-parse", "inspect", "roundtrip", "sign", "finalize"],
                "roles": ["parser", "signer", "finalizer"],
                "psbtVersions": [0],
                "scriptTypes": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                "operationScriptTypes": {
                    "inspect": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                    "roundtrip": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                    "sign": ["p2wpkh", "p2wsh", "p2tr-keypath"],
                    "finalize": ["p2wpkh", "p2wsh", "p2tr-keypath"]
                },
                "features": [
                    "fixture-commitment-sha256",
                    "network-free",
                    "trusted-witness-utxo-authorized-fixtures-only"
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
        "finalize" => finalize(&request, digest, commitments),
        _ => failure(
            &request.id,
            digest,
            "unsupported",
            "operation.unsupported",
            "Operation is not implemented by the BDK wallet adapter",
        ),
    }
}
