use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::key::PrivateKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{PublicKey, Witness};
use serde::Deserialize;
use serde_json::{Map, Value, json};

const PROTOCOL: &str = "psbt-lab.adapter/0.1";
const TEST_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const ALLOWED_FIXTURES: [&str; 2] = ["happy-path", "bdk-finalize-regression"];

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
        "sourceRevision": "bitcoin-crate-0.32.101"
    })
}

fn success(id: &str, digest: &str, output: Value) -> Value {
    json!({
        "protocol": PROTOCOL,
        "id": id,
        "status": "ok",
        "implementation": implementation(digest),
        "output": output
    })
}

fn failure(id: &str, digest: &str, status: &str, class: &str, message: &str) -> Value {
    json!({
        "protocol": PROTOCOL,
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

fn sign(request: &Request, digest: &str) -> Value {
    let (encoded, _) = match validate_fixture_payload(request, &["psbt", "network", "fixtureId"]) {
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

fn finalize_first_input(request: &Request, digest: &str) -> Value {
    let (encoded, fixture_id) =
        match validate_fixture_payload(request, &["psbt", "network", "fixtureId"]) {
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
    let Some(input) = psbt.inputs.first_mut() else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "finalize.missing_input",
            "Regression fixture has no first input",
        );
    };
    let Some(signature) = input.partial_sigs.get(&public_key).cloned() else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "finalize.missing_signature",
            "First input does not contain the fixture signature",
        );
    };
    let Some(witness_script) = input.witness_script.clone() else {
        return failure(
            &request.id,
            digest,
            "rejected",
            "finalize.missing_witness_script",
            "First input does not contain its fixture witness script",
        );
    };

    input.final_script_witness = Some(Witness::from_slice(&[
        signature.to_vec(),
        witness_script.as_bytes().to_vec(),
    ]));
    input.partial_sigs.clear();
    input.sighash_type = None;
    input.redeem_script = None;
    input.witness_script = None;
    input.bip32_derivation.clear();

    success(
        &request.id,
        digest,
        json!({
            "psbt": encoded_psbt(&psbt),
            "finalizedInput": 0,
            "remainingPartialInputs": psbt.inputs.iter().filter(|item| !item.partial_sigs.is_empty()).count()
        }),
    )
}

pub fn handle_value(value: Value, digest: &str) -> Value {
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
    if request.protocol != PROTOCOL || !safe_id(&request.id) {
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
                "operations": ["hello", "inspect", "roundtrip", "sign", "fixture-finalize-input"],
                "psbtVersions": [0],
                "signingPolicy": "regtest fixtures using the public scalar-one test key only"
            }),
        ),
        "hello" => failure(
            &request.id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "hello expects an empty payload",
        ),
        "inspect" => {
            if !exact_fields(&request.payload, &["psbt"]) {
                failure(
                    &request.id,
                    digest,
                    "rejected",
                    "protocol.invalid_payload",
                    "inspect expects only a psbt field",
                )
            } else if let Some(encoded) = payload_string(&request.payload, "psbt") {
                match parse_psbt(encoded) {
                    Ok((_, psbt)) => success(
                        &request.id,
                        digest,
                        json!({
                            "psbtVersion": psbt.version,
                            "inputs": psbt.inputs.len(),
                            "outputs": psbt.outputs.len(),
                            "finalizedInputs": psbt.inputs.iter().filter(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some()).count(),
                            "partialSignatureInputs": psbt.inputs.iter().filter(|input| !input.partial_sigs.is_empty()).count()
                        }),
                    ),
                    Err(message) => failure(
                        &request.id,
                        digest,
                        "rejected",
                        "psbt.parse_failed",
                        &message,
                    ),
                }
            } else {
                failure(
                    &request.id,
                    digest,
                    "rejected",
                    "protocol.invalid_payload",
                    "psbt must be a base64 string",
                )
            }
        }
        "roundtrip" => roundtrip(&request, digest),
        "sign" => sign(&request, digest),
        "fixture-finalize-input" => finalize_first_input(&request, digest),
        _ => failure(
            &request.id,
            digest,
            "unsupported",
            "operation.unsupported",
            "Operation is not implemented by the rust-bitcoin adapter",
        ),
    }
}
