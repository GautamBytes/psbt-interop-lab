use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use psbt_v2::v2::Psbt;
use serde::Deserialize;
use serde_json::{Map, Value, json};

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const JSON_ENVELOPE_ALLOWANCE: usize = 4096;
const MAX_PSBT_BYTES: usize = (MAX_LINE_BYTES - JSON_ENVELOPE_ALLOWANCE) * 3 / 4;
const MAX_MAP_COUNT: usize = 4096;
const MAX_MAP_ENTRIES: usize = 16_384;
const SOURCE_REVISION: &str = "rust-psbt/psbt-v2-0.3.0@8ca657c333b6b391f2501e8b31627ccbb6a67f66";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    operation: String,
    payload: Map<String, Value>,
}

struct ParsedPsbt {
    bytes: Vec<u8>,
    psbt: Psbt,
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

fn psbt_payload(request: &Request) -> Option<&str> {
    if !exact_fields(&request.payload, &["psbt"]) {
        return None;
    }
    request.payload.get("psbt").and_then(Value::as_str)
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
                "outputs": parsed.psbt.outputs.len()
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
    success(
        &request.id,
        digest,
        json!({
            "psbtVersion": 2,
            "inputs": parsed.psbt.inputs.len(),
            "outputs": parsed.psbt.outputs.len(),
            "finalizedInputs": finalized_inputs,
            "partialSignatureInputs": partial_signature_inputs
        }),
    )
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
    success(
        &request.id,
        digest,
        json!({
            "psbt": STANDARD.encode(&serialized),
            "byteIdentical": serialized == parsed.bytes,
            "psbtVersion": 2
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
                "operations": ["hello", "native-parse", "inspect", "roundtrip"],
                "roles": ["parser"],
                "psbtVersions": [2],
                "scriptTypes": ["p2wpkh"],
                "operationScriptTypes": {
                    "inspect": ["p2wpkh"],
                    "roundtrip": ["p2wpkh"]
                },
                "features": ["bip370-official-vectors", "bounded-map-counts"]
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
        _ => failure(
            &request.id,
            digest,
            "unsupported",
            "operation.unsupported",
            "Operation is outside this parser-only adapter scope",
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
