use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, raw::Key as RawKey};
use bitcoin::secp256k1::schnorr::Signature as BitcoinSchnorrSignature;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{TxOut, taproot};
use musig2::secp256k1::{PublicKey as MusigPublicKey, SecretKey as MusigSecretKey};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, aggregate_partial_signatures,
    sign_partial, verify_partial, verify_single,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const ADAPTER_PROTOCOL: &str = "psbt-lab.adapter/0.2";
pub const SOURCE_REVISION: &str = "musig2-crate-0.4.1+bitcoin-0.32.102";
pub const FIXTURE_ID: &str = "p2tr-musig2";
pub const PARTICIPANT_PUBLIC_KEYS: [&str; 2] = [
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
];
pub const AGGREGATE_PUBLIC_KEY: &str =
    "023b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec";

const MAX_COMMITMENTS_BYTES: usize = 4 * 1024;
const MAX_SESSIONS: usize = 64;
const MAX_CONSUMED_SESSION_IDS: usize = 1024;
const SESSION_TTL: Duration = Duration::from_secs(15 * 60);
const SECRET_KEYS: [&str; 2] = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
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
        if object.len() > 1 {
            return Err("fixture commitment configuration has too many entries");
        }
        let mut values = BTreeMap::new();
        for (fixture_id, value) in object {
            if fixture_id != FIXTURE_ID {
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

    fn verify(&self, fixture_id: &str, psbt: &Psbt) -> Result<(), &'static str> {
        if !self.valid {
            return Err("fixture commitment configuration is invalid");
        }
        let expected = self
            .values
            .get(fixture_id)
            .ok_or("fixture commitment is missing")?;
        let actual: [u8; 32] =
            Sha256::digest(bitcoin::consensus::serialize(&psbt.unsigned_tx)).into();
        let difference = actual
            .iter()
            .zip(expected)
            .fold(0_u8, |accumulator, (left, right)| {
                accumulator | (left ^ right)
            });
        if difference == 0 {
            Ok(())
        } else {
            Err("fixture commitment does not match the unsigned transaction")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerIdentity {
    One,
    Two,
}

impl SignerIdentity {
    pub fn from_selector(value: &str) -> Result<Self, &'static str> {
        match value {
            "1" => Ok(Self::One),
            "2" => Ok(Self::Two),
            _ => Err("PSBT_LAB_MUSIG2_SIGNER must be 1 or 2"),
        }
    }

    fn index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 1,
        }
    }

    pub fn implementation_name(self) -> &'static str {
        match self {
            Self::One => "musig2-rust-signer-1",
            Self::Two => "musig2-rust-signer-2",
        }
    }

    fn secret_key(self) -> MusigSecretKey {
        SECRET_KEYS[self.index()]
            .parse()
            .expect("fixed MuSig2 test secret must be valid")
    }

    fn public_key(self) -> MusigPublicKey {
        PARTICIPANT_PUBLIC_KEYS[self.index()]
            .parse()
            .expect("fixed MuSig2 test public key must be valid")
    }
}

struct NonceSession {
    created_at: Instant,
    message: [u8; 32],
    secret_nonce: SecNonce,
}

pub struct Musig2Adapter {
    identity: SignerIdentity,
    commitments: FixtureCommitments,
    sessions: BTreeMap<String, NonceSession>,
    consumed_sessions: BTreeSet<String>,
    consumed_session_order: VecDeque<String>,
}

impl Musig2Adapter {
    pub fn new(identity: SignerIdentity, commitments: FixtureCommitments) -> Self {
        Self {
            identity,
            commitments,
            sessions: BTreeMap::new(),
            consumed_sessions: BTreeSet::new(),
            consumed_session_order: VecDeque::new(),
        }
    }

    pub fn handle_value(&mut self, value: Value, digest: &str) -> Value {
        let request = match serde_json::from_value::<Request>(value) {
            Ok(request) => request,
            Err(_) => {
                return failure(
                    "invalid-1",
                    digest,
                    self.identity,
                    "rejected",
                    "protocol.invalid_request",
                    "Request does not match the adapter protocol",
                );
            }
        };
        if request.protocol != ADAPTER_PROTOCOL || !safe_identifier(&request.id) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "protocol.invalid_request",
                "Request protocol or identifier is invalid",
            );
        }
        match request.operation.as_str() {
            "hello" => success(
                &request.id,
                digest,
                self.identity,
                json!({
                    "operations": [
                        "hello",
                        "native-parse",
                        "roundtrip",
                        "musig2-nonce",
                        "musig2-partial-sign",
                        "musig2-aggregate"
                    ],
                    "roles": ["parser", "updater", "signer", "combiner", "finalizer"],
                    "psbtVersions": [0],
                    "scriptTypes": ["p2tr-keypath"],
                    "operationScriptTypes": {
                        "roundtrip": ["p2tr-keypath"],
                        "musig2-nonce": ["p2tr-keypath"],
                        "musig2-partial-sign": ["p2tr-keypath"],
                        "musig2-aggregate": ["p2tr-keypath"]
                    },
                    "features": [
                        "bip373-musig2-v1",
                        "bip327-csprng-nonce-v1",
                        "fixture-commitment-sha256",
                        "network-free"
                    ]
                }),
            ),
            "native-parse" => self.native_parse(&request, digest),
            "roundtrip" => self.roundtrip(&request, digest),
            "musig2-nonce" => self.nonce(&request, digest),
            "musig2-partial-sign" => self.partial_sign(&request, digest),
            "musig2-aggregate" => self.aggregate(&request, digest),
            _ => failure(
                &request.id,
                digest,
                self.identity,
                "unsupported",
                "operation.unsupported",
                "Operation is not supported by the MuSig2 adapter",
            ),
        }
    }

    fn native_parse(&self, request: &Request, digest: &str) -> Value {
        let Some(encoded) = request.payload.get("psbt").and_then(Value::as_str) else {
            return invalid_payload(
                request,
                digest,
                self.identity,
                "psbt must be a base64 string",
            );
        };
        match parse_psbt(encoded) {
            Ok(psbt) => success(
                &request.id,
                digest,
                self.identity,
                json!({
                    "accepted": true,
                    "psbtVersion": psbt.version,
                    "inputCount": psbt.inputs.len(),
                    "outputCount": psbt.outputs.len()
                }),
            ),
            Err(message) => failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "psbt.parse",
                &message,
            ),
        }
    }

    fn roundtrip(&self, request: &Request, digest: &str) -> Value {
        let Some(encoded) = request.payload.get("psbt").and_then(Value::as_str) else {
            return invalid_payload(
                request,
                digest,
                self.identity,
                "psbt must be a base64 string",
            );
        };
        let psbt = match parse_psbt(encoded) {
            Ok(psbt) => psbt,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "psbt.parse",
                    &message,
                );
            }
        };
        if let Err(message) = validate_participant_field(&psbt) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "bip373.invalid",
                &message,
            );
        }
        success(
            &request.id,
            digest,
            self.identity,
            json!({ "psbt": encoded, "byteIdentical": true }),
        )
    }

    fn nonce(&mut self, request: &Request, digest: &str) -> Value {
        let (mut psbt, session_id) = match self.signing_payload(request) {
            Ok(payload) => payload,
            Err((class, message)) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    class,
                    &message,
                );
            }
        };
        self.prune_expired_sessions();
        if self.sessions.len() >= MAX_SESSIONS {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.session_limit",
                "The signer has reached its in-memory session limit",
            );
        }
        if self.sessions.contains_key(&session_id) || self.consumed_sessions.contains(&session_id) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.nonce_reuse",
                "The MuSig2 session identifier has already been used",
            );
        }
        let key = nonce_or_partial_key(0x1b, self.identity);
        if psbt.inputs[0].unknown.contains_key(&key) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.duplicate_nonce",
                "The PSBT already contains this signer's public nonce",
            );
        }
        let message = match taproot_message(&psbt) {
            Ok(message) => message,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.sighash",
                    &message,
                );
            }
        };
        let context = key_agg_context();
        let aggregate: MusigPublicKey = context.aggregated_pubkey();
        let mut seed = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut seed) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.randomness",
                &format!("The operating system CSPRNG failed: {error}"),
            );
        }
        let secret_nonce = SecNonce::build_with_seckey(seed, self.identity.secret_key())
            .with_message(&message)
            .with_aggregated_pubkey(aggregate)
            .with_extra_input(&session_id)
            .build();
        let public_nonce = secret_nonce.public_nonce();
        let public_nonce_bytes = public_nonce.serialize();
        psbt.inputs[0]
            .unknown
            .insert(key, public_nonce_bytes.to_vec());
        self.sessions.insert(
            session_id,
            NonceSession {
                created_at: Instant::now(),
                message,
                secret_nonce,
            },
        );
        success(
            &request.id,
            digest,
            self.identity,
            json!({
                "psbt": encoded_psbt(&psbt),
                "publicNonce": encode_hex(&public_nonce_bytes)
            }),
        )
    }

    fn partial_sign(&mut self, request: &Request, digest: &str) -> Value {
        let (mut psbt, session_id) = match self.signing_payload(request) {
            Ok(payload) => payload,
            Err((class, message)) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    class,
                    &message,
                );
            }
        };
        let Some(session) = self.sessions.remove(&session_id) else {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.session_missing",
                "No live secret nonce exists for this MuSig2 session",
            );
        };
        self.mark_consumed(session_id);
        if session.created_at.elapsed() >= SESSION_TTL {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.session_expired",
                "The live secret nonce expired before partial signing",
            );
        }
        let message = match taproot_message(&psbt) {
            Ok(message) => message,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.sighash",
                    &message,
                );
            }
        };
        if message != session.message {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.session_mismatch",
                "The PSBT sighash changed after nonce generation",
            );
        }
        let public_nonces = match ordered_public_nonces(&psbt) {
            Ok(nonces) => nonces,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "bip373.nonce_set",
                    &message,
                );
            }
        };
        let aggregate_nonce = AggNonce::sum(&public_nonces);
        let context = key_agg_context();
        let partial = match sign_partial::<PartialSignature>(
            &context,
            self.identity.secret_key(),
            session.secret_nonce,
            &aggregate_nonce,
            message,
        ) {
            Ok(partial) => partial,
            Err(error) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.partial_sign",
                    &format!("MuSig2 partial signing failed: {error}"),
                );
            }
        };
        psbt.inputs[0].unknown.insert(
            nonce_or_partial_key(0x1c, self.identity),
            partial.serialize().to_vec(),
        );
        success(
            &request.id,
            digest,
            self.identity,
            json!({
                "psbt": encoded_psbt(&psbt),
                "partialSignature": encode_hex(&partial.serialize())
            }),
        )
    }

    fn aggregate(&self, request: &Request, digest: &str) -> Value {
        let mut psbt = match self.committed_psbt(request) {
            Ok(psbt) => psbt,
            Err((class, message)) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    class,
                    &message,
                );
            }
        };
        let message = match taproot_message(&psbt) {
            Ok(message) => message,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.sighash",
                    &message,
                );
            }
        };
        let public_nonces = match ordered_public_nonces(&psbt) {
            Ok(nonces) => nonces,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "bip373.nonce_set",
                    &message,
                );
            }
        };
        let partials = match ordered_partial_signatures(&psbt) {
            Ok(partials) => partials,
            Err(message) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "bip373.partial_set",
                    &message,
                );
            }
        };
        let aggregate_nonce = AggNonce::sum(&public_nonces);
        let context = key_agg_context();
        for index in 0..PARTICIPANT_PUBLIC_KEYS.len() {
            if let Err(error) = verify_partial(
                &context,
                partials[index],
                &aggregate_nonce,
                participant_public_keys()[index],
                &public_nonces[index],
                message,
            ) {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.partial_verify",
                    &format!("MuSig2 partial signature {index} is invalid: {error}"),
                );
            }
        }
        let verified_partials = partials.len();
        let final_signature: [u8; 64] =
            match aggregate_partial_signatures(&context, &aggregate_nonce, partials, message) {
                Ok(signature) => signature,
                Err(error) => {
                    return failure(
                        &request.id,
                        digest,
                        self.identity,
                        "rejected",
                        "musig2.aggregate",
                        &format!("MuSig2 aggregation failed: {error}"),
                    );
                }
            };
        let aggregate: MusigPublicKey = context.aggregated_pubkey();
        let compact_signature = match musig2::CompactSignature::from_bytes(&final_signature) {
            Ok(signature) => signature,
            Err(error) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.final_encoding",
                    &format!("Aggregated signature encoding is invalid: {error}"),
                );
            }
        };
        if let Err(error) = verify_single(aggregate, compact_signature, message) {
            return failure(
                &request.id,
                digest,
                self.identity,
                "rejected",
                "musig2.final_verify",
                &format!("Aggregated Schnorr signature is invalid: {error}"),
            );
        }
        let bitcoin_signature = match BitcoinSchnorrSignature::from_slice(&final_signature) {
            Ok(signature) => signature,
            Err(error) => {
                return failure(
                    &request.id,
                    digest,
                    self.identity,
                    "rejected",
                    "musig2.final_encoding",
                    &format!("Aggregated signature encoding is invalid: {error}"),
                );
            }
        };
        psbt.inputs[0].tap_key_sig = Some(taproot::Signature {
            signature: bitcoin_signature,
            sighash_type: TapSighashType::Default,
        });
        success(
            &request.id,
            digest,
            self.identity,
            json!({
                "psbt": encoded_psbt(&psbt),
                "tapKeySignature": encode_hex(&final_signature),
                "verifiedPartials": verified_partials
            }),
        )
    }

    fn signing_payload(&self, request: &Request) -> Result<(Psbt, String), (&'static str, String)> {
        let psbt = self.committed_psbt(request)?;
        let session_id = request
            .payload
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| safe_identifier(value))
            .ok_or((
                "protocol.invalid_payload",
                "sessionId must be a safe non-empty identifier".to_owned(),
            ))?
            .to_owned();
        Ok((psbt, session_id))
    }

    fn committed_psbt(&self, request: &Request) -> Result<Psbt, (&'static str, String)> {
        let encoded = request.payload.get("psbt").and_then(Value::as_str).ok_or((
            "protocol.invalid_payload",
            "psbt must be a base64 string".to_owned(),
        ))?;
        let fixture_id = request
            .payload
            .get("fixtureId")
            .and_then(Value::as_str)
            .ok_or((
                "protocol.invalid_payload",
                "fixtureId must be a string".to_owned(),
            ))?;
        let psbt = parse_psbt(encoded).map_err(|message| ("psbt.parse", message))?;
        self.commitments
            .verify(fixture_id, &psbt)
            .map_err(|message| ("fixture.commitment", message.to_owned()))?;
        validate_participant_field(&psbt).map_err(|message| ("bip373.invalid", message))?;
        Ok(psbt)
    }

    fn mark_consumed(&mut self, session_id: String) {
        if !self.consumed_sessions.insert(session_id.clone()) {
            return;
        }
        self.consumed_session_order.push_back(session_id);
        while self.consumed_session_order.len() > MAX_CONSUMED_SESSION_IDS {
            if let Some(expired) = self.consumed_session_order.pop_front() {
                self.consumed_sessions.remove(&expired);
            }
        }
    }

    fn prune_expired_sessions(&mut self) {
        let expired = self
            .sessions
            .iter()
            .filter(|(_, session)| session.created_at.elapsed() >= SESSION_TTL)
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in expired {
            self.sessions.remove(&session_id);
            self.mark_consumed(session_id);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    operation: String,
    payload: Map<String, Value>,
}

fn parse_psbt(encoded: &str) -> Result<Psbt, String> {
    if encoded.len() > 4 * 1024 * 1024 {
        return Err("PSBT exceeds the 4 MiB input limit".to_owned());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "PSBT is not canonical base64".to_owned())?;
    if STANDARD.encode(&bytes) != encoded {
        return Err("PSBT is not canonical base64".to_owned());
    }
    let psbt = Psbt::deserialize(&bytes).map_err(|error| format!("Invalid PSBT: {error}"))?;
    if psbt.version != 0 {
        return Err("The MuSig2 adapter supports PSBTv0 only".to_owned());
    }
    if psbt.inputs.len() != 1 {
        return Err("The MuSig2 fixture must contain exactly one input".to_owned());
    }
    Ok(psbt)
}

fn encoded_psbt(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

fn key_agg_context() -> KeyAggContext {
    let context =
        KeyAggContext::new(participant_public_keys()).expect("fixed MuSig2 key set must aggregate");
    let aggregate: MusigPublicKey = context.aggregated_pubkey();
    assert_eq!(aggregate.to_string(), AGGREGATE_PUBLIC_KEY);
    context
}

fn participant_public_keys() -> [MusigPublicKey; 2] {
    PARTICIPANT_PUBLIC_KEYS.map(|key| {
        key.parse()
            .expect("fixed MuSig2 participant public key must be valid")
    })
}

fn aggregate_bytes() -> [u8; 33] {
    AGGREGATE_PUBLIC_KEY
        .parse::<MusigPublicKey>()
        .expect("fixed aggregate public key must be valid")
        .serialize()
}

fn participant_bytes(identity: SignerIdentity) -> [u8; 33] {
    identity.public_key().serialize()
}

fn participant_field_key() -> RawKey {
    RawKey {
        type_value: 0x1a,
        key: aggregate_bytes().to_vec(),
    }
}

fn nonce_or_partial_key(type_value: u8, identity: SignerIdentity) -> RawKey {
    let mut key = Vec::with_capacity(66);
    key.extend_from_slice(&participant_bytes(identity));
    key.extend_from_slice(&aggregate_bytes());
    RawKey { type_value, key }
}

fn validate_participant_field(psbt: &Psbt) -> Result<(), String> {
    let input = &psbt.inputs[0];
    let value = input
        .unknown
        .get(&participant_field_key())
        .ok_or("The BIP373 participant field is missing")?;
    let expected = PARTICIPANT_PUBLIC_KEYS
        .iter()
        .flat_map(|key| {
            key.parse::<MusigPublicKey>()
                .expect("fixed participant key")
                .serialize()
        })
        .collect::<Vec<_>>();
    if value != &expected {
        return Err("The BIP373 participant list or ordering is invalid".to_owned());
    }
    let unexpected_participant_fields = input
        .unknown
        .keys()
        .filter(|key| key.type_value == 0x1a && *key != &participant_field_key())
        .count();
    if unexpected_participant_fields > 0 {
        return Err("The PSBT declares an unexpected MuSig2 aggregate key".to_owned());
    }
    let witness_utxo = input
        .witness_utxo
        .as_ref()
        .ok_or("The MuSig2 input is missing witness_utxo")?;
    let aggregate = aggregate_bytes();
    let mut expected_script = Vec::with_capacity(34);
    expected_script.extend_from_slice(&[0x51, 0x20]);
    expected_script.extend_from_slice(&aggregate[1..]);
    if witness_utxo.script_pubkey.as_bytes() != expected_script {
        return Err("The witness UTXO is not committed to the MuSig2 aggregate key".to_owned());
    }
    Ok(())
}

fn taproot_message(psbt: &Psbt) -> Result<[u8; 32], String> {
    let prevouts = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("Input {index} is missing witness_utxo"))
        })
        .collect::<Result<Vec<TxOut>, String>>()?;
    let sighash_type = psbt.inputs[0]
        .taproot_hash_ty()
        .map_err(|error| format!("Taproot sighash is invalid: {error}"))?;
    if sighash_type != TapSighashType::Default {
        return Err("The MuSig2 fixture requires SIGHASH_DEFAULT".to_owned());
    }
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sighash_type)
        .map_err(|error| format!("Taproot sighash failed: {error}"))?;
    Ok(sighash.to_byte_array())
}

fn ordered_public_nonces(psbt: &Psbt) -> Result<Vec<PubNonce>, String> {
    PARTICIPANT_PUBLIC_KEYS
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let identity = if index == 0 {
                SignerIdentity::One
            } else {
                SignerIdentity::Two
            };
            let value = psbt.inputs[0]
                .unknown
                .get(&nonce_or_partial_key(0x1b, identity))
                .ok_or_else(|| format!("Public nonce for participant {index} is missing"))?;
            PubNonce::from_bytes(value)
                .map_err(|_| format!("Public nonce for participant {index} is invalid"))
        })
        .collect()
}

fn ordered_partial_signatures(psbt: &Psbt) -> Result<Vec<PartialSignature>, String> {
    PARTICIPANT_PUBLIC_KEYS
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let identity = if index == 0 {
                SignerIdentity::One
            } else {
                SignerIdentity::Two
            };
            let value = psbt.inputs[0]
                .unknown
                .get(&nonce_or_partial_key(0x1c, identity))
                .ok_or_else(|| format!("Partial signature for participant {index} is missing"))?;
            PartialSignature::try_from(value.as_slice())
                .map_err(|_| format!("Partial signature for participant {index} is invalid"))
        })
        .collect()
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn implementation(digest: &str, identity: SignerIdentity) -> Value {
    json!({
        "name": identity.implementation_name(),
        "version": env!("CARGO_PKG_VERSION"),
        "artifactDigest": digest,
        "sourceRevision": SOURCE_REVISION
    })
}

fn success(id: &str, digest: &str, identity: SignerIdentity, output: Value) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": id,
        "status": "ok",
        "implementation": implementation(digest, identity),
        "output": output
    })
}

fn failure(
    id: &str,
    digest: &str,
    identity: SignerIdentity,
    status: &str,
    class: &str,
    message: &str,
) -> Value {
    json!({
        "protocol": ADAPTER_PROTOCOL,
        "id": if safe_identifier(id) { id } else { "invalid-1" },
        "status": status,
        "implementation": implementation(digest, identity),
        "error": {
            "class": class,
            "message": message,
            "retryable": false
        }
    })
}

fn invalid_payload(
    request: &Request,
    digest: &str,
    identity: SignerIdentity,
    message: &str,
) -> Value {
    failure(
        &request.id,
        digest,
        identity,
        "rejected",
        "protocol.invalid_payload",
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_keys_aggregate_to_the_committed_fixture_key() {
        let context = key_agg_context();
        let aggregate: MusigPublicKey = context.aggregated_pubkey();
        assert_eq!(aggregate.to_string(), AGGREGATE_PUBLIC_KEY);
    }

    #[test]
    fn signer_selector_is_allowlisted() {
        assert_eq!(
            SignerIdentity::from_selector("1").unwrap(),
            SignerIdentity::One
        );
        assert_eq!(
            SignerIdentity::from_selector("2").unwrap(),
            SignerIdentity::Two
        );
        assert!(SignerIdentity::from_selector("3").is_err());
    }
}
