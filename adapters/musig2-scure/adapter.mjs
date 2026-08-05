#!/usr/bin/env node
// @ts-check

import { createHash, randomBytes as cryptoRandomBytes } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { schnorr } from "@noble/curves/secp256k1.js";
import * as musig2 from "@scure/btc-signer/musig2.js";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";

bitcoin.initEccLib(ecc);

export const PROTOCOL = "psbt-lab.adapter/0.2";
export const MAX_LINE_BYTES = 4 * 1024 * 1024;
const MAX_PSBT_BYTES = Math.floor(((MAX_LINE_BYTES - 4096) * 3) / 4);
const MAX_COMMITMENTS_BYTES = 4 * 1024;
const MAX_SESSIONS = 64;
const MAX_CONSUMED_SESSION_IDS = 1024;
const SESSION_TTL_MS = 15 * 60 * 1000;
const ADAPTER_VERSION = "0.1.0";
const SOURCE_REVISION = "@scure/btc-signer@2.2.0+bitcoinjs-lib@7.0.1";
const FIXTURE_ID = "p2tr-musig2";
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_OPERATION = /^[a-z][a-z0-9-]{0,63}$/;
const SAFE_COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const SECRET_TWO = Buffer.concat([Buffer.alloc(31), Buffer.from([2])]);
const PUBLIC_KEYS = [1, 2].map((scalar) => {
  const secret = Buffer.concat([Buffer.alloc(31), Buffer.from([scalar])]);
  return Buffer.from(musig2.IndividualPubkey(secret));
});
const PUBLIC_TWO = PUBLIC_KEYS[1];
const AGGREGATE_X_ONLY = Buffer.from(musig2.keyAggExport(musig2.keyAggregate(PUBLIC_KEYS)));
const AGGREGATE_COMPRESSED = Buffer.concat([Buffer.from([2]), AGGREGATE_X_ONLY]);
const EXPECTED_SCRIPT = Buffer.concat([Buffer.from([0x51, 0x20]), AGGREGATE_X_ONLY]);

function artifactDigest() {
  return `sha256:${createHash("sha256")
    .update(readFileSync(fileURLToPath(import.meta.url)))
    .digest("hex")}`;
}

function implementation(digest) {
  return {
    name: "musig2-scure-signer-2",
    version: ADAPTER_VERSION,
    artifactDigest: digest,
    sourceRevision: SOURCE_REVISION,
  };
}

function success(id, digest, output) {
  return { protocol: PROTOCOL, id, status: "ok", implementation: implementation(digest), output };
}

function failure(id, digest, errorClass, message, status = "rejected") {
  return {
    protocol: PROTOCOL,
    id: SAFE_ID.test(id) ? id : "invalid-1",
    status,
    implementation: implementation(digest),
    error: { class: errorClass, message, retryable: false },
  };
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

function fallbackId(value) {
  return isRecord(value) && typeof value.id === "string" && SAFE_ID.test(value.id)
    ? value.id
    : "invalid-1";
}

function validRequest(value) {
  return (
    exactFields(value, ["protocol", "id", "operation", "payload"]) &&
    value.protocol === PROTOCOL &&
    typeof value.id === "string" &&
    SAFE_ID.test(value.id) &&
    typeof value.operation === "string" &&
    SAFE_OPERATION.test(value.operation) &&
    isRecord(value.payload)
  );
}

export function parseFixtureCommitments(raw) {
  if (raw === undefined) return { fixtureCommitments: null, fixtureCommitmentsError: "missing" };
  if (Buffer.byteLength(raw, "utf8") > MAX_COMMITMENTS_BYTES) {
    return { fixtureCommitments: null, fixtureCommitmentsError: "invalid" };
  }
  try {
    const value = JSON.parse(raw);
    if (
      !exactFields(value, [FIXTURE_ID]) ||
      typeof value[FIXTURE_ID] !== "string" ||
      !SAFE_COMMITMENT.test(value[FIXTURE_ID])
    ) {
      throw new Error("invalid");
    }
    return { fixtureCommitments: new Map([[FIXTURE_ID, value[FIXTURE_ID]]]) };
  } catch {
    return { fixtureCommitments: null, fixtureCommitmentsError: "invalid" };
  }
}

function parsePsbt(encoded) {
  if (
    typeof encoded !== "string" ||
    encoded.length > Math.ceil((MAX_PSBT_BYTES * 4) / 3) ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  ) {
    return null;
  }
  const bytes = Buffer.from(encoded, "base64");
  if (
    bytes.length > MAX_PSBT_BYTES ||
    bytes.toString("base64") !== encoded ||
    !bytes.subarray(0, 5).equals(Buffer.from("70736274ff", "hex"))
  ) {
    return null;
  }
  try {
    const psbt = bitcoin.Psbt.fromBuffer(bytes, { network: bitcoin.networks.regtest });
    if (psbt.inputCount !== 1) return null;
    return { bytes, psbt };
  } catch {
    return null;
  }
}

function unsignedCommitment(psbt) {
  return `sha256:${createHash("sha256")
    .update(psbt.data.globalMap.unsignedTx.toBuffer())
    .digest("hex")}`;
}

function fieldKey(type, participant) {
  return Buffer.concat([
    Buffer.from([type]),
    ...(participant ? [participant] : []),
    AGGREGATE_COMPRESSED,
  ]);
}

function unknownEntries(psbt) {
  return psbt.data.inputs[0]?.unknownKeyVals ?? [];
}

function findField(psbt, type, participant) {
  const expected = fieldKey(type, participant);
  return unknownEntries(psbt).find(({ key }) => Buffer.from(key).equals(expected));
}

function addField(psbt, type, participant, value) {
  const key = fieldKey(type, participant);
  if (unknownEntries(psbt).some((entry) => Buffer.from(entry.key).equals(key))) {
    throw new Error("duplicate");
  }
  psbt.addUnknownKeyValToInput(0, { key, value: Buffer.from(value) });
}

function validateParticipantField(psbt) {
  const participantKey = fieldKey(0x1a);
  const participantFields = unknownEntries(psbt).filter(({ key }) => key[0] === 0x1a);
  const field = participantFields.find(({ key }) => Buffer.from(key).equals(participantKey));
  if (!field || participantFields.length !== 1) return false;
  if (!Buffer.from(field.value).equals(Buffer.concat(PUBLIC_KEYS))) return false;
  const witness = psbt.data.inputs[0]?.witnessUtxo;
  return Boolean(witness && Buffer.from(witness.script).equals(EXPECTED_SCRIPT));
}

function taprootMessage(psbt) {
  const input = psbt.data.inputs[0];
  if (!input?.witnessUtxo) return null;
  if (
    input.sighashType !== undefined &&
    input.sighashType !== bitcoin.Transaction.SIGHASH_DEFAULT
  ) {
    return null;
  }
  try {
    const tx = bitcoin.Transaction.fromBuffer(psbt.data.globalMap.unsignedTx.toBuffer());
    return Buffer.from(
      tx.hashForWitnessV1(
        0,
        [Buffer.from(input.witnessUtxo.script)],
        [input.witnessUtxo.value],
        bitcoin.Transaction.SIGHASH_DEFAULT,
      ),
    );
  } catch {
    return null;
  }
}

function orderedFields(psbt, type, size) {
  const values = [];
  for (const participant of PUBLIC_KEYS) {
    const field = findField(psbt, type, participant);
    if (!field || field.value.length !== size) return null;
    values.push(Buffer.from(field.value));
  }
  const allowed = new Set(
    PUBLIC_KEYS.map((participant) => fieldKey(type, participant).toString("hex")),
  );
  const fields = unknownEntries(psbt).filter(({ key }) => key[0] === type);
  if (
    fields.length !== PUBLIC_KEYS.length ||
    fields.some(({ key }) => !allowed.has(Buffer.from(key).toString("hex")))
  ) {
    return null;
  }
  return values;
}

function committedPsbt(payload, config) {
  if (
    !exactFields(payload, ["psbt", "fixtureId"]) &&
    !exactFields(payload, ["psbt", "fixtureId", "sessionId"])
  ) {
    return { parsed: null, error: "protocol.invalid_payload" };
  }
  if (typeof payload.psbt !== "string" || payload.fixtureId !== FIXTURE_ID) {
    return { parsed: null, error: "protocol.invalid_payload" };
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed) return { parsed: null, error: "psbt.parse_failed" };
  if (!config.fixtureCommitments) {
    return {
      parsed: null,
      error: `fixture.commitment_${config.fixtureCommitmentsError ?? "missing"}`,
    };
  }
  if (config.fixtureCommitments.get(FIXTURE_ID) !== unsignedCommitment(parsed.psbt)) {
    return { parsed: null, error: "fixture.commitment_mismatch" };
  }
  if (!validateParticipantField(parsed.psbt)) {
    return { parsed: null, error: "bip373.invalid" };
  }
  return { parsed, error: null };
}

function signingPayload(payload, config) {
  if (
    !exactFields(payload, ["psbt", "fixtureId", "sessionId"]) ||
    !SAFE_ID.test(payload.sessionId)
  ) {
    return { parsed: null, error: "protocol.invalid_payload" };
  }
  const result = committedPsbt(payload, config);
  return {
    parsed: result.parsed ? { ...result.parsed, sessionId: payload.sessionId } : null,
    error: result.error,
  };
}

function errorMessage(errorClass) {
  const messages = {
    "protocol.invalid_payload": "Request payload does not match the operation contract",
    "psbt.parse_failed": "bitcoinjs-lib rejected the PSBT",
    "fixture.commitment_missing": "Fixture commitments are unavailable",
    "fixture.commitment_invalid": "Fixture commitments are invalid",
    "fixture.commitment_mismatch": "PSBT does not match the authorized fixture",
    "bip373.invalid": "The BIP373 participant field or Taproot output is invalid",
  };
  return messages[errorClass] ?? "MuSig2 request was rejected";
}

function handleHello(id, digest, payload) {
  if (!exactFields(payload, [])) {
    return failure(id, digest, "protocol.invalid_payload", "hello expects an empty payload");
  }
  return success(id, digest, {
    operations: [
      "hello",
      "native-parse",
      "roundtrip",
      "musig2-nonce",
      "musig2-partial-sign",
      "musig2-aggregate",
    ],
    roles: ["parser", "updater", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2tr-keypath"],
    operationScriptTypes: {
      roundtrip: ["p2tr-keypath"],
      "musig2-nonce": ["p2tr-keypath"],
      "musig2-partial-sign": ["p2tr-keypath"],
      "musig2-aggregate": ["p2tr-keypath"],
    },
    features: [
      "bip373-musig2-v1",
      "bip327-csprng-nonce-v1",
      "fixture-commitment-sha256",
      "network-free",
    ],
  });
}

function handleNativeParse(id, digest, payload) {
  if (!exactFields(payload, ["psbt"]) || typeof payload.psbt !== "string") {
    return failure(id, digest, "protocol.invalid_payload", "native-parse expects one psbt field");
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed) {
    return failure(id, digest, "psbt.native_parse_failed", "bitcoinjs-lib rejected the PSBT");
  }
  return success(id, digest, {
    accepted: true,
    psbtVersion: 0,
    inputCount: parsed.psbt.inputCount,
    outputCount: parsed.psbt.txOutputs.length,
  });
}

function handleRoundtrip(id, digest, payload) {
  if (!exactFields(payload, ["psbt"]) || typeof payload.psbt !== "string") {
    return failure(id, digest, "protocol.invalid_payload", "roundtrip expects one psbt field");
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed) return failure(id, digest, "psbt.parse_failed", "bitcoinjs-lib rejected the PSBT");
  if (!validateParticipantField(parsed.psbt)) {
    return failure(id, digest, "bip373.invalid", "The BIP373 participant field is invalid");
  }
  const serialized = Buffer.from(parsed.psbt.toBuffer());
  return success(id, digest, {
    psbt: serialized.toString("base64"),
    byteIdentical: serialized.equals(parsed.bytes),
  });
}

export function createMusig2ScureAdapter(config = parseFixtureCommitments()) {
  const sessions = new Map();
  const consumed = new Set();
  const consumedOrder = [];
  const randomBytes = config.randomBytes ?? ((size) => cryptoRandomBytes(size));
  const now = config.now ?? (() => Date.now());

  function markConsumed(sessionId) {
    if (consumed.has(sessionId)) return;
    consumed.add(sessionId);
    consumedOrder.push(sessionId);
    while (consumedOrder.length > MAX_CONSUMED_SESSION_IDS) {
      consumed.delete(consumedOrder.shift());
    }
  }

  function pruneExpired() {
    for (const [sessionId, session] of sessions) {
      if (now() - session.createdAt >= SESSION_TTL_MS) {
        sessions.delete(sessionId);
        markConsumed(sessionId);
      }
    }
  }

  function handleNonce(id, digest, payload) {
    const { parsed, error } = signingPayload(payload, config);
    if (!parsed) return failure(id, digest, error, errorMessage(error));
    pruneExpired();
    if (sessions.has(parsed.sessionId) || consumed.has(parsed.sessionId)) {
      return failure(
        id,
        digest,
        "musig2.nonce_reuse",
        "The MuSig2 session identifier has already been used",
      );
    }
    if (sessions.size >= MAX_SESSIONS) {
      return failure(id, digest, "musig2.session_limit", "The signer reached its session limit");
    }
    if (findField(parsed.psbt, 0x1b, PUBLIC_TWO)) {
      return failure(id, digest, "musig2.duplicate_nonce", "The signer nonce already exists");
    }
    const message = taprootMessage(parsed.psbt);
    if (!message) return failure(id, digest, "musig2.sighash", "Taproot sighash failed");
    let seed;
    try {
      seed = Buffer.from(randomBytes(32));
      if (seed.length !== 32) throw new Error("invalid");
    } catch {
      return failure(id, digest, "musig2.randomness", "The operating system CSPRNG failed");
    }
    let nonces;
    try {
      nonces = musig2.nonceGen(
        PUBLIC_TWO,
        SECRET_TWO,
        AGGREGATE_X_ONLY,
        message,
        Buffer.from(parsed.sessionId),
        seed,
      );
      addField(parsed.psbt, 0x1b, PUBLIC_TWO, nonces.public);
    } catch {
      return failure(id, digest, "musig2.nonce", "MuSig2 nonce generation failed");
    }
    sessions.set(parsed.sessionId, {
      createdAt: now(),
      message: Buffer.from(message),
      secretNonce: Buffer.from(nonces.secret),
    });
    return success(id, digest, {
      psbt: parsed.psbt.toBase64(),
      publicNonce: Buffer.from(nonces.public).toString("hex"),
    });
  }

  function handlePartialSign(id, digest, payload) {
    const { parsed, error } = signingPayload(payload, config);
    if (!parsed) return failure(id, digest, error, errorMessage(error));
    const session = sessions.get(parsed.sessionId);
    if (!session) {
      return failure(
        id,
        digest,
        "musig2.session_missing",
        "No live secret nonce exists for this session",
      );
    }
    sessions.delete(parsed.sessionId);
    markConsumed(parsed.sessionId);
    if (now() - session.createdAt >= SESSION_TTL_MS) {
      return failure(id, digest, "musig2.session_expired", "The secret nonce expired");
    }
    const message = taprootMessage(parsed.psbt);
    if (!message || !Buffer.from(message).equals(session.message)) {
      return failure(id, digest, "musig2.session_mismatch", "The PSBT sighash changed");
    }
    const publicNonces = orderedFields(parsed.psbt, 0x1b, 66);
    if (!publicNonces) {
      return failure(id, digest, "bip373.nonce_set", "The public nonce set is incomplete");
    }
    if (findField(parsed.psbt, 0x1c, PUBLIC_TWO)) {
      return failure(id, digest, "musig2.duplicate_partial", "The signer partial already exists");
    }
    let partial;
    try {
      const signingSession = new musig2.Session(
        musig2.nonceAggregate(publicNonces),
        PUBLIC_KEYS,
        message,
      );
      partial = Buffer.from(signingSession.sign(Buffer.from(session.secretNonce), SECRET_TWO));
      if (!signingSession.partialSigVerify(partial, publicNonces, 1)) throw new Error("invalid");
      addField(parsed.psbt, 0x1c, PUBLIC_TWO, partial);
    } catch {
      return failure(id, digest, "musig2.partial_sign", "MuSig2 partial signing failed");
    }
    return success(id, digest, {
      psbt: parsed.psbt.toBase64(),
      partialSignature: partial.toString("hex"),
    });
  }

  function handleAggregate(id, digest, payload) {
    if (!exactFields(payload, ["psbt", "fixtureId"])) {
      return failure(
        id,
        digest,
        "protocol.invalid_payload",
        errorMessage("protocol.invalid_payload"),
      );
    }
    const { parsed, error } = committedPsbt(payload, config);
    if (!parsed) return failure(id, digest, error, errorMessage(error));
    const message = taprootMessage(parsed.psbt);
    const publicNonces = orderedFields(parsed.psbt, 0x1b, 66);
    const partials = orderedFields(parsed.psbt, 0x1c, 32);
    if (!message) return failure(id, digest, "musig2.sighash", "Taproot sighash failed");
    if (!publicNonces) {
      return failure(id, digest, "bip373.nonce_set", "The public nonce set is incomplete");
    }
    if (!partials) {
      return failure(id, digest, "bip373.partial_set", "The partial signature set is incomplete");
    }
    if (parsed.psbt.data.inputs[0]?.tapKeySig) {
      return failure(
        id,
        digest,
        "musig2.duplicate_final",
        "A Taproot key signature already exists",
      );
    }
    try {
      const signingSession = new musig2.Session(
        musig2.nonceAggregate(publicNonces),
        PUBLIC_KEYS,
        message,
      );
      for (let index = 0; index < partials.length; index += 1) {
        if (!signingSession.partialSigVerify(partials[index], publicNonces, index)) {
          return failure(
            id,
            digest,
            "musig2.partial_verify",
            `MuSig2 partial signature ${index} is invalid`,
          );
        }
      }
      const signature = Buffer.from(signingSession.partialSigAgg(partials));
      if (
        !schnorr.verify(signature, message, AGGREGATE_X_ONLY) ||
        !ecc.verifySchnorr(message, AGGREGATE_X_ONLY, signature)
      ) {
        return failure(id, digest, "musig2.final_verify", "Aggregated signature is invalid");
      }
      parsed.psbt.updateInput(0, { tapKeySig: signature });
      return success(id, digest, {
        psbt: parsed.psbt.toBase64(),
        tapKeySignature: signature.toString("hex"),
        verifiedPartials: partials.length,
      });
    } catch {
      return failure(id, digest, "musig2.aggregate", "MuSig2 aggregation failed");
    }
  }

  function handleValue(value, digest = artifactDigest()) {
    const id = fallbackId(value);
    if (!validRequest(value)) {
      return failure(id, digest, "protocol.invalid_request", "Request does not match the protocol");
    }
    switch (value.operation) {
      case "hello":
        return handleHello(id, digest, value.payload);
      case "native-parse":
        return handleNativeParse(id, digest, value.payload);
      case "roundtrip":
        return handleRoundtrip(id, digest, value.payload);
      case "musig2-nonce":
        return handleNonce(id, digest, value.payload);
      case "musig2-partial-sign":
        return handlePartialSign(id, digest, value.payload);
      case "musig2-aggregate":
        return handleAggregate(id, digest, value.payload);
      default:
        return failure(
          id,
          digest,
          "operation.unsupported",
          "Operation is not supported by the MuSig2 adapter",
          "unsupported",
        );
    }
  }

  return { handleValue };
}

async function run() {
  const digest = artifactDigest();
  const adapter = createMusig2ScureAdapter(
    parseFixtureCommitments(process.env["PSBT_LAB_FIXTURE_COMMITMENTS"]),
  );
  let buffered = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffered += chunk;
    if (Buffer.byteLength(buffered, "utf8") > MAX_LINE_BYTES) {
      process.exitCode = 1;
      process.stdin.destroy(new Error("Request line exceeded the adapter limit"));
      return;
    }
    let newline = buffered.indexOf("\n");
    while (newline >= 0) {
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      if (line.length > 0) {
        let response;
        try {
          response = adapter.handleValue(JSON.parse(line), digest);
        } catch {
          response = failure(
            "invalid-1",
            digest,
            "protocol.invalid_json",
            "Request line is not valid JSON",
          );
        }
        process.stdout.write(`${JSON.stringify(response)}\n`);
      }
      newline = buffered.indexOf("\n");
    }
  });
  await once(process.stdin, "end");
  if (buffered.length > 0) {
    let response;
    try {
      response = adapter.handleValue(JSON.parse(buffered), digest);
    } catch {
      response = failure(
        "invalid-1",
        digest,
        "protocol.invalid_json",
        "Request line is not valid JSON",
      );
    }
    process.stdout.write(`${JSON.stringify(response)}\n`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await run();
}
