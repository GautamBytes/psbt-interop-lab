// @ts-check

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";

export const PROTOCOL = "psbt-lab.adapter/0.2";
export const MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MAX_PSBT_BYTES = Math.floor(((MAX_LINE_BYTES - 4096) * 3) / 4);

const ADAPTER_VERSION = "1.0.0";
const SOURCE_REVISION = "bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4";
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_OPERATION = /^[a-z][a-z-]{0,63}$/;
const ALLOWED_FIXTURES = new Set(["happy-path", "bdk-finalize-regression"]);
const TEST_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);

bitcoin.initEccLib(ecc);

const TEST_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(TEST_PRIVATE_KEY, true));
const TEST_WITNESS_SCRIPT = bitcoin.script.compile([TEST_PUBLIC_KEY, bitcoin.opcodes.OP_CHECKSIG]);
const TEST_SCRIPT_PUBKEY = bitcoin.payments.p2wsh({ redeem: { output: TEST_WITNESS_SCRIPT } }).output;

function artifactDigest() {
  return `sha256:${createHash("sha256").update(readFileSync(fileURLToPath(import.meta.url))).digest("hex")}`;
}

function implementation(digest) {
  return {
    name: "bitcoinjs-lib",
    version: ADAPTER_VERSION,
    artifactDigest: digest,
    sourceRevision: SOURCE_REVISION,
  };
}

function success(id, digest, output) {
  return { protocol: PROTOCOL, id, status: "ok", implementation: implementation(digest), output };
}

function failure(id, digest, status, errorClass, message) {
  return {
    protocol: PROTOCOL,
    id,
    status,
    implementation: implementation(digest),
    error: { class: errorClass, message, retryable: false },
  };
}

function fallbackId(value) {
  return isRecord(value) && typeof value.id === "string" && SAFE_ID.test(value.id) ? value.id : "invalid-1";
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return isRecord(value) && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function validRequest(value) {
  return (
    hasExactFields(value, ["protocol", "id", "operation", "payload"]) &&
    value.protocol === PROTOCOL &&
    typeof value.id === "string" &&
    SAFE_ID.test(value.id) &&
    typeof value.operation === "string" &&
    SAFE_OPERATION.test(value.operation) &&
    isRecord(value.payload)
  );
}

function sameBytes(left, right) {
  return left.length === right.length && Buffer.from(left).equals(Buffer.from(right));
}

function readCompactSize(bytes, offset) {
  if (offset >= bytes.length) throw new Error("truncated");
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  const length = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + length > bytes.length) throw new Error("truncated");
  let value = 0n;
  for (let index = 0; index < length; index += 1) value |= BigInt(bytes[offset + 1 + index]) << BigInt(index * 8);
  if ((first === 0xfd && value < 0xfdn) || (first === 0xfe && value <= 0xffffn) || (first === 0xff && value <= 0xffffffffn) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("noncanonical");
  }
  return [Number(value), offset + 1 + length];
}

function psbtVersion(bytes) {
  if (bytes.length < 6 || !Buffer.from(bytes.subarray(0, 5)).equals(Buffer.from("70736274ff", "hex"))) throw new Error("magic");
  let offset = 5;
  let version = 0;
  while (true) {
    const [keyLength, nextKey] = readCompactSize(bytes, offset);
    offset = nextKey;
    if (keyLength === 0) return version;
    if (keyLength > bytes.length - offset) throw new Error("truncated");
    const key = bytes.subarray(offset, offset + keyLength);
    offset += keyLength;
    const [valueLength, nextValue] = readCompactSize(bytes, offset);
    offset = nextValue;
    if (valueLength > bytes.length - offset) throw new Error("truncated");
    if (key.length === 1 && key[0] === 0xfb) {
      if (valueLength !== 4) throw new Error("version");
      version = bytes.readUInt32LE(offset);
    }
    offset += valueLength;
  }
}

function parsePsbt(encoded) {
  if (typeof encoded !== "string" || encoded.length > Math.ceil((MAX_PSBT_BYTES * 4) / 3) || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return null;
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length > MAX_PSBT_BYTES || bytes.toString("base64") !== encoded) return null;
  try {
    if (psbtVersion(bytes) !== 0) return null;
    return { bytes, psbt: bitcoin.Psbt.fromBuffer(bytes, { network: bitcoin.networks.regtest }) };
  } catch {
    return null;
  }
}

function encodedPsbt(psbt) {
  const bytes = Buffer.from(psbt.toBuffer());
  return bytes.length <= MAX_PSBT_BYTES ? bytes.toString("base64") : null;
}

function parsePsbtPayload(payload, fields) {
  if (!hasExactFields(payload, fields) || typeof payload.psbt !== "string") return { error: "protocol.invalid_payload" };
  const parsed = parsePsbt(payload.psbt);
  return parsed === null ? { error: "psbt.parse_failed" } : { parsed };
}

function validateFixturePayload(payload, fields) {
  if (!hasExactFields(payload, fields) || typeof payload.psbt !== "string" || typeof payload.network !== "string" || typeof payload.fixtureId !== "string") {
    return { error: "protocol.invalid_payload" };
  }
  if (payload.network !== "regtest") return { error: "policy.network_not_allowed" };
  if (!ALLOWED_FIXTURES.has(payload.fixtureId)) return { error: "policy.fixture_not_allowed" };
  const parsed = parsePsbt(payload.psbt);
  return parsed === null ? { error: "psbt.parse_failed" } : { parsed, fixtureId: payload.fixtureId };
}

function validateSigningScope(psbt) {
  if (psbt.inputCount === 0 || psbt.txInputs.length !== psbt.inputCount) return false;
  for (let index = 0; index < psbt.inputCount; index += 1) {
    const input = psbt.data.inputs[index];
    const txInput = psbt.txInputs[index];
    if (!input || !txInput || !input.witnessScript || !sameBytes(input.witnessScript, TEST_WITNESS_SCRIPT)) return false;

    /** @type {{ script: Uint8Array, value: bigint } | undefined} */
    let nonWitnessOutput;
    if (input.nonWitnessUtxo) {
      try {
        const funding = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
        if (!sameBytes(funding.getHash(), txInput.hash) || txInput.index >= funding.outs.length) return false;
        nonWitnessOutput = funding.outs[txInput.index];
      } catch {
        return false;
      }
    }
    const witnessOutput = input.witnessUtxo;
    if (!witnessOutput && !nonWitnessOutput) return false;
    if (witnessOutput && nonWitnessOutput && (!sameBytes(witnessOutput.script, nonWitnessOutput.script) || witnessOutput.value !== nonWitnessOutput.value)) return false;
    const fundingOutput = witnessOutput ?? nonWitnessOutput;
    if (!fundingOutput || !sameBytes(fundingOutput.script, TEST_SCRIPT_PUBKEY)) return false;
  }
  return true;
}

function failureForFixturePayload(id, digest, validation) {
  const messages = {
    "protocol.invalid_payload": "Payload has missing, invalid, or unknown fields",
    "policy.network_not_allowed": "Signing is restricted to regtest fixtures",
    "policy.fixture_not_allowed": "Unknown signing fixture",
    "psbt.parse_failed": "PSBT is not canonical PSBTv0 base64 within the adapter limit",
  };
  return failure(id, digest, "rejected", validation.error, messages[validation.error]);
}

function requestedInputIndexes(value, inputCount) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const seen = new Set();
  for (const index of value) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= inputCount || seen.has(index)) return null;
    seen.add(index);
  }
  return value;
}

function sign(psbt) {
  const signer = { publicKey: TEST_PUBLIC_KEY, sign: (hash) => Buffer.from(ecc.sign(hash, TEST_PRIVATE_KEY)) };
  let signedInputs = 0;
  for (let index = 0; index < psbt.inputCount; index += 1) {
    psbt.signInput(index, signer);
    signedInputs += 1;
  }
  return signedInputs;
}

function compactSize(value) {
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const result = Buffer.alloc(3);
    result[0] = 0xfd;
    result.writeUInt16LE(value, 1);
    return result;
  }
  throw new Error("fixture witness item is unexpectedly large");
}

function p2wshFixtureFinalizer(_inputIndex, input) {
  const signature = input.partialSig?.find((item) => sameBytes(item.pubkey, TEST_PUBLIC_KEY))?.signature;
  if (!signature) throw new Error("fixture signature is missing");
  const stack = [Buffer.from(signature), Buffer.from(TEST_WITNESS_SCRIPT)];
  return {
    finalScriptWitness: Buffer.concat([
      compactSize(stack.length),
      ...stack.flatMap((item) => [compactSize(item.length), item]),
    ]),
  };
}

function handleHello(id, digest, payload) {
  if (!hasExactFields(payload, [])) return failure(id, digest, "rejected", "protocol.invalid_payload", "hello expects an empty payload");
  return success(id, digest, {
    operations: ["hello", "inspect", "roundtrip", "sign", "combine", "finalize", "finalize-inputs"],
    roles: ["parser", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
  });
}

function handleRoundtrip(id, digest, payload) {
  const result = parsePsbtPayload(payload, ["psbt"]);
  if (result.error) return failure(id, digest, "rejected", result.error, result.error === "protocol.invalid_payload" ? "roundtrip expects one psbt field" : "PSBT is not canonical PSBTv0 base64 within the adapter limit");
  const serialized = Buffer.from(result.parsed.psbt.toBuffer());
  const encoded = encodedPsbt(result.parsed.psbt);
  if (!encoded) return failure(id, digest, "rejected", "psbt.too_large", "Serialized PSBT exceeds the response limit");
  return success(id, digest, { psbt: encoded, byteIdentical: serialized.equals(result.parsed.bytes), psbtVersion: 0 });
}

function handleInspect(id, digest, payload) {
  const result = parsePsbtPayload(payload, ["psbt"]);
  if (result.error) return failure(id, digest, "rejected", result.error, result.error === "protocol.invalid_payload" ? "inspect expects one psbt field" : "PSBT is not canonical PSBTv0 base64 within the adapter limit");
  return success(id, digest, { inputs: result.parsed.psbt.inputCount, outputs: result.parsed.psbt.txOutputs.length, psbtVersion: 0 });
}

function handleSign(id, digest, payload) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  if (!validateSigningScope(result.parsed.psbt)) return failure(id, digest, "rejected", "policy.psbt_not_authorized", "PSBT does not match the deterministic fixture scope");
  try {
    const signedInputs = sign(result.parsed.psbt);
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded) return failure(id, digest, "rejected", "psbt.too_large", "Serialized PSBT exceeds the response limit");
    return success(id, digest, { psbt: encoded, signedInputs });
  } catch {
    return failure(id, digest, "rejected", "signing.failed", "The deterministic fixture key could not sign the authorized PSBT");
  }
}

function handleCombine(id, digest, payload) {
  if (!hasExactFields(payload, ["psbts"]) || !Array.isArray(payload.psbts) || payload.psbts.length < 2 || payload.psbts.length > 16 || !payload.psbts.every((value) => typeof value === "string")) {
    return failure(id, digest, "rejected", "protocol.invalid_payload", "combine expects two to sixteen PSBT strings");
  }
  const parsed = payload.psbts.map(parsePsbt);
  if (parsed.some((value) => value === null)) return failure(id, digest, "rejected", "psbt.parse_failed", "Every PSBT must be canonical PSBTv0 base64 within the adapter limit");
  try {
    const [first, ...rest] = parsed;
    first.psbt.combine(...rest.map((value) => value.psbt));
    const encoded = encodedPsbt(first.psbt);
    if (!encoded) return failure(id, digest, "rejected", "psbt.too_large", "Combined PSBT exceeds the response limit");
    return success(id, digest, { psbt: encoded, combinedCount: parsed.length });
  } catch {
    return failure(id, digest, "rejected", "combine.failed", "PSBTs do not describe the same unsigned transaction");
  }
}

function handleFinalize(id, digest, payload) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  if (!validateSigningScope(result.parsed.psbt)) return failure(id, digest, "rejected", "policy.psbt_not_authorized", "PSBT does not match the deterministic fixture scope");
  try {
    for (let index = 0; index < result.parsed.psbt.inputCount; index += 1) result.parsed.psbt.finalizeInput(index, p2wshFixtureFinalizer);
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded) return failure(id, digest, "rejected", "psbt.too_large", "Serialized PSBT exceeds the response limit");
    return success(id, digest, { psbt: encoded, finalizedInputs: Array.from({ length: result.parsed.psbt.inputCount }, (_, index) => index) });
  } catch {
    return failure(id, digest, "rejected", "finalize.failed", "The authorized PSBT could not be finalized");
  }
}

function handleFinalizeInputs(id, digest, payload) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId", "inputIndexes"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  if (result.fixtureId !== "bdk-finalize-regression") return failure(id, digest, "rejected", "policy.fixture_not_allowed", "Selected-input finalization is reserved for the regression fixture");
  const indexes = requestedInputIndexes(payload.inputIndexes, result.parsed.psbt.inputCount);
  if (!indexes) return failure(id, digest, "rejected", "protocol.invalid_payload", "inputIndexes must be unique, non-empty, in-range safe integers");
  if (!validateSigningScope(result.parsed.psbt)) return failure(id, digest, "rejected", "policy.psbt_not_authorized", "PSBT does not match the deterministic fixture scope");
  try {
    for (const index of indexes) result.parsed.psbt.finalizeInput(index, p2wshFixtureFinalizer);
    const remainingPartialInputs = result.parsed.psbt.data.inputs.filter((input) => (input.partialSig?.length ?? 0) > 0).length;
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded) return failure(id, digest, "rejected", "psbt.too_large", "Serialized PSBT exceeds the response limit");
    return success(id, digest, { psbt: encoded, finalizedInputs: indexes, remainingPartialInputs });
  } catch {
    return failure(id, digest, "rejected", "finalize.failed", "The requested authorized inputs could not be finalized");
  }
}

export function handleValue(value, digest = artifactDigest()) {
  const id = fallbackId(value);
  if (!validRequest(value)) return failure(id, digest, "rejected", "protocol.invalid_request", "Request does not match the adapter protocol");
  switch (value.operation) {
    case "hello": return handleHello(value.id, digest, value.payload);
    case "roundtrip": return handleRoundtrip(value.id, digest, value.payload);
    case "inspect": return handleInspect(value.id, digest, value.payload);
    case "sign": return handleSign(value.id, digest, value.payload);
    case "combine": return handleCombine(value.id, digest, value.payload);
    case "finalize": return handleFinalize(value.id, digest, value.payload);
    case "finalize-inputs": return handleFinalizeInputs(value.id, digest, value.payload);
    default: return failure(value.id, digest, "unsupported", "operation.unsupported", "Operation is not implemented by the bitcoinjs-lib adapter");
  }
}

function writeResponse(value, digest) {
  process.stdout.write(`${JSON.stringify(handleValue(value, digest))}\n`);
}

async function runJsonLines() {
  const digest = artifactDigest();
  /** @type {Buffer[]} */
  let fragments = [];
  let lineBytes = 0;
  let discarding = false;
  for await (const chunk of process.stdin) {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      const length = end - start;
      if (discarding) {
        if (newline !== -1) {
          const oversized = failure("invalid-1", digest, "rejected", "protocol.line_too_large", "Request line exceeds the 4 MiB limit");
          process.stdout.write(`${JSON.stringify(oversized)}\n`);
          discarding = false;
        }
      } else if (lineBytes + length > MAX_LINE_BYTES) {
        fragments = [];
        lineBytes = 0;
        if (newline === -1) {
          discarding = true;
        } else {
          const oversized = failure("invalid-1", digest, "rejected", "protocol.line_too_large", "Request line exceeds the 4 MiB limit");
          process.stdout.write(`${JSON.stringify(oversized)}\n`);
        }
      } else {
        if (length > 0) fragments.push(chunk.subarray(start, end));
        lineBytes += length;
        if (newline !== -1) {
          const line = Buffer.concat(fragments, lineBytes);
          fragments = [];
          lineBytes = 0;
          try {
            writeResponse(JSON.parse(line.toString("utf8")), digest);
          } catch {
            const invalid = failure("invalid-1", digest, "rejected", "protocol.invalid_json", "Request line is not valid JSON");
            process.stdout.write(`${JSON.stringify(invalid)}\n`);
          }
        }
      }
      start = newline === -1 ? chunk.length : newline + 1;
    }
  }
  if (discarding) {
    const oversized = failure("invalid-1", digest, "rejected", "protocol.line_too_large", "Request line exceeds the 4 MiB limit");
    process.stdout.write(`${JSON.stringify(oversized)}\n`);
  } else if (lineBytes > 0) {
    try {
      writeResponse(JSON.parse(Buffer.concat(fragments, lineBytes).toString("utf8")), digest);
    } catch {
      const invalid = failure("invalid-1", digest, "rejected", "protocol.invalid_json", "Request line is not valid JSON");
      process.stdout.write(`${JSON.stringify(invalid)}\n`);
    }
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runJsonLines().catch(() => process.exitCode = 1);
}
