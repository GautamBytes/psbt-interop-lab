// @ts-check

import { createHash, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
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
const SAFE_COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const MAX_FIXTURE_COMMITMENTS_BYTES = 4096;
const TEST_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const SECOND_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([2])]);
/** @typedef {{ fixtureCommitments: Map<string, string> | null, fixtureCommitmentsError?: "missing" | "invalid" }} AdapterConfig */
/** @typedef {{ protocol: string, id: string, operation: string, payload: Record<string, any> }} AdapterRequest */
/** @type {Readonly<AdapterConfig>} */
const MISSING_FIXTURE_CONFIG = Object.freeze({
  fixtureCommitments: null,
  fixtureCommitmentsError: "missing",
});

bitcoin.initEccLib(ecc);

const TEST_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(TEST_PRIVATE_KEY, true));
const SECOND_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(SECOND_PRIVATE_KEY, true));
const THIRD_PUBLIC_KEY = Buffer.from(
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "hex",
);
const TEST_X_ONLY_PUBLIC_KEY = TEST_PUBLIC_KEY.subarray(1);
const TEST_WITNESS_SCRIPT = bitcoin.script.compile([TEST_PUBLIC_KEY, bitcoin.opcodes.OP_CHECKSIG]);
const TEST_SCRIPT_PUBKEY = bitcoin.payments.p2wsh({
  redeem: { output: TEST_WITNESS_SCRIPT },
}).output;
const P2WPKH_SCRIPT_PUBKEY = bitcoin.payments.p2wpkh({ pubkey: TEST_PUBLIC_KEY }).output;
const MULTISIG_WITNESS_SCRIPT = bitcoin.script.compile([
  bitcoin.opcodes.OP_2,
  TEST_PUBLIC_KEY,
  SECOND_PUBLIC_KEY,
  THIRD_PUBLIC_KEY,
  bitcoin.opcodes.OP_3,
  bitcoin.opcodes.OP_CHECKMULTISIG,
]);
const MULTISIG_SCRIPT_PUBKEY = bitcoin.payments.p2wsh({
  redeem: { output: MULTISIG_WITNESS_SCRIPT },
}).output;
const TAPROOT_SCRIPT_PUBKEY = bitcoin.payments.p2tr({
  internalPubkey: TEST_X_ONLY_PUBLIC_KEY,
}).output;
const SIGNING_POLICIES = new Map([
  [
    "happy-path",
    {
      kind: "p2wsh-single-key",
      scriptPubKey: TEST_SCRIPT_PUBKEY,
      witnessScript: TEST_WITNESS_SCRIPT,
    },
  ],
  [
    "bdk-finalize-regression",
    {
      kind: "p2wsh-single-key",
      scriptPubKey: TEST_SCRIPT_PUBKEY,
      witnessScript: TEST_WITNESS_SCRIPT,
    },
  ],
  ["p2wpkh", { kind: "p2wpkh", scriptPubKey: P2WPKH_SCRIPT_PUBKEY }],
  [
    "p2wsh-2-of-3",
    {
      kind: "p2wsh-2-of-3",
      scriptPubKey: MULTISIG_SCRIPT_PUBKEY,
      witnessScript: MULTISIG_WITNESS_SCRIPT,
    },
  ],
  ["p2tr-keypath", { kind: "p2tr-keypath", scriptPubKey: TAPROOT_SCRIPT_PUBKEY }],
]);
const ALLOWED_FIXTURES = new Set(SIGNING_POLICIES.keys());
const FINALIZABLE_FIXTURES = new Set(["happy-path", "bdk-finalize-regression"]);

function artifactDigest() {
  return `sha256:${createHash("sha256")
    .update(readFileSync(fileURLToPath(import.meta.url)))
    .digest("hex")}`;
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
  return isRecord(value) && typeof value.id === "string" && SAFE_ID.test(value.id)
    ? value.id
    : "invalid-1";
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

/**
 * @param {string | undefined} raw
 * @returns {AdapterConfig}
 */
export function parseFixtureCommitments(raw) {
  if (raw === undefined) return MISSING_FIXTURE_CONFIG;
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_FIXTURE_COMMITMENTS_BYTES) {
    return { fixtureCommitments: null, fixtureCommitmentsError: "invalid" };
  }
  try {
    const value = JSON.parse(raw);
    if (!isRecord(value)) throw new Error("invalid fixture commitments");
    const entries = Object.entries(value);
    if (
      entries.length === 0 ||
      entries.length > ALLOWED_FIXTURES.size ||
      entries.some(
        ([fixtureId, commitment]) =>
          !ALLOWED_FIXTURES.has(fixtureId) ||
          typeof commitment !== "string" ||
          !SAFE_COMMITMENT.test(commitment),
      )
    ) {
      throw new Error("invalid fixture commitments");
    }
    return { fixtureCommitments: new Map(entries) };
  } catch {
    return { fixtureCommitments: null, fixtureCommitmentsError: "invalid" };
  }
}

/**
 * @param {unknown} value
 * @returns {value is AdapterRequest}
 */
function validRequest(value) {
  return (
    isRecord(value) &&
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
  for (let index = 0; index < length; index += 1)
    value |= BigInt(bytes[offset + 1 + index]) << BigInt(index * 8);
  if (
    (first === 0xfd && value < 0xfdn) ||
    (first === 0xfe && value <= 0xffffn) ||
    (first === 0xff && value <= 0xffffffffn) ||
    value > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error("noncanonical");
  }
  return [Number(value), offset + 1 + length];
}

function psbtVersion(bytes) {
  if (
    bytes.length < 6 ||
    !Buffer.from(bytes.subarray(0, 5)).equals(Buffer.from("70736274ff", "hex"))
  )
    throw new Error("magic");
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
  if (
    typeof encoded !== "string" ||
    encoded.length > Math.ceil((MAX_PSBT_BYTES * 4) / 3) ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  )
    return null;
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
  if (!hasExactFields(payload, fields) || typeof payload.psbt !== "string")
    return { error: "protocol.invalid_payload" };
  const parsed = parsePsbt(payload.psbt);
  return parsed === null ? { error: "psbt.parse_failed" } : { parsed };
}

function validateFixturePayload(payload, fields) {
  if (
    !hasExactFields(payload, fields) ||
    typeof payload.psbt !== "string" ||
    typeof payload.network !== "string" ||
    typeof payload.fixtureId !== "string"
  ) {
    return { error: "protocol.invalid_payload" };
  }
  if (payload.network !== "regtest") return { error: "policy.network_not_allowed" };
  if (!ALLOWED_FIXTURES.has(payload.fixtureId)) return { error: "policy.fixture_not_allowed" };
  const parsed = parsePsbt(payload.psbt);
  return parsed === null
    ? { error: "psbt.parse_failed" }
    : { parsed, fixtureId: payload.fixtureId };
}

function authorizeFixture(psbt, fixtureId, config) {
  if (config?.fixtureCommitmentsError === "missing" || config === undefined) {
    return {
      class: "adapter.fixture_commitments_missing",
      message: "Fixture commitment configuration is required",
    };
  }
  if (!(config.fixtureCommitments instanceof Map)) {
    return {
      class: "adapter.fixture_commitments_invalid",
      message: "Fixture commitment configuration is invalid",
    };
  }
  const expected = config.fixtureCommitments.get(fixtureId);
  if (typeof expected !== "string") {
    return {
      class: "policy.fixture_commitment_missing",
      message: "Selected fixture is not committed for this run",
    };
  }
  if (!SAFE_COMMITMENT.test(expected)) {
    return {
      class: "adapter.fixture_commitments_invalid",
      message: "Fixture commitment configuration is invalid",
    };
  }
  const actualDigest = createHash("sha256")
    .update(psbt.data.globalMap.unsignedTx.toBuffer())
    .digest();
  const expectedDigest = Buffer.from(expected.slice("sha256:".length), "hex");
  if (!timingSafeEqual(actualDigest, expectedDigest)) {
    return {
      class: "policy.fixture_commitment_mismatch",
      message: "PSBT does not match the run-scoped fixture commitment",
    };
  }
  return null;
}

function validateFundingScope(input, txInput, expectedScriptPubKey) {
  /** @type {{ script: Uint8Array, value: bigint } | undefined} */
  let nonWitnessOutput;
  if (input.nonWitnessUtxo) {
    try {
      const funding = bitcoin.Transaction.fromBuffer(input.nonWitnessUtxo);
      if (!sameBytes(funding.getHash(), txInput.hash) || txInput.index >= funding.outs.length)
        return false;
      nonWitnessOutput = funding.outs[txInput.index];
    } catch {
      return false;
    }
  }
  const witnessOutput = input.witnessUtxo;
  if (!witnessOutput && !nonWitnessOutput) return false;
  if (
    witnessOutput &&
    nonWitnessOutput &&
    (!sameBytes(witnessOutput.script, nonWitnessOutput.script) ||
      witnessOutput.value !== nonWitnessOutput.value)
  )
    return false;
  const fundingOutput = witnessOutput ?? nonWitnessOutput;
  return fundingOutput !== undefined && sameBytes(fundingOutput.script, expectedScriptPubKey);
}

function parseWitnessStack(serialized) {
  try {
    const bytes = Buffer.from(serialized);
    const [itemCount, firstItemOffset] = readCompactSize(bytes, 0);
    if (itemCount > 100) return null;
    const items = [];
    let offset = firstItemOffset;
    for (let index = 0; index < itemCount; index += 1) {
      const [length, valueOffset] = readCompactSize(bytes, offset);
      if (length > bytes.length - valueOffset) return null;
      items.push(bytes.subarray(valueOffset, valueOffset + length));
      offset = valueOffset + length;
    }
    return offset === bytes.length ? items : null;
  } catch {
    return null;
  }
}

function expectedSignatureIsValid(psbt, inputIndex) {
  try {
    return psbt.validateSignaturesOfInput(
      inputIndex,
      (publicKey, hash, signature) => ecc.verify(hash, publicKey, signature),
      TEST_PUBLIC_KEY,
    );
  } catch {
    return false;
  }
}

function validateFinalizedInput(psbt, inputIndex, input) {
  if (!input.finalScriptWitness || input.finalScriptSig) return false;
  const witness = parseWitnessStack(input.finalScriptWitness);
  if (witness?.length !== 2 || !sameBytes(witness[1], TEST_WITNESS_SCRIPT)) return false;
  try {
    const validationCopy = psbt.clone();
    validationCopy.updateInput(inputIndex, {
      witnessScript: TEST_WITNESS_SCRIPT,
      partialSig: [{ pubkey: TEST_PUBLIC_KEY, signature: witness[0] }],
    });
    return expectedSignatureIsValid(validationCopy, inputIndex);
  } catch {
    return false;
  }
}

function hasTaprootScriptPathMetadata(input) {
  return (
    input.tapMerkleRoot !== undefined ||
    (input.tapLeafScript?.length ?? 0) > 0 ||
    (input.tapScriptSig?.length ?? 0) > 0 ||
    (input.tapBip32Derivation ?? []).some((derivation) => derivation.leafHashes.length > 0)
  );
}

function hasAnyTaprootMetadata(input) {
  return (
    input.tapInternalKey !== undefined ||
    input.tapKeySig !== undefined ||
    input.tapMerkleRoot !== undefined ||
    (input.tapLeafScript?.length ?? 0) > 0 ||
    (input.tapScriptSig?.length ?? 0) > 0 ||
    (input.tapBip32Derivation?.length ?? 0) > 0
  );
}

function validateProfileMetadata(input, policy) {
  if (input.finalScriptSig || input.redeemScript) return false;
  switch (policy.kind) {
    case "p2wsh-single-key":
    case "p2wsh-2-of-3":
      return (
        input.witnessScript !== undefined &&
        sameBytes(input.witnessScript, policy.witnessScript) &&
        !hasAnyTaprootMetadata(input)
      );
    case "p2wpkh":
      return input.witnessScript === undefined && !hasAnyTaprootMetadata(input);
    case "p2tr-keypath":
      return (
        input.witnessScript === undefined &&
        input.tapInternalKey !== undefined &&
        sameBytes(input.tapInternalKey, TEST_X_ONLY_PUBLIC_KEY) &&
        !hasTaprootScriptPathMetadata(input) &&
        (input.sighashType === undefined ||
          input.sighashType === bitcoin.Transaction.SIGHASH_DEFAULT)
      );
    default:
      return false;
  }
}

function validateSigningScope(psbt, fixtureId) {
  const policy = SIGNING_POLICIES.get(fixtureId);
  if (!policy) return false;
  if (psbt.inputCount === 0 || psbt.txInputs.length !== psbt.inputCount) return false;
  for (let index = 0; index < psbt.inputCount; index += 1) {
    const input = psbt.data.inputs[index];
    const txInput = psbt.txInputs[index];
    if (!input || !txInput || !validateFundingScope(input, txInput, policy.scriptPubKey))
      return false;
    if (input.finalScriptWitness) {
      if (policy.kind !== "p2wsh-single-key" || !validateFinalizedInput(psbt, index, input))
        return false;
    } else if (!validateProfileMetadata(input, policy)) {
      return false;
    }
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
    if (!Number.isSafeInteger(index) || index < 0 || index >= inputCount || seen.has(index))
      return null;
    seen.add(index);
  }
  return value;
}

function deterministicSigner(privateKey) {
  return {
    publicKey: Buffer.from(ecc.pointFromScalar(privateKey, true)),
    sign: (hash) => Buffer.from(ecc.sign(hash, privateKey)),
  };
}

function taprootSigner() {
  const normalizedPrivateKey =
    TEST_PUBLIC_KEY[0] === 3 ? Buffer.from(ecc.privateNegate(TEST_PRIVATE_KEY)) : TEST_PRIVATE_KEY;
  const tweak = bitcoin.crypto.taggedHash("TapTweak", TEST_X_ONLY_PUBLIC_KEY);
  const tweakedPrivateKey = ecc.privateAdd(normalizedPrivateKey, tweak);
  if (!tweakedPrivateKey) throw new Error("fixture Taproot key tweak failed");
  return {
    publicKey: Buffer.from(ecc.pointFromScalar(tweakedPrivateKey, true)),
    sign: (hash) => Buffer.from(ecc.sign(hash, tweakedPrivateKey)),
    signSchnorr: (hash) => Buffer.from(ecc.signSchnorr(hash, tweakedPrivateKey)),
  };
}

function sign(psbt, fixtureId) {
  const policy = SIGNING_POLICIES.get(fixtureId);
  if (!policy) throw new Error("fixture signing policy is missing");
  const signer =
    policy.kind === "p2wsh-2-of-3"
      ? deterministicSigner(SECOND_PRIVATE_KEY)
      : policy.kind === "p2tr-keypath"
        ? taprootSigner()
        : deterministicSigner(TEST_PRIVATE_KEY);
  const sighashTypes =
    policy.kind === "p2tr-keypath"
      ? [bitcoin.Transaction.SIGHASH_DEFAULT]
      : [bitcoin.Transaction.SIGHASH_ALL];
  let signedInputs = 0;
  for (let index = 0; index < psbt.inputCount; index += 1) {
    psbt.signInput(index, signer, sighashTypes);
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
  const signature = input.partialSig?.find((item) =>
    sameBytes(item.pubkey, TEST_PUBLIC_KEY),
  )?.signature;
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
  if (!hasExactFields(payload, []))
    return failure(
      id,
      digest,
      "rejected",
      "protocol.invalid_payload",
      "hello expects an empty payload",
    );
  return success(id, digest, {
    operations: ["hello", "inspect", "roundtrip", "sign", "combine", "finalize", "finalize-inputs"],
    roles: ["parser", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath"],
    operationScriptTypes: {
      inspect: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      combine: ["p2wsh"],
      finalize: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
    features: ["fixture-commitment-sha256"],
  });
}

function handleRoundtrip(id, digest, payload) {
  const result = parsePsbtPayload(payload, ["psbt"]);
  if (result.error)
    return failure(
      id,
      digest,
      "rejected",
      result.error,
      result.error === "protocol.invalid_payload"
        ? "roundtrip expects one psbt field"
        : "PSBT is not canonical PSBTv0 base64 within the adapter limit",
    );
  const serialized = Buffer.from(result.parsed.psbt.toBuffer());
  const encoded = encodedPsbt(result.parsed.psbt);
  if (!encoded)
    return failure(
      id,
      digest,
      "rejected",
      "psbt.too_large",
      "Serialized PSBT exceeds the response limit",
    );
  return success(id, digest, {
    psbt: encoded,
    byteIdentical: serialized.equals(result.parsed.bytes),
    psbtVersion: 0,
  });
}

function handleInspect(id, digest, payload) {
  const result = parsePsbtPayload(payload, ["psbt"]);
  if (result.error)
    return failure(
      id,
      digest,
      "rejected",
      result.error,
      result.error === "protocol.invalid_payload"
        ? "inspect expects one psbt field"
        : "PSBT is not canonical PSBTv0 base64 within the adapter limit",
    );
  return success(id, digest, {
    inputs: result.parsed.psbt.inputCount,
    outputs: result.parsed.psbt.txOutputs.length,
    psbtVersion: 0,
  });
}

function handleSign(id, digest, payload, config) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  const authorizationError = authorizeFixture(result.parsed.psbt, result.fixtureId, config);
  if (authorizationError)
    return failure(id, digest, "rejected", authorizationError.class, authorizationError.message);
  if (!validateSigningScope(result.parsed.psbt, result.fixtureId))
    return failure(
      id,
      digest,
      "rejected",
      "policy.psbt_not_authorized",
      "PSBT does not match the deterministic fixture scope",
    );
  try {
    const signedInputs = sign(result.parsed.psbt, result.fixtureId);
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded)
      return failure(
        id,
        digest,
        "rejected",
        "psbt.too_large",
        "Serialized PSBT exceeds the response limit",
      );
    return success(id, digest, { psbt: encoded, signedInputs });
  } catch {
    return failure(
      id,
      digest,
      "rejected",
      "signing.failed",
      "The deterministic fixture key could not sign the authorized PSBT",
    );
  }
}

function handleCombine(id, digest, payload) {
  if (
    !hasExactFields(payload, ["psbts"]) ||
    !Array.isArray(payload.psbts) ||
    payload.psbts.length < 2 ||
    payload.psbts.length > 16 ||
    !payload.psbts.every((value) => typeof value === "string")
  ) {
    return failure(
      id,
      digest,
      "rejected",
      "protocol.invalid_payload",
      "combine expects two to sixteen PSBT strings",
    );
  }
  const parsed = payload.psbts.map(parsePsbt);
  if (parsed.some((value) => value === null))
    return failure(
      id,
      digest,
      "rejected",
      "psbt.parse_failed",
      "Every PSBT must be canonical PSBTv0 base64 within the adapter limit",
    );
  try {
    const [first, ...rest] = parsed;
    first.psbt.combine(...rest.map((value) => value.psbt));
    const encoded = encodedPsbt(first.psbt);
    if (!encoded)
      return failure(
        id,
        digest,
        "rejected",
        "psbt.too_large",
        "Combined PSBT exceeds the response limit",
      );
    return success(id, digest, { psbt: encoded, combinedCount: parsed.length });
  } catch {
    return failure(
      id,
      digest,
      "rejected",
      "combine.failed",
      "PSBTs do not describe the same unsigned transaction",
    );
  }
}

function handleFinalize(id, digest, payload, config) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  const authorizationError = authorizeFixture(result.parsed.psbt, result.fixtureId, config);
  if (authorizationError)
    return failure(id, digest, "rejected", authorizationError.class, authorizationError.message);
  if (!FINALIZABLE_FIXTURES.has(result.fixtureId))
    return failure(
      id,
      digest,
      "rejected",
      "policy.fixture_not_allowed",
      "Finalization is restricted to the deterministic single-key P2WSH fixtures",
    );
  if (!validateSigningScope(result.parsed.psbt, result.fixtureId))
    return failure(
      id,
      digest,
      "rejected",
      "policy.psbt_not_authorized",
      "PSBT does not match the deterministic fixture scope",
    );
  const indexes = Array.from({ length: result.parsed.psbt.inputCount }, (_, index) => index).filter(
    (index) => !result.parsed.psbt.data.inputs[index].finalScriptWitness,
  );
  if (indexes.some((index) => !expectedSignatureIsValid(result.parsed.psbt, index))) {
    return failure(
      id,
      digest,
      "rejected",
      "finalize.signature_invalid",
      "An expected fixture signature is missing or invalid",
    );
  }
  try {
    for (const index of indexes) result.parsed.psbt.finalizeInput(index, p2wshFixtureFinalizer);
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded)
      return failure(
        id,
        digest,
        "rejected",
        "psbt.too_large",
        "Serialized PSBT exceeds the response limit",
      );
    return success(id, digest, { psbt: encoded, finalizedInputs: indexes });
  } catch {
    return failure(
      id,
      digest,
      "rejected",
      "finalize.failed",
      "The authorized PSBT could not be finalized",
    );
  }
}

function handleFinalizeInputs(id, digest, payload, config) {
  const result = validateFixturePayload(payload, ["psbt", "network", "fixtureId", "inputIndexes"]);
  if (result.error) return failureForFixturePayload(id, digest, result);
  if (result.fixtureId !== "bdk-finalize-regression")
    return failure(
      id,
      digest,
      "rejected",
      "policy.fixture_not_allowed",
      "Selected-input finalization is reserved for the regression fixture",
    );
  const authorizationError = authorizeFixture(result.parsed.psbt, result.fixtureId, config);
  if (authorizationError)
    return failure(id, digest, "rejected", authorizationError.class, authorizationError.message);
  const indexes = requestedInputIndexes(payload.inputIndexes, result.parsed.psbt.inputCount);
  if (!indexes)
    return failure(
      id,
      digest,
      "rejected",
      "protocol.invalid_payload",
      "inputIndexes must be unique, non-empty, in-range safe integers",
    );
  if (!validateSigningScope(result.parsed.psbt, result.fixtureId))
    return failure(
      id,
      digest,
      "rejected",
      "policy.psbt_not_authorized",
      "PSBT does not match the deterministic fixture scope",
    );
  if (indexes.some((index) => result.parsed.psbt.data.inputs[index].finalScriptWitness)) {
    return failure(
      id,
      digest,
      "rejected",
      "finalize.input_already_finalized",
      "A requested input is already finalized",
    );
  }
  if (indexes.some((index) => !expectedSignatureIsValid(result.parsed.psbt, index))) {
    return failure(
      id,
      digest,
      "rejected",
      "finalize.signature_invalid",
      "An expected fixture signature is missing or invalid",
    );
  }
  try {
    for (const index of indexes) result.parsed.psbt.finalizeInput(index, p2wshFixtureFinalizer);
    const remainingPartialInputs = result.parsed.psbt.data.inputs.filter(
      (input) => (input.partialSig?.length ?? 0) > 0,
    ).length;
    const encoded = encodedPsbt(result.parsed.psbt);
    if (!encoded)
      return failure(
        id,
        digest,
        "rejected",
        "psbt.too_large",
        "Serialized PSBT exceeds the response limit",
      );
    return success(id, digest, { psbt: encoded, finalizedInputs: indexes, remainingPartialInputs });
  } catch {
    return failure(
      id,
      digest,
      "rejected",
      "finalize.failed",
      "The requested authorized inputs could not be finalized",
    );
  }
}

/**
 * @param {unknown} value
 * @param {string} digest
 * @param {AdapterConfig} config
 * @returns {any}
 */
export function handleValue(value, digest = artifactDigest(), config = MISSING_FIXTURE_CONFIG) {
  const id = fallbackId(value);
  if (!validRequest(value))
    return failure(
      id,
      digest,
      "rejected",
      "protocol.invalid_request",
      "Request does not match the adapter protocol",
    );
  switch (value.operation) {
    case "hello":
      return handleHello(value.id, digest, value.payload);
    case "roundtrip":
      return handleRoundtrip(value.id, digest, value.payload);
    case "inspect":
      return handleInspect(value.id, digest, value.payload);
    case "sign":
      return handleSign(value.id, digest, value.payload, config);
    case "combine":
      return handleCombine(value.id, digest, value.payload);
    case "finalize":
      return handleFinalize(value.id, digest, value.payload, config);
    case "finalize-inputs":
      return handleFinalizeInputs(value.id, digest, value.payload, config);
    default:
      return failure(
        value.id,
        digest,
        "unsupported",
        "operation.unsupported",
        "Operation is not implemented by the bitcoinjs-lib adapter",
      );
  }
}

async function writeJsonLine(output, response) {
  const line = `${JSON.stringify(response)}\n`;
  if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
    throw new Error("adapter response exceeds the JSONL limit");
  }
  if (!output.write(line)) await once(output, "drain");
}

async function writeResponse(output, value, digest, config) {
  await writeJsonLine(output, handleValue(value, digest, config));
}

export async function runJsonLines(options = {}) {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const digest = options.digest ?? artifactDigest();
  const config =
    options.config ?? parseFixtureCommitments(process.env.PSBT_LAB_FIXTURE_COMMITMENTS);
  /** @type {Buffer[]} */
  let fragments = [];
  let lineBytes = 0;
  let discarding = false;
  for await (const value of input) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      const length = end - start;
      if (discarding) {
        if (newline !== -1) {
          const oversized = failure(
            "invalid-1",
            digest,
            "rejected",
            "protocol.line_too_large",
            "Request line exceeds the 4 MiB limit",
          );
          await writeJsonLine(output, oversized);
          discarding = false;
        }
      } else if (lineBytes + length > MAX_LINE_BYTES) {
        fragments = [];
        lineBytes = 0;
        if (newline === -1) {
          discarding = true;
        } else {
          const oversized = failure(
            "invalid-1",
            digest,
            "rejected",
            "protocol.line_too_large",
            "Request line exceeds the 4 MiB limit",
          );
          await writeJsonLine(output, oversized);
        }
      } else {
        if (length > 0) fragments.push(chunk.subarray(start, end));
        lineBytes += length;
        if (newline !== -1) {
          const line = Buffer.concat(fragments, lineBytes);
          fragments = [];
          lineBytes = 0;
          let parsed;
          try {
            parsed = JSON.parse(line.toString("utf8"));
          } catch {
            const invalid = failure(
              "invalid-1",
              digest,
              "rejected",
              "protocol.invalid_json",
              "Request line is not valid JSON",
            );
            await writeJsonLine(output, invalid);
            parsed = undefined;
          }
          if (parsed !== undefined) await writeResponse(output, parsed, digest, config);
        }
      }
      start = newline === -1 ? chunk.length : newline + 1;
    }
  }
  if (discarding) {
    const oversized = failure(
      "invalid-1",
      digest,
      "rejected",
      "protocol.line_too_large",
      "Request line exceeds the 4 MiB limit",
    );
    await writeJsonLine(output, oversized);
  } else if (lineBytes > 0) {
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(fragments, lineBytes).toString("utf8"));
    } catch {
      const invalid = failure(
        "invalid-1",
        digest,
        "rejected",
        "protocol.invalid_json",
        "Request line is not valid JSON",
      );
      await writeJsonLine(output, invalid);
      parsed = undefined;
    }
    if (parsed !== undefined) await writeResponse(output, parsed, digest, config);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runJsonLines().catch(() => (process.exitCode = 1));
}
