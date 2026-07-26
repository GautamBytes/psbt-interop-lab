#!/usr/bin/env node
// @ts-check

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as bitcoin from "bitcoinjs-lib";

import {
  DERIVATION_PATH,
  DEVICE_FINGERPRINT,
  DEVICE_PATH,
  DEVICE_TYPE,
} from "./device-simulator.mjs";

export { DERIVATION_PATH, DEVICE_FINGERPRINT, DEVICE_PATH };

export const PROTOCOL = "psbt-lab.adapter/0.2";
export const MAX_LINE_BYTES = 4 * 1024 * 1024;
const MAX_PSBT_BYTES = Math.floor(((MAX_LINE_BYTES - 4096) * 3) / 4);
const ADAPTER_VERSION = "0.1.0";
const SOURCE_REVISION = "hwi-json-contract-v1+bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4";
const DEVICE_ENTRYPOINT = fileURLToPath(new URL("./device-simulator.mjs", import.meta.url));
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_OPERATION = /^[a-z][a-z-]{0,63}$/;
const SAFE_COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const DEVICE_PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

function artifactDigest() {
  const hash = createHash("sha256");
  for (const path of [fileURLToPath(import.meta.url), DEVICE_ENTRYPOINT]) {
    hash.update(readFileSync(path));
  }
  return `sha256:${hash.digest("hex")}`;
}

function implementation(digest) {
  return {
    name: "hwi-simulator",
    version: ADAPTER_VERSION,
    artifactDigest: digest,
    sourceRevision: SOURCE_REVISION,
  };
}

function success(id, digest, output) {
  return { protocol: PROTOCOL, id, status: "ok", implementation: implementation(digest), output };
}

function failure(id, digest, errorClass, message) {
  return {
    protocol: PROTOCOL,
    id,
    status: "rejected",
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

function fallbackId(value) {
  return isRecord(value) && typeof value.id === "string" && SAFE_ID.test(value.id)
    ? value.id
    : "invalid-1";
}

export function parseFixtureCommitments(raw) {
  if (raw === undefined) return { fixtureCommitments: null, fixtureCommitmentsError: "missing" };
  try {
    const value = JSON.parse(raw);
    if (
      !isRecord(value) ||
      Object.keys(value).length !== 1 ||
      typeof value["p2wpkh"] !== "string" ||
      !SAFE_COMMITMENT.test(value["p2wpkh"])
    ) {
      throw new Error("invalid");
    }
    return { fixtureCommitments: new Map([["p2wpkh", value["p2wpkh"]]]) };
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
    return {
      bytes,
      psbt: bitcoin.Psbt.fromBuffer(bytes, { network: bitcoin.networks.regtest }),
    };
  } catch {
    return null;
  }
}

function unsignedCommitment(psbt) {
  return `sha256:${createHash("sha256")
    .update(psbt.data.globalMap.unsignedTx.toBuffer())
    .digest("hex")}`;
}

function invokeDevice(args, userAction) {
  const child = spawnSync(process.execPath, [DEVICE_ENTRYPOINT, ...args], {
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: MAX_LINE_BYTES,
    env: {
      PATH: process.env["PATH"],
      PSBT_LAB_HWI_USER_ACTION: userAction,
    },
  });
  if (child.error) throw child.error;
  let output;
  try {
    output = JSON.parse(child.stdout);
  } catch {
    throw new Error("HWI simulator returned invalid JSON");
  }
  if (!isRecord(output) && !Array.isArray(output)) {
    throw new Error("HWI simulator returned an invalid response");
  }
  return output;
}

function enumerateDevice() {
  const output = invokeDevice(["enumerate"], "approve");
  if (
    !Array.isArray(output) ||
    output.length !== 1 ||
    !isRecord(output[0]) ||
    output[0].type !== DEVICE_TYPE ||
    output[0].path !== DEVICE_PATH ||
    output[0].fingerprint !== DEVICE_FINGERPRINT
  ) {
    throw new Error("Expected HWI simulator was not enumerated");
  }
}

function mapDeviceError(output) {
  const message = typeof output.error === "string" ? output.error : "HWI simulator failed";
  if (output.code === -13) return ["hwi.action_canceled", message];
  if (message === "Unexpected key origin") return ["hwi.key_origin_mismatch", message];
  return ["hwi.device_rejected", message];
}

function readCompactSize(bytes, offset) {
  if (offset >= bytes.length) throw new Error("truncated PSBT");
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  if (first === 0xfd && offset + 3 <= bytes.length) {
    const value = bytes.readUInt16LE(offset + 1);
    if (value < 0xfd) throw new Error("noncanonical PSBT");
    return [value, offset + 3];
  }
  if (first === 0xfe && offset + 5 <= bytes.length) {
    const value = bytes.readUInt32LE(offset + 1);
    if (value <= 0xffff) throw new Error("noncanonical PSBT");
    return [value, offset + 5];
  }
  throw new Error("unsupported PSBT field size");
}

function rawMaps(bytes, mapCount) {
  let offset = 5;
  const maps = [];
  for (let mapIndex = 0; mapIndex < mapCount; mapIndex += 1) {
    const entries = new Map();
    while (true) {
      const [keyLength, keyOffset] = readCompactSize(bytes, offset);
      offset = keyOffset;
      if (keyLength === 0) break;
      if (offset + keyLength > bytes.length) throw new Error("truncated PSBT key");
      const key = bytes.subarray(offset, offset + keyLength);
      offset += keyLength;
      const [valueLength, valueOffset] = readCompactSize(bytes, offset);
      offset = valueOffset;
      if (offset + valueLength > bytes.length) throw new Error("truncated PSBT value");
      const value = bytes.subarray(offset, offset + valueLength);
      offset += valueLength;
      entries.set(key.toString("hex"), value.toString("hex"));
    }
    maps.push(entries);
  }
  if (offset !== bytes.length) throw new Error("unexpected PSBT maps");
  return maps;
}

function signatureOnlyMutation(before, after) {
  if (before.psbt.inputCount !== 1 || after.psbt.inputCount !== 1) return false;
  if (
    !Buffer.from(before.psbt.data.globalMap.unsignedTx.toBuffer()).equals(
      Buffer.from(after.psbt.data.globalMap.unsignedTx.toBuffer()),
    )
  ) {
    return false;
  }
  const mapCount = 1 + before.psbt.inputCount + before.psbt.txOutputs.length;
  const beforeMaps = rawMaps(before.bytes, mapCount);
  const afterMaps = rawMaps(after.bytes, mapCount);
  const expectedSignatureKey = `02${DEVICE_PUBLIC_KEY}`;
  for (let index = 0; index < mapCount; index += 1) {
    const expected = new Map(beforeMaps[index]);
    if (index === 1) {
      const signature = afterMaps[index].get(expectedSignatureKey);
      if (!signature) return false;
      expected.set(expectedSignatureKey, signature);
    }
    if (
      expected.size !== afterMaps[index].size ||
      [...expected].some(([key, value]) => afterMaps[index].get(key) !== value)
    ) {
      return false;
    }
  }
  return true;
}

function handleHello(id, digest, payload) {
  if (!exactFields(payload, []))
    return failure(id, digest, "protocol.invalid_payload", "hello expects an empty payload");
  return success(id, digest, {
    operations: ["hello", "native-parse", "roundtrip", "sign"],
    roles: ["parser", "signer"],
    psbtVersions: [0],
    scriptTypes: ["p2wpkh"],
    operationScriptTypes: {
      roundtrip: ["p2wpkh"],
      sign: ["p2wpkh"],
    },
    features: [
      "fixture-commitment-sha256",
      "hwi-json-process-v1",
      "hwi-simulator-v1",
      "simulated-user-confirmation-v1",
      "network-free",
    ],
  });
}

function handleNativeParse(id, digest, payload) {
  if (!exactFields(payload, ["psbt"]) || typeof payload.psbt !== "string") {
    return failure(id, digest, "protocol.invalid_payload", "native-parse expects one psbt field");
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed)
    return failure(id, digest, "psbt.native_parse_failed", "bitcoinjs-lib rejected the PSBT");
  return success(id, digest, {
    nativeParser: "bitcoinjs-lib",
    psbtVersion: 0,
    inputs: parsed.psbt.inputCount,
    outputs: parsed.psbt.txOutputs.length,
  });
}

function handleRoundtrip(id, digest, payload) {
  if (!exactFields(payload, ["psbt"]) || typeof payload.psbt !== "string") {
    return failure(id, digest, "protocol.invalid_payload", "roundtrip expects one psbt field");
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed) return failure(id, digest, "psbt.parse_failed", "bitcoinjs-lib rejected the PSBT");
  const serialized = Buffer.from(parsed.psbt.toBuffer());
  return success(id, digest, {
    psbt: serialized.toString("base64"),
    byteIdentical: serialized.equals(parsed.bytes),
    psbtVersion: 0,
  });
}

function handleSign(id, digest, payload, config) {
  if (
    !exactFields(payload, ["psbt", "network", "fixtureId", "userAction"]) ||
    typeof payload.psbt !== "string" ||
    payload.network !== "regtest" ||
    payload.fixtureId !== "p2wpkh" ||
    (payload.userAction !== "approve" && payload.userAction !== "reject")
  ) {
    return failure(
      id,
      digest,
      "protocol.invalid_payload",
      "sign expects authorized p2wpkh, regtest, and userAction fields",
    );
  }
  const parsed = parsePsbt(payload.psbt);
  if (!parsed) return failure(id, digest, "psbt.parse_failed", "bitcoinjs-lib rejected the PSBT");
  if (!config.fixtureCommitments) {
    return failure(
      id,
      digest,
      `fixture.commitment_${config.fixtureCommitmentsError ?? "missing"}`,
      "Fixture commitments are unavailable",
    );
  }
  if (config.fixtureCommitments.get("p2wpkh") !== unsignedCommitment(parsed.psbt)) {
    return failure(
      id,
      digest,
      "fixture.commitment_mismatch",
      "PSBT does not match the authorized fixture",
    );
  }

  try {
    enumerateDevice();
    const output = invokeDevice(
      ["-t", DEVICE_TYPE, "-d", DEVICE_PATH, "--chain", "regtest", "signtx", payload.psbt],
      payload.userAction,
    );
    if (typeof output.error === "string") {
      const [errorClass, message] = mapDeviceError(output);
      return failure(id, digest, errorClass, message);
    }
    if (typeof output.psbt !== "string") {
      return failure(id, digest, "hwi.invalid_response", "HWI simulator omitted the signed PSBT");
    }
    const signed = parsePsbt(output.psbt);
    if (!signed || !signatureOnlyMutation(parsed, signed)) {
      return failure(
        id,
        digest,
        "hwi.invalid_mutation",
        "HWI simulator changed fields outside the expected signature",
      );
    }
    return success(id, digest, {
      psbt: output.psbt,
      signedInputs: 1,
      deviceFingerprint: DEVICE_FINGERPRINT,
    });
  } catch (error) {
    return failure(
      id,
      digest,
      "hwi.process_failed",
      error instanceof Error ? error.message : "HWI simulator process failed",
    );
  }
}

export function handleValue(value, digest = artifactDigest(), config = parseFixtureCommitments()) {
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
    case "sign":
      return handleSign(id, digest, value.payload, config);
    default:
      return failure(
        id,
        digest,
        "protocol.unsupported_operation",
        `Operation ${value.operation} is unsupported`,
      );
  }
}

async function run() {
  const digest = artifactDigest();
  const config = parseFixtureCommitments(process.env["PSBT_LAB_FIXTURE_COMMITMENTS"]);
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
        let value;
        try {
          value = JSON.parse(line);
        } catch {
          value = null;
        }
        process.stdout.write(`${JSON.stringify(handleValue(value, digest, config))}\n`);
      }
      newline = buffered.indexOf("\n");
    }
  });
  await once(process.stdin, "end");
  if (buffered.length > 0) {
    let value;
    try {
      value = JSON.parse(buffered);
    } catch {
      value = null;
    }
    process.stdout.write(`${JSON.stringify(handleValue(value, digest, config))}\n`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await run();
}
