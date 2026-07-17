import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const PROTOCOL = "psbt-lab.adapter/0.2";
const MAX_LINE_BYTES = 4 * 1024 * 1024;
const MAX_PSBT_BYTES = 3 * 1024 * 1024;
const MAGIC = Buffer.from("70736274ff", "hex");
const SOURCE_REVISION = "bundled-js-v1";
const ARTIFACT_DIGEST = `sha256:${createHash("sha256")
  .update(readFileSync(fileURLToPath(import.meta.url)))
  .digest("hex")}`;
const IMPLEMENTATION = {
  name: "psbt-lab-js",
  version: "0.1.0",
  sourceRevision: SOURCE_REVISION,
  artifactDigest: ARTIFACT_DIGEST,
};

class PsbtParseError extends Error {}

function requireBytes(buffer, offset, count, label) {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(count) ||
    offset + count > buffer.length
  ) {
    throw new PsbtParseError(`${label} is truncated`);
  }
}

function compactSize(buffer, offset, label) {
  requireBytes(buffer, offset, 1, label);
  const marker = buffer[offset];
  if (marker < 0xfd) return { value: marker, nextOffset: offset + 1 };
  if (marker === 0xfd) {
    requireBytes(buffer, offset + 1, 2, label);
    const value = buffer.readUInt16LE(offset + 1);
    if (value < 0xfd) throw new PsbtParseError(`${label} is not canonical`);
    return { value, nextOffset: offset + 3 };
  }
  if (marker === 0xfe) {
    requireBytes(buffer, offset + 1, 4, label);
    const value = buffer.readUInt32LE(offset + 1);
    if (value <= 0xffff) throw new PsbtParseError(`${label} is not canonical`);
    return { value, nextOffset: offset + 5 };
  }
  requireBytes(buffer, offset + 1, 8, label);
  const value = buffer.readBigUInt64LE(offset + 1);
  if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new PsbtParseError(`${label} is non-canonical or too large`);
  }
  return { value: Number(value), nextOffset: offset + 9 };
}

function decodeCanonicalBase64(encoded) {
  if (
    typeof encoded !== "string" ||
    encoded.length === 0 ||
    encoded.length > 4 * Math.ceil(MAX_PSBT_BYTES / 3) ||
    encoded.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    throw new PsbtParseError("PSBT must be bounded canonical base64");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length > MAX_PSBT_BYTES || bytes.toString("base64") !== encoded) {
    throw new PsbtParseError("PSBT must be bounded canonical base64");
  }
  return bytes;
}

function parseMap(buffer, startOffset) {
  const entries = [];
  const keys = new Set();
  let offset = startOffset;
  while (true) {
    const keyLength = compactSize(buffer, offset, "PSBT key length");
    offset = keyLength.nextOffset;
    if (keyLength.value === 0) return { entries, nextOffset: offset };
    requireBytes(buffer, offset, keyLength.value, "PSBT key");
    const key = buffer.subarray(offset, offset + keyLength.value);
    offset += keyLength.value;
    const keyId = key.toString("hex");
    if (keys.has(keyId)) throw new PsbtParseError("PSBT map contains a duplicate key");
    keys.add(keyId);
    compactSize(key, 0, "PSBT key type");

    const valueLength = compactSize(buffer, offset, "PSBT value length");
    offset = valueLength.nextOffset;
    requireBytes(buffer, offset, valueLength.value, "PSBT value");
    const value = buffer.subarray(offset, offset + valueLength.value);
    offset += valueLength.value;
    entries.push({ key: Buffer.from(key), value: Buffer.from(value) });
  }
}

function singleton(entries, type) {
  return entries.find(({ key }) => key.length === 1 && key[0] === type)?.value;
}

function requiredSingleton(entries, type, length, label) {
  const value = singleton(entries, type);
  if (value === undefined) throw new PsbtParseError(`PSBTv2 requires ${label}`);
  if (length !== undefined && value.length !== length) {
    throw new PsbtParseError(`${label} must contain ${length} bytes`);
  }
  return value;
}

function compactSizeValue(value, label) {
  const decoded = compactSize(value, 0, label);
  if (decoded.nextOffset !== value.length) throw new PsbtParseError(`${label} has trailing bytes`);
  return decoded.value;
}

function unsignedTransactionCounts(transaction) {
  let offset = 0;
  requireBytes(transaction, offset, 4, "transaction version");
  offset += 4;
  const inputs = compactSize(transaction, offset, "transaction input count");
  offset = inputs.nextOffset;
  if (inputs.value === 0) throw new PsbtParseError("unsigned transaction must contain an input");
  for (let index = 0; index < inputs.value; index += 1) {
    requireBytes(transaction, offset, 36, "transaction input");
    offset += 36;
    const script = compactSize(transaction, offset, "transaction scriptSig length");
    offset = script.nextOffset;
    if (script.value !== 0)
      throw new PsbtParseError("unsigned transaction scriptSig must be empty");
    requireBytes(transaction, offset, 4, "transaction sequence");
    offset += 4;
  }
  const outputs = compactSize(transaction, offset, "transaction output count");
  offset = outputs.nextOffset;
  for (let index = 0; index < outputs.value; index += 1) {
    requireBytes(transaction, offset, 8, "transaction output amount");
    offset += 8;
    const script = compactSize(transaction, offset, "transaction output script length");
    offset = script.nextOffset;
    requireBytes(transaction, offset, script.value, "transaction output script");
    offset += script.value;
  }
  requireBytes(transaction, offset, 4, "transaction locktime");
  offset += 4;
  if (offset !== transaction.length)
    throw new PsbtParseError("unsigned transaction has trailing bytes");
  return { inputs: inputs.value, outputs: outputs.value };
}

function parsePsbt(encoded) {
  const bytes = decodeCanonicalBase64(encoded);
  requireBytes(bytes, 0, MAGIC.length, "PSBT magic");
  if (!bytes.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new PsbtParseError("invalid PSBT magic bytes");
  }
  const globalMap = parseMap(bytes, MAGIC.length);
  const versionValue = singleton(globalMap.entries, 0xfb);
  let psbtVersion = 0;
  if (versionValue !== undefined) {
    if (versionValue.length !== 4) throw new PsbtParseError("PSBT version must contain four bytes");
    psbtVersion = versionValue.readUInt32LE(0);
  }
  let counts;
  if (psbtVersion === 0) {
    const transaction = singleton(globalMap.entries, 0x00);
    if (transaction === undefined)
      throw new PsbtParseError("PSBTv0 requires an unsigned transaction");
    counts = unsignedTransactionCounts(transaction);
  } else if (psbtVersion === 2) {
    if (singleton(globalMap.entries, 0x00) !== undefined) {
      throw new PsbtParseError("PSBTv2 must not contain a global unsigned transaction");
    }
    requiredSingleton(globalMap.entries, 0x02, 4, "a global transaction version");
    const inputs = singleton(globalMap.entries, 0x04);
    const outputs = singleton(globalMap.entries, 0x05);
    if (inputs === undefined || outputs === undefined) {
      throw new PsbtParseError("PSBTv2 requires declared map counts");
    }
    counts = {
      inputs: compactSizeValue(inputs, "PSBTv2 input count"),
      outputs: compactSizeValue(outputs, "PSBTv2 output count"),
    };
  } else {
    throw new PsbtParseError(`unsupported PSBT version ${psbtVersion}`);
  }

  let offset = globalMap.nextOffset;
  const inputMaps = [];
  const outputMaps = [];
  for (let index = 0; index < counts.inputs; index += 1) {
    const map = parseMap(bytes, offset);
    inputMaps.push(map.entries);
    offset = map.nextOffset;
  }
  for (let index = 0; index < counts.outputs; index += 1) {
    const map = parseMap(bytes, offset);
    outputMaps.push(map.entries);
    offset = map.nextOffset;
  }
  if (psbtVersion === 2) {
    for (const entries of inputMaps) {
      requiredSingleton(entries, 0x0e, 32, "an input previous transaction ID");
      requiredSingleton(entries, 0x0f, 4, "an input previous output index");
      const sequence = singleton(entries, 0x10);
      if (sequence !== undefined && sequence.length !== 4) {
        throw new PsbtParseError("an input sequence must contain four bytes");
      }
    }
    for (const entries of outputMaps) {
      requiredSingleton(entries, 0x03, 8, "an output amount");
      requiredSingleton(entries, 0x04, undefined, "an output script");
    }
  }
  if (offset !== bytes.length) throw new PsbtParseError("PSBT has trailing bytes or maps");
  return { psbtVersion, inputs: counts.inputs, outputs: counts.outputs };
}

function success(id, output) {
  return { protocol: PROTOCOL, id, status: "ok", implementation: IMPLEMENTATION, output };
}

function failure(id, status, errorClass, message) {
  return {
    protocol: PROTOCOL,
    id,
    status,
    implementation: IMPLEMENTATION,
    error: { class: errorClass, message, retryable: false },
  };
}

function handle(request) {
  const id = typeof request?.id === "string" ? request.id : "invalid-request";
  if (
    request?.protocol !== PROTOCOL ||
    typeof request?.payload !== "object" ||
    request.payload === null
  ) {
    return failure(
      id,
      "rejected",
      "protocol.invalid_request",
      "Request does not match the adapter protocol",
    );
  }
  if (request.operation === "hello") {
    return success(id, {
      operations: ["hello", "native-parse", "roundtrip"],
      roles: ["parser"],
      psbtVersions: [0, 2],
      scriptTypes: ["p2wpkh", "p2wsh"],
      operationScriptTypes: { roundtrip: ["p2wpkh", "p2wsh"] },
      features: ["dockerless", "public-fixtures-only"],
    });
  }
  if (request.operation !== "native-parse" && request.operation !== "roundtrip") {
    return failure(
      id,
      "unsupported",
      "operation.unsupported",
      "Operation is not supported locally",
    );
  }
  if (Object.keys(request.payload).length !== 1 || typeof request.payload.psbt !== "string") {
    return failure(
      id,
      "rejected",
      "protocol.invalid_payload",
      "Operation expects only a PSBT string",
    );
  }
  try {
    const parsed = parsePsbt(request.payload.psbt);
    if (request.operation === "native-parse") {
      return success(id, { nativeParser: IMPLEMENTATION.name, ...parsed });
    }
    return success(id, {
      psbt: request.payload.psbt,
      byteIdentical: true,
      psbtVersion: parsed.psbtVersion,
    });
  } catch (error) {
    return failure(
      id,
      "rejected",
      request.operation === "native-parse" ? "psbt.native_parse_failed" : "psbt.parse_failed",
      error instanceof Error ? error.message : "PSBT parsing failed",
    );
  }
}

function writeResponse(response) {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

let pending = Buffer.alloc(0);
for await (const chunk of process.stdin) {
  pending = Buffer.concat([pending, chunk]);
  if (pending.length > MAX_LINE_BYTES && !pending.includes(0x0a)) {
    throw new Error("Adapter request exceeds the line limit");
  }
  let newline = pending.indexOf(0x0a);
  while (newline !== -1) {
    const line = pending.subarray(0, newline);
    pending = pending.subarray(newline + 1);
    if (line.length > MAX_LINE_BYTES) throw new Error("Adapter request exceeds the line limit");
    try {
      writeResponse(handle(JSON.parse(line.toString("utf8"))));
    } catch {
      writeResponse(
        failure("invalid-json", "rejected", "protocol.invalid_json", "Request is not valid JSON"),
      );
    }
    newline = pending.indexOf(0x0a);
  }
}
