import { createInterface } from "node:readline";
import { Psbt } from "bitcoinjs-lib";

const PROTOCOL = "psbt-lab.adapter/0.2";
const MAX_LINE_BYTES = 4 * 1024 * 1024;
const IMPLEMENTATION = {
  name: "wallet-ci-bitcoinjs",
  version: "1.0.0",
  artifactDigest: `sha256:${"c".repeat(64)}`,
  sourceRevision: "bitcoinjs-lib-v7.0.1-example",
};
const SCRIPT_TYPES = ["p2sh-p2wpkh", "p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"];

function success(id, output) {
  return {
    protocol: PROTOCOL,
    id,
    status: "ok",
    implementation: IMPLEMENTATION,
    output,
  };
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

function safeId(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
}

function exactObject(value, keys) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0")
  );
}

function parsePsbtPayload(request) {
  if (
    !exactObject(request.payload, ["psbt"]) ||
    typeof request.payload.psbt !== "string" ||
    request.payload.psbt.length === 0
  ) {
    return undefined;
  }
  return request.payload.psbt;
}

function parseNativePsbt(encoded) {
  return Psbt.fromBase64(encoded);
}

function handleRequest(request) {
  const fallbackId = safeId(request?.id) ? request.id : "invalid-1";
  if (
    !exactObject(request, ["protocol", "id", "operation", "payload"]) ||
    request.protocol !== PROTOCOL ||
    !safeId(request.id) ||
    typeof request.operation !== "string" ||
    typeof request.payload !== "object" ||
    request.payload === null ||
    Array.isArray(request.payload)
  ) {
    return failure(
      fallbackId,
      "rejected",
      "protocol.invalid_request",
      "Request does not match the adapter protocol",
    );
  }

  if (request.operation === "hello") {
    if (!exactObject(request.payload, [])) {
      return failure(
        request.id,
        "rejected",
        "protocol.invalid_payload",
        "hello expects an empty payload",
      );
    }
    return success(request.id, {
      operations: ["hello", "native-parse", "roundtrip"],
      roles: ["parser"],
      psbtVersions: [0],
      scriptTypes: SCRIPT_TYPES,
      operationScriptTypes: { roundtrip: SCRIPT_TYPES },
      features: ["external-ci-example"],
    });
  }

  if (request.operation === "native-parse" || request.operation === "roundtrip") {
    const encoded = parsePsbtPayload(request);
    if (!encoded) {
      return failure(
        request.id,
        "rejected",
        "protocol.invalid_payload",
        `${request.operation} expects only a psbt string field`,
      );
    }
    let psbt;
    try {
      psbt = parseNativePsbt(encoded);
    } catch {
      return failure(
        request.id,
        "rejected",
        "psbt.native_parse_failed",
        "bitcoinjs-lib rejected the PSBT",
      );
    }
    if (request.operation === "native-parse") {
      return success(request.id, {
        nativeParser: IMPLEMENTATION.name,
        psbtVersion: 0,
        inputs: psbt.inputCount,
        outputs: psbt.txOutputs.length,
      });
    }
    return success(request.id, {
      psbt: psbt.toBase64(),
      byteIdentical: psbt.toBase64() === encoded,
      psbtVersion: 0,
    });
  }

  return failure(
    request.id,
    "unsupported",
    "operation.unsupported",
    "Operation is outside this adapter's declared capabilities",
  );
}

function handleLine(line) {
  if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
    return failure(
      "invalid-1",
      "rejected",
      "protocol.line_too_large",
      "Request line exceeds the adapter limit",
    );
  }
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return failure(
      "invalid-1",
      "rejected",
      "protocol.invalid_json",
      "Request line is not valid JSON",
    );
  }
  return handleRequest(request);
}

const lines = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });
for await (const line of lines) {
  process.stdout.write(`${JSON.stringify(handleLine(line))}\n`);
}
