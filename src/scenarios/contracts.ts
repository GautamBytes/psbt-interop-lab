import type {
  AdapterOperation,
  AdapterResponse,
  AdapterSuccessResponse,
  JsonValue,
} from "../protocol/types.js";
import { extractWireFacts } from "../psbt/wire-facts.js";

export interface ExpectedAdapterContract {
  name: string;
  version: string;
  sourceRevision: string;
  operations: readonly AdapterOperation[];
}

export const RUST_ADAPTER_CONTRACT = {
  name: "rust-bitcoin",
  version: "0.1.0",
  sourceRevision: "bitcoin-crate-0.32.101",
  operations: ["hello", "roundtrip", "sign", "fixture-finalize-input"],
} as const satisfies ExpectedAdapterContract;

export const BDK_ADAPTER_CONTRACT = {
  name: "bdkpython",
  version: "2.3.1",
  sourceRevision: "bdk-ffi-v2.3.1",
  operations: ["hello", "roundtrip", "finalize"],
} as const satisfies ExpectedAdapterContract;

function requireSuccess(response: AdapterResponse, operation: string): AdapterSuccessResponse {
  if (response.status !== "ok") {
    throw new Error(
      `${response.implementation.name} ${operation} failed: ${response.error.class}: ${response.error.message}`,
    );
  }
  return response;
}

function outputString(response: AdapterSuccessResponse, key: string): string {
  const value = response.output[key];
  if (typeof value !== "string") {
    throw new Error(`${response.implementation.name} omitted string output ${key}`);
  }
  return value;
}

function stringArray(value: JsonValue | undefined, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Adapter hello omitted string array ${label}`);
  }
  return value as string[];
}

function numberArray(value: JsonValue | undefined, label: string): number[] {
  if (!Array.isArray(value) || value.some((entry) => !Number.isSafeInteger(entry))) {
    throw new Error(`Adapter hello omitted integer array ${label}`);
  }
  return value as number[];
}

export function assertAdapterHello(
  response: AdapterResponse,
  expected: ExpectedAdapterContract,
): AdapterSuccessResponse {
  const success = requireSuccess(response, "hello");
  const implementation = success.implementation;
  if (implementation.name !== expected.name) throw new Error("Unexpected adapter name");
  if (implementation.version !== expected.version) throw new Error("Unexpected adapter version");
  if (implementation.sourceRevision !== expected.sourceRevision) {
    throw new Error(`Unexpected ${expected.name} source revision`);
  }
  const operations = stringArray(success.output["operations"], "operations");
  for (const operation of expected.operations) {
    if (!operations.includes(operation))
      throw new Error(`${expected.name} omitted operation ${operation}`);
  }
  const versions = numberArray(success.output["psbtVersions"], "psbtVersions");
  if (!versions.includes(0)) throw new Error(`${expected.name} does not support PSBTv0`);
  return success;
}

export function assertByteIdenticalRoundtrip(
  response: AdapterResponse,
  source: string,
  label: string,
): string {
  const success = requireSuccess(response, "roundtrip");
  const returned = outputString(success, "psbt");
  if (success.output["byteIdentical"] !== true)
    throw new Error(`${label} did not confirm byte identity`);
  extractWireFacts(source);
  extractWireFacts(returned);
  if (!Buffer.from(source, "base64").equals(Buffer.from(returned, "base64"))) {
    throw new Error(`${label} changed the PSBT during roundtrip`);
  }
  return returned;
}
