import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import type {
  AdapterOperation,
  AdapterResponse,
  AdapterRole,
  AdapterScriptType,
  AdapterSuccessResponse,
  NegotiatedAdapter,
  PsbtVersion,
} from "../protocol/types.js";
import { extractWireFacts } from "../psbt/wire-facts.js";

export interface ExpectedAdapterContract {
  name: string;
  version: string;
  sourceRevision: string;
  operations: readonly AdapterOperation[];
  roles: readonly AdapterRole[];
  psbtVersions: readonly PsbtVersion[];
  scriptTypes: readonly AdapterScriptType[];
  features?: readonly string[];
}

export const RUST_ADAPTER_CONTRACT = {
  name: "rust-bitcoin",
  version: "0.1.0",
  sourceRevision: "bitcoin-crate-0.32.101",
  operations: ["hello", "roundtrip", "sign", "finalize-inputs"],
  roles: ["parser", "signer", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wsh"],
} as const satisfies ExpectedAdapterContract;

export const BDK_ADAPTER_CONTRACT = {
  name: "bdkpython",
  version: "2.3.1",
  sourceRevision: "bdk-ffi-v2.3.1",
  operations: ["hello", "inspect", "roundtrip", "finalize"],
  roles: ["parser", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wsh"],
  features: ["historical-regression.bdk-wallet-488"],
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

export function assertAdapterHello(
  response: AdapterResponse,
  expected: ExpectedAdapterContract,
): NegotiatedAdapter {
  const success = requireSuccess(response, "hello");
  const implementation = success.implementation;
  if (implementation.name !== expected.name) throw new Error("Unexpected adapter name");
  if (implementation.version !== expected.version) throw new Error("Unexpected adapter version");
  if (implementation.sourceRevision !== expected.sourceRevision) {
    throw new Error(`Unexpected ${expected.name} source revision`);
  }
  const capabilities = parseAdapterHelloCapabilities(success.output);
  requireCapabilities(expected.name, "operation", expected.operations, capabilities.operations);
  requireCapabilities(expected.name, "role", expected.roles, capabilities.roles);
  requireCapabilities(
    expected.name,
    "PSBT version",
    expected.psbtVersions,
    capabilities.psbtVersions,
  );
  requireCapabilities(expected.name, "script type", expected.scriptTypes, capabilities.scriptTypes);
  requireCapabilities(
    expected.name,
    "feature",
    expected.features ?? [],
    capabilities.features ?? [],
  );
  return { implementation, capabilities };
}

function requireCapabilities<T extends string | number>(
  adapterName: string,
  label: string,
  required: readonly T[],
  declared: readonly T[],
): void {
  for (const capability of required) {
    if (!declared.includes(capability)) {
      const rendered = label === "PSBT version" ? `PSBTv${capability}` : `${label} ${capability}`;
      throw new Error(`${adapterName} omitted required ${rendered}`);
    }
  }
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
