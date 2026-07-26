import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import type {
  AdapterOperation,
  AdapterResponse,
  AdapterRole,
  AdapterScriptOperation,
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
  operationScriptTypes: Readonly<
    Partial<Record<AdapterScriptOperation, readonly AdapterScriptType[]>>
  >;
  features?: readonly string[];
}

export const RUST_ADAPTER_CONTRACT = {
  name: "rust-bitcoin",
  version: "0.1.0",
  sourceRevision: "bitcoin-crate-0.32.102",
  operations: ["hello", "native-parse", "roundtrip", "sign", "finalize-inputs"],
  roles: ["parser", "signer", "finalizer"],
  psbtVersions: [0],
  scriptTypes: [
    "p2pkh",
    "p2wpkh",
    "p2sh-p2wpkh",
    "p2sh-p2wsh",
    "p2wsh",
    "p2tr-keypath",
    "p2tr-scriptpath",
  ],
  operationScriptTypes: {
    roundtrip: [
      "p2pkh",
      "p2wpkh",
      "p2sh-p2wpkh",
      "p2sh-p2wsh",
      "p2wsh",
      "p2tr-keypath",
      "p2tr-scriptpath",
    ],
    sign: ["p2pkh", "p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    "finalize-inputs": ["p2wsh", "p2tr-scriptpath"],
  },
  features: ["fixture-commitment-sha256", "sighash-matrix-v1", "adversarial-signer-inputs-v1"],
} as const satisfies ExpectedAdapterContract;

export const GO_ADAPTER_CONTRACT = {
  name: "btcsuite-go",
  version: "v1.2.0",
  sourceRevision: "github.com/btcsuite/btcd/btcutil/psbt@v1.2.0",
  operations: [
    "hello",
    "native-parse",
    "inspect",
    "roundtrip",
    "sign",
    "finalize",
    "finalize-inputs",
  ],
  roles: ["parser", "signer", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  operationScriptTypes: {
    inspect: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    roundtrip: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
    finalize: ["p2wsh"],
    "finalize-inputs": ["p2wsh"],
  },
  features: ["fixture-commitment-sha256"],
} as const satisfies ExpectedAdapterContract;

export const BITCOINJS_ADAPTER_CONTRACT = {
  name: "bitcoinjs-lib",
  version: "1.0.0",
  sourceRevision: "bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4",
  operations: [
    "hello",
    "native-parse",
    "inspect",
    "roundtrip",
    "sign",
    "combine",
    "finalize",
    "finalize-inputs",
  ],
  roles: ["parser", "signer", "combiner", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  operationScriptTypes: {
    inspect: ["p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    roundtrip: ["p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    sign: ["p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath"],
    combine: ["p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath"],
    finalize: ["p2wsh"],
    "finalize-inputs": ["p2wsh"],
  },
  features: ["fixture-commitment-sha256", "combiner-conflicts-v1"],
} as const satisfies ExpectedAdapterContract;

export const BDK_ADAPTER_CONTRACT = {
  name: "bdkpython",
  version: "2.3.1",
  sourceRevision: "bdk-ffi-v2.3.1",
  operations: ["hello", "native-parse", "inspect", "roundtrip", "finalize"],
  roles: ["parser", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wsh"],
  operationScriptTypes: {
    inspect: ["p2wsh"],
    roundtrip: ["p2wsh"],
    finalize: ["p2wsh"],
  },
  features: ["historical-regression.bdk-wallet-488"],
} as const satisfies ExpectedAdapterContract;

export const PSBTV2_ADAPTER_CONTRACT = {
  name: "rust-psbt-v2",
  version: "0.1.0",
  sourceRevision: "rust-psbt/psbt-v2-0.3.0@8ca657c333b6b391f2501e8b31627ccbb6a67f66",
  operations: [
    "hello",
    "native-parse",
    "inspect",
    "roundtrip",
    "sign",
    "combine",
    "finalize",
    "extract",
    "construct",
  ],
  roles: ["parser", "updater", "signer", "combiner", "finalizer", "extractor", "constructor"],
  psbtVersions: [2],
  scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  operationScriptTypes: {
    inspect: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    sign: ["p2wpkh", "p2wsh"],
    combine: ["p2wpkh", "p2wsh"],
    finalize: ["p2wpkh", "p2wsh"],
    extract: ["p2wpkh", "p2wsh"],
    construct: ["p2wpkh", "p2wsh"],
  },
  features: [
    "bip370-official-vectors",
    "bounded-map-counts",
    "fixture-commitment-sha256",
    "bip370-unique-id",
    "unsigned-tx-sha256",
    "bip370-constructor",
    "bip370-locktime",
    "bip371-taproot-roundtrip",
  ],
} as const satisfies ExpectedAdapterContract;

export const LIBWALLY_ADAPTER_CONTRACT = {
  name: "libwally-core",
  version: "1.5.4",
  sourceRevision: "libwally-core-release_1.5.4@c5591834b3ae4ee4c7db9e537a9c19104ab4bf0c",
  operations: [
    "hello",
    "native-parse",
    "inspect",
    "roundtrip",
    "sign",
    "combine",
    "finalize",
    "extract",
    "convert",
  ],
  roles: ["parser", "signer", "combiner", "finalizer", "extractor"],
  psbtVersions: [0, 2],
  scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  operationScriptTypes: {
    inspect: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    sign: ["p2wpkh", "p2wsh"],
    combine: ["p2wpkh", "p2wsh"],
    finalize: ["p2wpkh", "p2wsh"],
    extract: ["p2wpkh", "p2wsh"],
    convert: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  },
  features: [
    "fixture-commitment-sha256",
    "bip370-unique-id",
    "unsigned-tx-sha256",
    "psbt-v0-v2-conversion",
    "network-free",
    "bip371-taproot-roundtrip",
  ],
} as const satisfies ExpectedAdapterContract;

export const BDK_CURRENT_ADAPTER_CONTRACT = {
  name: "bdk-wallet-current",
  version: "3.1.0",
  sourceRevision: "bdk-wallet-v3.1.0+bitcoin-0.32.102+miniscript-12.3.7",
  operations: ["hello", "native-parse", "inspect", "roundtrip", "sign", "finalize"],
  roles: ["parser", "signer", "finalizer"],
  psbtVersions: [0],
  scriptTypes: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  operationScriptTypes: {
    inspect: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    roundtrip: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    sign: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
    finalize: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
  },
  features: [
    "fixture-commitment-sha256",
    "network-free",
    "trusted-witness-utxo-authorized-fixtures-only",
  ],
} as const satisfies ExpectedAdapterContract;

function musig2AdapterContract(name: "musig2-rust-signer-1" | "musig2-rust-signer-2") {
  return {
    name,
    version: "0.1.0",
    sourceRevision: "musig2-crate-0.4.1+bitcoin-0.32.102",
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
  } as const satisfies ExpectedAdapterContract;
}

export const MUSIG2_SIGNER_ONE_ADAPTER_CONTRACT = musig2AdapterContract("musig2-rust-signer-1");
export const MUSIG2_SIGNER_TWO_ADAPTER_CONTRACT = musig2AdapterContract("musig2-rust-signer-2");

export const HWI_SIMULATOR_ADAPTER_CONTRACT = {
  name: "hwi-simulator",
  version: "0.1.0",
  sourceRevision: "hwi-json-contract-v1+bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4",
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
  for (const [operation, scriptTypes] of Object.entries(expected.operationScriptTypes)) {
    requireCapabilities(
      expected.name,
      `${operation} script type`,
      scriptTypes,
      capabilities.operationScriptTypes?.[operation as AdapterScriptOperation] ?? [],
    );
  }
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
