export const ADAPTER_PROTOCOL = "psbt-lab.adapter/0.2" as const;

export const adapterOperations = [
  "hello",
  "native-parse",
  "inspect",
  "roundtrip",
  "sign",
  "combine",
  "finalize",
  "finalize-inputs",
  "extract",
  "convert",
  "construct",
  "musig2-nonce",
  "musig2-partial-sign",
  "musig2-aggregate",
  "silent-payment-send",
] as const;

export type AdapterOperation = (typeof adapterOperations)[number];

export const adapterRoles = [
  "parser",
  "updater",
  "signer",
  "combiner",
  "finalizer",
  "extractor",
  "constructor",
] as const;

export type AdapterRole = (typeof adapterRoles)[number];

export const adapterScriptTypes = [
  "p2pkh",
  "p2sh-p2wpkh",
  "p2sh-p2wsh",
  "p2wpkh",
  "p2wsh",
  "p2tr-keypath",
  "p2tr-scriptpath",
] as const;

export type AdapterScriptType = (typeof adapterScriptTypes)[number];

export type AdapterScriptOperation = Exclude<AdapterOperation, "hello" | "native-parse">;

export type OperationScriptTypes = Partial<Record<AdapterScriptOperation, AdapterScriptType[]>>;

export type PsbtVersion = 0 | 2;

export interface AdapterHelloCapabilities {
  operations: AdapterOperation[];
  roles: AdapterRole[];
  psbtVersions: PsbtVersion[];
  scriptTypes: AdapterScriptType[];
  operationScriptTypes?: OperationScriptTypes;
  features?: string[];
}

export const adapterStatuses = ["ok", "unsupported", "rejected", "crashed", "timeout"] as const;

export type AdapterStatus = (typeof adapterStatuses)[number];

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface AdapterRequest {
  protocol: typeof ADAPTER_PROTOCOL;
  id: string;
  operation: AdapterOperation;
  payload: Record<string, JsonValue>;
}

export interface AdapterImplementation {
  name: string;
  version: string;
  artifactDigest: string;
  sourceRevision?: string;
}

export interface NegotiatedAdapter {
  registryId?: string;
  implementation: AdapterImplementation;
  capabilities: AdapterHelloCapabilities;
}

export interface AdapterError {
  class: string;
  message: string;
  retryable?: boolean;
}

interface AdapterResponseBase {
  protocol: typeof ADAPTER_PROTOCOL;
  id: string;
  implementation: AdapterImplementation;
}

export interface AdapterSuccessResponse extends AdapterResponseBase {
  status: "ok";
  output: Record<string, JsonValue>;
}

export interface AdapterFailureResponse extends AdapterResponseBase {
  status: Exclude<AdapterStatus, "ok">;
  error: AdapterError;
}

export type AdapterResponse = AdapterSuccessResponse | AdapterFailureResponse;

export type ValidationResult = { ok: true } | { ok: false; errors: string[] };
