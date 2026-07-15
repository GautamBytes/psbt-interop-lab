export const ADAPTER_PROTOCOL = "psbt-lab.adapter/0.1" as const;

export const adapterOperations = [
  "hello",
  "inspect",
  "roundtrip",
  "sign",
  "finalize",
  "fixture-finalize-input",
] as const;

export type AdapterOperation = (typeof adapterOperations)[number];

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
