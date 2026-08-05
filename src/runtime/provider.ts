import type { AdapterImplementation, AdapterRequest, AdapterResponse } from "../protocol/types.js";

export interface RuntimeAdapterProcess {
  request(request: AdapterRequest, timeoutMs: number): Promise<AdapterResponse>;
  restart?(): Promise<void>;
  close(): Promise<void>;
}

export interface AvailableRuntimeAdapter {
  readonly id: string;
  readonly availability: "available";
  readonly process: RuntimeAdapterProcess;
  readonly timeoutMs: number;
  readonly expected: Pick<AdapterImplementation, "name" | "version"> &
    Required<Pick<AdapterImplementation, "sourceRevision">> &
    Partial<Pick<AdapterImplementation, "artifactDigest">>;
}

export interface UnsupportedRuntimeAdapter {
  readonly id: string;
  readonly availability: "unsupported";
  readonly reason: string;
}

export type RuntimeAdapter = AvailableRuntimeAdapter | UnsupportedRuntimeAdapter;

export interface RuntimeProvider {
  readonly runtime: string;
  adapters(): Promise<readonly RuntimeAdapter[]>;
  close(): Promise<void>;
}
