import type { AdapterProcessOptions } from "../protocol/adapter-process.js";
import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import {
  ADAPTER_PROTOCOL,
  type AdapterRequest,
  type AdapterResponse,
  type NegotiatedAdapter,
} from "../protocol/types.js";
import {
  type AdapterManifest,
  type ExpectedExternalAdapter,
  FIXTURE_COMMITMENTS_ENV,
} from "./manifest.js";

export interface ExternalAdapterProcess {
  request(request: AdapterRequest, timeoutMs: number): Promise<AdapterResponse>;
  close(): Promise<void>;
}

export interface ExternalRuntimeAdapter {
  readonly id: string;
  readonly process: ExternalAdapterProcess;
  readonly timeoutMs: number;
  readonly expected: ExpectedExternalAdapter;
}

export type ExternalAdapterProcessFactory = (
  options: AdapterProcessOptions,
) => ExternalAdapterProcess;

function assertIdentity(
  id: string,
  response: AdapterResponse,
  expected: ExpectedExternalAdapter,
): void {
  const actual = response.implementation;
  if (actual.name !== expected.name) {
    throw new Error(`External adapter ${id} returned unexpected name ${actual.name}`);
  }
  if (actual.version !== expected.version) {
    throw new Error(`External adapter ${id} returned unexpected version ${actual.version}`);
  }
  if (actual.sourceRevision !== expected.sourceRevision) {
    throw new Error(`External adapter ${id} returned an unexpected source revision`);
  }
  if (expected.artifactDigest !== undefined && actual.artifactDigest !== expected.artifactDigest) {
    throw new Error(`External adapter ${id} returned an unexpected artifact digest`);
  }
}

export function createExternalAdapterRegistry(
  manifest: AdapterManifest,
  fixtureCommitments: string,
  createProcess: ExternalAdapterProcessFactory,
  reservedIds: readonly string[] = [],
): Map<string, ExternalRuntimeAdapter> {
  const registry = new Map<string, ExternalRuntimeAdapter>();
  const ids = new Set(reservedIds);
  for (const definition of manifest.adapters) {
    if (ids.has(definition.id)) {
      throw new Error(`Duplicate runtime adapter id ${definition.id}`);
    }
    ids.add(definition.id);
    if (definition.process.env?.[FIXTURE_COMMITMENTS_ENV] !== undefined) {
      throw new Error(`${FIXTURE_COMMITMENTS_ENV} is reserved for the matrix runner`);
    }
    const child = createProcess({
      ...definition.process,
      args: [...(definition.process.args ?? [])],
      env: {
        ...definition.process.env,
        [FIXTURE_COMMITMENTS_ENV]: fixtureCommitments,
      },
    });
    const process: ExternalAdapterProcess = {
      async request(request, timeoutMs) {
        const response = await child.request(request, Math.min(timeoutMs, definition.timeoutMs));
        assertIdentity(definition.id, response, definition.expected);
        return response;
      },
      close: () => child.close(),
    };
    registry.set(definition.id, {
      id: definition.id,
      process,
      timeoutMs: definition.timeoutMs,
      expected: definition.expected,
    });
  }
  return registry;
}

export async function negotiateExternalAdapter(
  runtime: ExternalRuntimeAdapter,
): Promise<NegotiatedAdapter> {
  const response = await runtime.process.request(
    {
      protocol: ADAPTER_PROTOCOL,
      id: "matrix-hello",
      operation: "hello",
      payload: {},
    },
    runtime.timeoutMs,
  );
  if (response.status !== "ok") {
    throw new Error(
      `External adapter ${runtime.id} rejected hello: ${response.error.class}: ${response.error.message}`,
    );
  }
  assertIdentity(runtime.id, response, runtime.expected);
  return {
    registryId: runtime.id,
    implementation: response.implementation,
    capabilities: parseAdapterHelloCapabilities(response.output),
  };
}
