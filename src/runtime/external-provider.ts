import type { AdapterManifest } from "../conformance/manifest.js";
import {
  createExternalAdapterRegistry,
  type ExternalAdapterProcessFactory,
} from "../conformance/runtime.js";
import { AdapterProcess } from "../protocol/adapter-process.js";
import type { AvailableRuntimeAdapter, RuntimeProvider } from "./provider.js";

export function createExternalRuntimeProvider(
  manifest: AdapterManifest,
  fixtureCommitments: string,
  createProcess: ExternalAdapterProcessFactory = (options) => new AdapterProcess(options),
): RuntimeProvider {
  const registry = createExternalAdapterRegistry(manifest, fixtureCommitments, createProcess);
  const adapters: readonly AvailableRuntimeAdapter[] = [...registry.values()].map((adapter) => ({
    id: adapter.id,
    availability: "available",
    process: adapter.process,
    timeoutMs: adapter.timeoutMs,
    expected: adapter.expected,
  }));
  let closed = false;

  return {
    runtime: "external",
    async adapters() {
      return [...adapters];
    },
    async close() {
      if (closed) return;
      closed = true;
      await Promise.all(adapters.map((adapter) => adapter.process.close()));
    },
  };
}
