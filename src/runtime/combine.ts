import type { RuntimeAdapter, RuntimeProvider } from "./provider.js";

export function combineRuntimeProviders(providers: readonly RuntimeProvider[]): RuntimeProvider {
  if (providers.length === 0) throw new TypeError("At least one runtime provider is required");
  const runtime = providers.map((provider) => provider.runtime).join("+");
  let closed = false;
  let discovery: Promise<readonly RuntimeAdapter[]> | undefined;

  async function closeProviders(): Promise<void> {
    if (closed) return;
    closed = true;
    const results = await Promise.allSettled(providers.map((provider) => provider.close()));
    const errors = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (errors.length > 0) throw new AggregateError(errors, "Could not close runtime providers");
  }

  async function discover(): Promise<readonly RuntimeAdapter[]> {
    try {
      const groups = await Promise.all(providers.map((provider) => provider.adapters()));
      const adapters = groups.flat();
      const ids = new Set<string>();
      for (const adapter of adapters) {
        if (ids.has(adapter.id)) throw new Error(`Duplicate runtime adapter id ${adapter.id}`);
        ids.add(adapter.id);
      }
      return adapters;
    } catch (error) {
      await closeProviders().catch(() => undefined);
      throw error;
    }
  }

  return {
    runtime,
    adapters() {
      discovery ??= discover();
      return discovery;
    },
    close: closeProviders,
  };
}
