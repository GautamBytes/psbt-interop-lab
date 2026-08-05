import { describe, expect, test, vi } from "vitest";
import { combineRuntimeProviders } from "../../src/runtime/combine.js";
import type { RuntimeAdapter, RuntimeProvider } from "../../src/runtime/provider.js";

function provider(runtime: string, adapters: readonly RuntimeAdapter[]): RuntimeProvider {
  return {
    runtime,
    adapters: vi.fn(async () => adapters),
    close: vi.fn(async () => undefined),
  };
}

const unsupported = (id: string): RuntimeAdapter => ({
  id,
  availability: "unsupported",
  reason: "not installed",
});

describe("combineRuntimeProviders", () => {
  test("preserves provider and adapter order", async () => {
    const local = provider("local", [unsupported("local-a"), unsupported("local-b")]);
    const external = provider("external", [unsupported("wallet")]);
    const combined = combineRuntimeProviders([local, external]);

    await expect(combined.adapters()).resolves.toEqual([
      unsupported("local-a"),
      unsupported("local-b"),
      unsupported("wallet"),
    ]);
    expect(combined.runtime).toBe("local+external");

    await combined.close();
    await combined.close();
    expect(local.close).toHaveBeenCalledOnce();
    expect(external.close).toHaveBeenCalledOnce();
  });

  test("rejects duplicate adapter ids and closes every provider", async () => {
    const local = provider("local", [unsupported("shared")]);
    const external = provider("external", [unsupported("shared")]);
    const combined = combineRuntimeProviders([local, external]);

    await expect(combined.adapters()).rejects.toThrow("Duplicate runtime adapter id shared");
    expect(local.close).toHaveBeenCalledOnce();
    expect(external.close).toHaveBeenCalledOnce();
  });

  test("closes every provider when discovery fails", async () => {
    const local = provider("local", [unsupported("local")]);
    const external: RuntimeProvider = {
      runtime: "external",
      adapters: vi.fn(async () => {
        throw new Error("discovery failed");
      }),
      close: vi.fn(async () => undefined),
    };
    const combined = combineRuntimeProviders([local, external]);

    await expect(combined.adapters()).rejects.toThrow("discovery failed");
    expect(local.close).toHaveBeenCalledOnce();
    expect(external.close).toHaveBeenCalledOnce();
  });
});
