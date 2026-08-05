import { describe, expect, test, vi } from "vitest";
import type { AdapterManifest } from "../../src/conformance/manifest.js";
import type { AdapterProcessOptions } from "../../src/protocol/adapter-process.js";
import { createExternalRuntimeProvider } from "../../src/runtime/external-provider.js";

const IMPLEMENTATION = {
  name: "wallet-parser",
  version: "2.0.0",
  sourceRevision: "wallet-parser-v2",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

describe("createExternalRuntimeProvider", () => {
  test("wraps trusted external adapters without exposing process configuration", async () => {
    const child = {
      request: vi.fn(async (request: { id: string }) => ({
        protocol: "psbt-lab.adapter/0.2" as const,
        id: request.id,
        status: "ok" as const,
        implementation: IMPLEMENTATION,
        output: {},
      })),
      close: vi.fn(async () => undefined),
    };
    const createProcess = vi.fn((_options: AdapterProcessOptions) => child);
    const manifest: AdapterManifest = {
      schema: "psbt-lab.adapters/0.1",
      adapters: [
        {
          id: "wallet",
          process: {
            command: "/trusted/wallet-adapter",
            args: ["--parser"],
            cwd: "/trusted",
            env: { WALLET_MODE: "test" },
          },
          timeoutMs: 2_000,
          expected: {
            name: IMPLEMENTATION.name,
            version: IMPLEMENTATION.version,
            sourceRevision: IMPLEMENTATION.sourceRevision,
          },
        },
      ],
    };

    const runtime = createExternalRuntimeProvider(manifest, "{}", createProcess);
    const adapters = await runtime.adapters();

    expect(runtime.runtime).toBe("external");
    expect(adapters).toHaveLength(1);
    expect(adapters[0]).toMatchObject({
      id: "wallet",
      availability: "available",
      timeoutMs: 2_000,
      expected: manifest.adapters[0]?.expected,
    });
    expect(createProcess).toHaveBeenCalledOnce();
    expect(createProcess.mock.calls[0]?.[0]).toMatchObject({
      command: "/trusted/wallet-adapter",
      args: ["--parser"],
      cwd: "/trusted",
      env: {
        WALLET_MODE: "test",
        PSBT_LAB_FIXTURE_COMMITMENTS: "{}",
      },
    });
    expect(createProcess.mock.calls[0]?.[0]).not.toHaveProperty("shell");

    await runtime.close();
    await runtime.close();
    expect(child.close).toHaveBeenCalledOnce();
  });
});
