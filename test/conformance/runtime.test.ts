import { describe, expect, test, vi } from "vitest";
import { parseAdapterManifest } from "../../src/conformance/manifest.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";

const COMMITMENTS = JSON.stringify({ p2wpkh: `sha256:${"a".repeat(64)}` });

function manifest() {
  return parseAdapterManifest(
    {
      schema: "psbt-lab.adapters/0.1",
      adapters: [
        {
          id: "wallet-alias",
          command: "/usr/bin/example-adapter",
          env: { EXAMPLE_NETWORK: "regtest" },
          timeoutMs: 5_000,
          expected: {
            name: "actual-wallet-library",
            version: "2.0.0",
            sourceRevision: "actual-wallet-v2.0.0",
          },
        },
      ],
    },
    "/project",
  );
}

function helloResponse(request: AdapterRequest, version = "2.0.0"): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation: {
      name: "actual-wallet-library",
      version,
      sourceRevision: "actual-wallet-v2.0.0",
      artifactDigest: `sha256:${"b".repeat(64)}`,
    },
    output: {
      operations: ["hello", "native-parse", "roundtrip", "sign"],
      roles: ["parser", "signer"],
      psbtVersions: [0],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
        sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      },
      features: ["fixture-commitment-sha256"],
    },
  };
}

describe("external matrix runtime registry", () => {
  test("is keyed by manifest id and injects the reserved commitment environment", async () => {
    const runtime = await import("../../src/conformance/runtime.js").catch(() => undefined);
    expect(runtime, "the external runtime registry boundary is missing").toBeDefined();
    if (!runtime) return;
    const process = {
      request: vi.fn(async (request: AdapterRequest) => helloResponse(request)),
      close: vi.fn(async () => undefined),
    };
    const createProcess = vi.fn(() => process);

    const registry = runtime.createExternalAdapterRegistry(manifest(), COMMITMENTS, createProcess);

    expect([...registry.keys()]).toEqual(["wallet-alias"]);
    expect(createProcess).toHaveBeenCalledWith(
      expect.objectContaining({
        command: "/usr/bin/example-adapter",
        env: {
          EXAMPLE_NETWORK: "regtest",
          PSBT_LAB_FIXTURE_COMMITMENTS: COMMITMENTS,
        },
      }),
    );
    const negotiated = await runtime.negotiateExternalAdapter(
      registry.get("wallet-alias") as never,
    );
    expect(negotiated).toMatchObject({
      registryId: "wallet-alias",
      implementation: { name: "actual-wallet-library", version: "2.0.0" },
    });
  });

  test("fails closed when hello identity differs from the manifest", async () => {
    const runtime = await import("../../src/conformance/runtime.js").catch(() => undefined);
    expect(runtime, "the external runtime registry boundary is missing").toBeDefined();
    if (!runtime) return;
    const registry = runtime.createExternalAdapterRegistry(manifest(), COMMITMENTS, () => ({
      request: vi.fn(async (request: AdapterRequest) => helloResponse(request, "9.9.9")),
      close: vi.fn(async () => undefined),
    }));

    await expect(
      runtime.negotiateExternalAdapter(registry.get("wallet-alias") as never),
    ).rejects.toThrow(/version/i);
  });

  test("rejects manifest ids that collide with bundled registry ids", async () => {
    const runtime = await import("../../src/conformance/runtime.js").catch(() => undefined);
    expect(runtime, "the external runtime registry boundary is missing").toBeDefined();
    if (!runtime) return;

    expect(() =>
      runtime.createExternalAdapterRegistry(manifest(), COMMITMENTS, vi.fn(), ["wallet-alias"]),
    ).toThrow(/duplicate.*wallet-alias/i);
  });

  test("enforces manifest timeout and identity on every matrix request", async () => {
    const runtime = await import("../../src/conformance/runtime.js");
    const request = vi.fn(
      async (value: AdapterRequest): Promise<AdapterResponse> => ({
        ...helloResponse(value),
        implementation: {
          ...helloResponse(value).implementation,
          version: value.operation === "hello" ? "2.0.0" : "9.9.9",
        },
      }),
    );
    const registry = runtime.createExternalAdapterRegistry(manifest(), COMMITMENTS, () => ({
      request,
      close: vi.fn(async () => undefined),
    }));
    const adapter = registry.get("wallet-alias");
    expect(adapter).toBeDefined();
    if (!adapter) return;
    await runtime.negotiateExternalAdapter(adapter);

    await expect(
      adapter.process.request(
        {
          protocol: "psbt-lab.adapter/0.2",
          id: "roundtrip-check",
          operation: "roundtrip",
          payload: { psbt: "fixture" },
        },
        60_000,
      ),
    ).rejects.toThrow(/version/i);
    expect(request).toHaveBeenLastCalledWith(expect.anything(), 5_000);
  });
});
