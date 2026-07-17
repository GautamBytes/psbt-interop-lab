import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { loadAdapterManifest, parseAdapterManifest } from "../../src/conformance/manifest.js";

function validManifest() {
  return {
    schema: "psbt-lab.adapters/0.1",
    adapters: [
      {
        id: "sample-wallet",
        command: "/usr/bin/sample-wallet-adapter",
        args: ["--stdio"],
        cwd: "./adapter",
        env: { SAMPLE_NETWORK: "regtest" },
        timeoutMs: 5_000,
        expected: {
          name: "sample-wallet",
          version: "1.0.0",
          sourceRevision: "sample-wallet-v1.0.0",
        },
      },
    ],
  };
}

describe("external adapter manifest", () => {
  test("parses a strict manifest and resolves cwd from the manifest directory", () => {
    const parsed = parseAdapterManifest(validManifest(), "/project/config");

    expect(parsed).toMatchObject({
      schema: "psbt-lab.adapters/0.1",
      adapters: [
        {
          id: "sample-wallet",
          process: {
            command: "/usr/bin/sample-wallet-adapter",
            args: ["--stdio"],
            cwd: "/project/config/adapter",
            env: { SAMPLE_NETWORK: "regtest" },
          },
          timeoutMs: 5_000,
          expected: {
            name: "sample-wallet",
            version: "1.0.0",
            sourceRevision: "sample-wallet-v1.0.0",
          },
        },
      ],
    });
  });

  test.each([
    ["unknown manifest properties", { ...validManifest(), shell: true }],
    [
      "duplicate adapter ids",
      { ...validManifest(), adapters: [validManifest().adapters[0], validManifest().adapters[0]] },
    ],
    [
      "unsafe environment names",
      {
        ...validManifest(),
        adapters: [{ ...validManifest().adapters[0], env: { "BAD-NAME": "value" } }],
      },
    ],
    [
      "the reserved fixture commitment environment",
      {
        ...validManifest(),
        adapters: [
          {
            ...validManifest().adapters[0],
            env: { PSBT_LAB_FIXTURE_COMMITMENTS: "caller-controlled" },
          },
        ],
      },
    ],
    [
      "unbounded timeout",
      {
        ...validManifest(),
        adapters: [{ ...validManifest().adapters[0], timeoutMs: 1_000_000 }],
      },
    ],
  ])("rejects %s", (_label, value) => {
    expect(() => parseAdapterManifest(value, "/project/config")).toThrow(/manifest/i);
  });

  test("loads a bounded manifest file", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-manifest-"));
    const path = resolve(directory, "adapters.json");
    writeFileSync(path, JSON.stringify(validManifest()), { mode: 0o600 });

    const loaded = await loadAdapterManifest(path);

    expect(loaded.adapters[0]?.process.cwd).toBe(resolve(directory, "adapter"));
  });
});
