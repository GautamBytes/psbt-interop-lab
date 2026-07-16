import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { runAdapterConformance } from "../../src/conformance/check.js";
import { parseAdapterManifest } from "../../src/conformance/manifest.js";

const fixture = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));

function manifest(version = "1.0.0", mode = "conformant") {
  return parseAdapterManifest(
    {
      schema: "psbt-lab.adapters/0.1",
      adapters: [
        {
          id: "fake-wallet",
          command: process.execPath,
          args: [fixture, mode],
          expected: {
            name: "fake-wallet",
            version,
            sourceRevision: "fake-wallet-v1.0.0",
          },
        },
      ],
    },
    process.cwd(),
  );
}

describe("external adapter conformance", () => {
  test("checks transport, identity, native parsing, rejection, and semantic roundtrip", async () => {
    const report = await runAdapterConformance(manifest());

    expect(report).toMatchObject({
      schema: "psbt-lab.conformance/0.1",
      passed: true,
      adapters: [
        {
          id: "fake-wallet",
          passed: true,
          implementation: {
            name: "fake-wallet",
            version: "1.0.0",
            sourceRevision: "fake-wallet-v1.0.0",
          },
          checks: expect.arrayContaining([
            expect.objectContaining({ name: "hello", passed: true }),
            expect.objectContaining({ name: "identity", passed: true }),
            expect.objectContaining({ name: "native-parse-valid", passed: true }),
            expect.objectContaining({ name: "native-parse-invalid", passed: true }),
            expect.objectContaining({ name: "roundtrip-preservation", passed: true }),
          ]),
        },
      ],
    });
  });

  test("fails closed when the manifest credits the wrong implementation version", async () => {
    const report = await runAdapterConformance(manifest("9.9.9"));

    expect(report.passed).toBe(false);
    expect(report.adapters[0]).toMatchObject({
      passed: false,
      checks: expect.arrayContaining([
        expect.objectContaining({ name: "identity", passed: false }),
      ]),
    });
  });

  test("fails when an adapter omits semantic roundtrip support", async () => {
    const report = await runAdapterConformance(manifest("1.0.0", "parser-only"));

    expect(report).toMatchObject({
      passed: false,
      adapters: [
        {
          passed: false,
          checks: expect.arrayContaining([
            expect.objectContaining({ name: "baseline-capabilities", passed: false }),
          ]),
        },
      ],
    });
  });
});
