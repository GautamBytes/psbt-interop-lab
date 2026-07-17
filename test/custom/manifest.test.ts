import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { loadCustomSuiteManifest, parseCustomSuiteManifest } from "../../src/custom/manifest.js";

function validSuite() {
  return {
    schema: "psbt-lab.suite/0.1",
    fixtures: [
      {
        id: "merchant-refund",
        inputs: [{ descriptor: "p2wpkh", sequence: 0xffff_fffc }],
        outputs: [
          { descriptor: "p2wpkh", amountSats: 100_000 },
          { descriptor: "p2tr-keypath", remainder: true },
        ],
        feeSats: 15_000,
        locktime: 42,
        transactionVersion: 2,
      },
    ],
    scenarios: [
      {
        id: "merchant-refund-handoff",
        title: "Merchant refund handoff",
        fixture: "merchant-refund",
        steps: [
          {
            id: "parsed",
            adapter: "rust-bitcoin",
            operation: "roundtrip",
            input: "fixture",
          },
          {
            id: "signed",
            adapter: "rust-bitcoin",
            operation: "sign",
            input: "parsed",
          },
          { id: "finalized", operation: "core-finalize", input: "signed" },
          { id: "policy", operation: "core-policy-check", input: "finalized" },
        ],
      },
    ],
  };
}

describe("custom suite manifest", () => {
  test("parses bounded deterministic fixtures and scenario dataflow", () => {
    expect(parseCustomSuiteManifest(validSuite())).toEqual(validSuite());
  });

  test("accepts the nested SegWit and Taproot script-path public templates", () => {
    const suite = validSuite();
    const manifest = {
      ...suite,
      fixtures: [
        {
          ...suite.fixtures[0],
          inputs: [{ descriptor: "p2sh-p2wpkh", sequence: 0xffff_fffc }],
          outputs: [{ descriptor: "p2tr-scriptpath", remainder: true }],
        },
      ],
    };

    expect(parseCustomSuiteManifest(manifest)).toEqual(manifest);
  });

  test.each([
    ["unknown properties", { ...validSuite(), command: "rm -rf /" }],
    [
      "arbitrary descriptors",
      {
        ...validSuite(),
        fixtures: [
          {
            ...validSuite().fixtures[0],
            inputs: [{ descriptor: "wpkh(tprv-secret)", sequence: 0xffff_fffc }],
          },
        ],
      },
    ],
    [
      "multiple remainder outputs",
      {
        ...validSuite(),
        fixtures: [
          {
            ...validSuite().fixtures[0],
            outputs: [
              { descriptor: "p2wpkh", remainder: true },
              { descriptor: "p2tr-keypath", remainder: true },
            ],
          },
        ],
      },
    ],
    [
      "arbitrary adapter payloads",
      {
        ...validSuite(),
        scenarios: [
          {
            ...validSuite().scenarios[0],
            steps: [
              {
                id: "parsed",
                adapter: "rust-bitcoin",
                operation: "roundtrip",
                input: "fixture",
                payload: { shell: true },
              },
            ],
          },
        ],
      },
    ],
  ])("rejects %s", (_label, manifest) => {
    expect(() => parseCustomSuiteManifest(manifest)).toThrow(/custom suite manifest/i);
  });

  test("rejects duplicate fixture and scenario ids", () => {
    const suite = validSuite();
    expect(() =>
      parseCustomSuiteManifest({
        ...suite,
        fixtures: [suite.fixtures[0], suite.fixtures[0]],
      }),
    ).toThrow(/duplicate fixture id/i);
    expect(() =>
      parseCustomSuiteManifest({
        ...suite,
        scenarios: [suite.scenarios[0], suite.scenarios[0]],
      }),
    ).toThrow(/duplicate scenario id/i);
  });

  test("loads a bounded suite file", async () => {
    const directory = mkdtempSync(resolve(tmpdir(), "psbt-suite-"));
    const path = resolve(directory, "suite.json");
    writeFileSync(path, JSON.stringify(validSuite()), { mode: 0o600 });

    await expect(loadCustomSuiteManifest(path)).resolves.toEqual(validSuite());
  });
});
