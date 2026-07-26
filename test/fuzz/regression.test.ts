import { describe, expect, test, vi } from "vitest";
import type { CustomSuiteManifest } from "../../src/custom/manifest.js";
import { runParserRegressionSuite } from "../../src/fuzz/regression.js";
import { LOCAL_PARSE_FIXTURES } from "../../src/local/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import type { RuntimeProvider } from "../../src/runtime/provider.js";

const IMPLEMENTATION = {
  name: "regression-parser",
  version: "1.0.0",
  sourceRevision: "regression-parser-v1",
  artifactDigest: `sha256:${"b".repeat(64)}`,
};

function provider(acceptedFacts?: {
  readonly psbtVersion: number;
  readonly inputs: number;
  readonly outputs: number;
}): RuntimeProvider {
  return {
    runtime: "test",
    adapters: vi.fn(async () => [
      {
        id: "regression-parser",
        availability: "available" as const,
        timeoutMs: 1_000,
        expected: IMPLEMENTATION,
        process: {
          request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
            if (request.operation === "hello") {
              return {
                protocol: "psbt-lab.adapter/0.2",
                id: request.id,
                status: "ok",
                implementation: IMPLEMENTATION,
                output: {
                  operations: ["hello", "native-parse"],
                  roles: ["parser"],
                  psbtVersions: [0],
                  scriptTypes: ["p2wpkh"],
                },
              };
            }
            return acceptedFacts
              ? {
                  protocol: "psbt-lab.adapter/0.2",
                  id: request.id,
                  status: "ok",
                  implementation: IMPLEMENTATION,
                  output: {
                    nativeParser: IMPLEMENTATION.name,
                    ...acceptedFacts,
                  },
                }
              : {
                  protocol: "psbt-lab.adapter/0.2",
                  id: request.id,
                  status: "rejected",
                  implementation: IMPLEMENTATION,
                  error: {
                    class: "psbt.native_parse_failed",
                    message: "truncated PSBT",
                  },
                };
          }),
          close: vi.fn(async () => undefined),
        },
      },
    ]),
    close: vi.fn(async () => undefined),
  };
}

describe("runParserRegressionSuite", () => {
  test("replays a promoted parser-only suite with the selected runtime", async () => {
    const fixture = LOCAL_PARSE_FIXTURES[0];
    if (!fixture) throw new Error("Missing local parser fixture");
    const manifest: CustomSuiteManifest = {
      schema: "psbt-lab.suite/0.2",
      fixtures: [],
      parserFixtures: [
        {
          id: "base",
          psbt: fixture.psbt,
          sha256: `sha256:${fixture.sha256}`,
        },
      ],
      scenarios: [
        {
          id: "truncated-regression",
          title: "Truncated parser regression",
          fixture: "base",
          steps: [
            {
              id: "mutated",
              operation: "mutate",
              input: "fixture",
              recipes: [{ kind: "truncate", byteLength: 10 }],
            },
            {
              id: "compare",
              operation: "compare-parsers",
              input: "mutated",
              adapters: ["regression-parser"],
              expected: {
                lab: "rejected",
                "regression-parser": "rejected",
              },
            },
          ],
        },
      ],
    };

    const report = await runParserRegressionSuite({
      manifest,
      createProvider: async () => provider(),
    });

    expect(report).toMatchObject({
      runtime: "test",
      outcome: "passed",
      scenarios: [
        {
          id: "truncated-regression",
          outcome: "passed",
          assertions: [
            { name: "compare-lab", actual: "rejected", passed: true },
            {
              name: "compare-regression-parser",
              actual: "rejected",
              passed: true,
            },
          ],
        },
      ],
    });
  });

  test("refuses Core-backed steps in the Dockerless parser regression path", async () => {
    const fixture = LOCAL_PARSE_FIXTURES[0];
    if (!fixture) throw new Error("Missing local parser fixture");
    const manifest: CustomSuiteManifest = {
      schema: "psbt-lab.suite/0.2",
      fixtures: [],
      parserFixtures: [
        {
          id: "base",
          psbt: fixture.psbt,
          sha256: `sha256:${fixture.sha256}`,
        },
      ],
      scenarios: [
        {
          id: "unsafe-regression",
          title: "Unsafe regression",
          fixture: "base",
          steps: [{ id: "finalize", operation: "core-finalize", input: "fixture" }],
        },
      ],
    };

    await expect(
      runParserRegressionSuite({ manifest, createProvider: async () => provider() }),
    ).rejects.toThrow(/contains a Core or signing operation/);
  });

  test("fails a promoted fact-level parser regression when structural facts drift", async () => {
    const fixture = LOCAL_PARSE_FIXTURES[0];
    if (!fixture) throw new Error("Missing local parser fixture");
    const manifest: CustomSuiteManifest = {
      schema: "psbt-lab.suite/0.2",
      fixtures: [],
      parserFixtures: [
        {
          id: "base",
          psbt: fixture.psbt,
          sha256: `sha256:${fixture.sha256}`,
        },
      ],
      scenarios: [
        {
          id: "fact-regression",
          title: "Fact regression",
          fixture: "base",
          steps: [
            {
              id: "compare",
              operation: "compare-parsers",
              input: "fixture",
              adapters: ["regression-parser"],
              expected: {
                lab: {
                  classification: "accepted",
                  facts: { psbtVersion: 0, inputs: 1, outputs: 1 },
                },
                "regression-parser": {
                  classification: "accepted",
                  facts: { psbtVersion: 0, inputs: 2, outputs: 1 },
                },
              },
            },
          ],
        },
      ],
    };

    const report = await runParserRegressionSuite({
      manifest,
      createProvider: async () => provider({ psbtVersion: 0, inputs: 1, outputs: 1 }),
    });

    expect(report).toMatchObject({
      outcome: "failed",
      scenarios: [
        {
          outcome: "failed",
          assertions: [
            { name: "compare-lab", passed: true },
            {
              name: "compare-regression-parser",
              expectedFacts: { psbtVersion: 0, inputs: 2, outputs: 1 },
              actualFacts: { psbtVersion: 0, inputs: 1, outputs: 1 },
              passed: false,
            },
          ],
        },
      ],
    });
  });
});
