import { describe, expect, test, vi } from "vitest";
import {
  classifyLabParser,
  hasSameParserOutcomes,
  parserOutcomeMatches,
  runDifferentialFuzz,
} from "../../src/fuzz/differential.js";
import { promoteDifferentialCase } from "../../src/fuzz/promotion.js";
import { runParserRegressionSuite } from "../../src/fuzz/regression.js";
import { LOCAL_PARSE_FIXTURES } from "../../src/local/fixtures.js";
import { AdapterTimeoutError } from "../../src/protocol/adapter-process.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import * as outputAmountSemantics from "../../src/psbt/output-amount-semantics.js";
import type { RuntimeProvider } from "../../src/runtime/provider.js";

const IMPLEMENTATION = {
  name: "permissive-parser",
  version: "1.0.0",
  sourceRevision: "permissive-parser-v1",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

function localFixture(index: number) {
  const fixture = LOCAL_PARSE_FIXTURES[index];
  if (!fixture) throw new RangeError(`Missing local parse fixture ${index}`);
  return fixture;
}

function provider(): RuntimeProvider {
  const process = {
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
            psbtVersions: [0, 2],
            scriptTypes: ["p2wpkh"],
          },
        };
      }
      const psbt = request.payload["psbt"];
      if (typeof psbt !== "string") throw new TypeError("Expected a PSBT");
      let facts: { psbtVersion: number; inputCount: number; outputCount: number } | undefined;
      try {
        const parsed = parsePsbtDocument(psbt);
        facts = {
          psbtVersion: parsed.psbtVersion,
          inputCount: parsed.inputCount,
          outputCount: parsed.outputCount,
        };
      } catch {
        // Deliberately permissive: malformed cases are still reported as accepted.
      }
      return {
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "ok",
        implementation: IMPLEMENTATION,
        output: {
          nativeParser: IMPLEMENTATION.name,
          psbtVersion: facts?.psbtVersion ?? 0,
          inputs: facts?.inputCount ?? 0,
          outputs: facts?.outputCount ?? 0,
        },
      };
    }),
    restart: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
  };
  return {
    runtime: "test",
    adapters: vi.fn(async () => [
      {
        id: "permissive",
        availability: "available" as const,
        process,
        timeoutMs: 1_000,
        expected: IMPLEMENTATION,
      },
      {
        id: "unavailable",
        availability: "unsupported" as const,
        reason: "not installed",
      },
    ]),
    close: vi.fn(async () => undefined),
  };
}

function labOnlyProvider(): RuntimeProvider {
  return {
    runtime: "test",
    adapters: vi.fn(async () => []),
    close: vi.fn(async () => undefined),
  };
}

describe("runDifferentialFuzz", () => {
  test("distinguishes exact classifications and accepted parser facts", () => {
    const baseline = {
      lab: {
        classification: "accepted" as const,
        detail: "accepted",
        facts: { psbtVersion: 0, inputs: 1, outputs: 1 },
      },
      native: { classification: "rejected" as const, detail: "rejected" },
    };

    expect(
      hasSameParserOutcomes(baseline, {
        ...baseline,
        lab: { ...baseline.lab, detail: "different diagnostic" },
      }),
    ).toBe(true);
    expect(
      hasSameParserOutcomes(baseline, {
        ...baseline,
        native: {
          classification: "accepted",
          detail: "accepted",
          facts: { psbtVersion: 0, inputs: 0, outputs: 0 },
        },
      }),
    ).toBe(false);
    expect(
      parserOutcomeMatches(baseline.lab, {
        classification: "accepted",
        facts: { psbtVersion: 0, inputs: 1, outputs: 1 },
      }),
    ).toBe(true);
    expect(
      parserOutcomeMatches(baseline.lab, {
        classification: "accepted",
        facts: { psbtVersion: 0, inputs: 2, outputs: 1 },
      }),
    ).toBe(false);
  });

  test("finds, minimizes, and records seeded parser divergences", async () => {
    const runtime = provider();
    const result = await runDifferentialFuzz({
      provider: runtime,
      fixture: localFixture(0),
      seed: 42,
      cases: 24,
    });

    expect(result.seed).toBe(42);
    expect(result.implementations).toEqual({ permissive: IMPLEMENTATION });
    expect(result.cases).toHaveLength(24);
    expect(result.interesting.length).toBeGreaterThan(0);
    expect(result.interesting[0]).toMatchObject({
      outcomes: {
        lab: { classification: "rejected" },
        permissive: { classification: "accepted" },
        unavailable: { classification: "unsupported" },
      },
    });
    expect(result.interesting.every((item) => item.minimizedRecipes.length > 0)).toBe(true);
    expect(
      result.interesting.every((item) =>
        hasSameParserOutcomes(item.minimizedOutcomes, item.outcomes),
      ),
    ).toBe(true);
    const interesting = result.interesting[0];
    if (!interesting) throw new Error("Expected a differential case");
    expect(interesting.minimizedOutputAmountSemantics).toEqual(
      (() => {
        try {
          return outputAmountSemantics.assessOutputAmountSemantics(
            parsePsbtDocument(interesting.minimizedPsbt),
          );
        } catch {
          return { status: "not-evaluated", findings: [] };
        }
      })(),
    );
    const suite = promoteDifferentialCase({
      fixture: localFixture(0),
      seed: result.seed,
      caseIndex: interesting.index,
      recipes: interesting.minimizedRecipes,
      outcomes: interesting.minimizedOutcomes,
    });
    await expect(
      runParserRegressionSuite({
        manifest: suite,
        createProvider: async () => provider(),
      }),
    ).resolves.toMatchObject({ outcome: "passed" });
    expect(runtime.close).toHaveBeenCalledOnce();
  });

  test("reports issue #38 as parser-accepted but semantically invalid", async () => {
    const result = await runDifferentialFuzz({
      provider: labOnlyProvider(),
      fixture: localFixture(1),
      seed: 42,
      cases: 128,
    });

    expect(result.cases[48]).toMatchObject({
      outcomes: { lab: { classification: "accepted" } },
      outputAmountSemantics: {
        status: "invalid",
        outputsModifiable: false,
        findings: [
          {
            ruleId: "lab.transaction-output.money-range",
            code: "OUTPUT_AMOUNT_NEGATIVE",
            outputIndex: 0,
          },
        ],
      },
    });
    expect(result.interesting).toEqual([]);
  });

  test("does not evaluate semantics after structural parser rejection", async () => {
    const result = await runDifferentialFuzz({
      provider: labOnlyProvider(),
      fixture: localFixture(0),
      seed: 42,
      cases: 24,
    });
    const rejected = result.cases.find(
      ({ outcomes }) => outcomes["lab"]?.classification === "rejected",
    );

    expect(rejected?.outputAmountSemantics).toEqual({
      status: "not-evaluated",
      findings: [],
    });
  });

  test("does not disguise an internal semantic failure as parser rejection", () => {
    const assessment = vi
      .spyOn(outputAmountSemantics, "assessOutputAmountSemantics")
      .mockImplementation(() => {
        throw new Error("semantic invariant failed");
      });

    try {
      expect(() => classifyLabParser(localFixture(0).psbt)).toThrow("semantic invariant failed");
    } finally {
      assessment.mockRestore();
    }
  });

  test("is byte-for-byte deterministic for the same fixture and seed", async () => {
    const first = await runDifferentialFuzz({
      provider: provider(),
      fixture: localFixture(1),
      seed: 7,
      cases: 12,
    });
    const second = await runDifferentialFuzz({
      provider: provider(),
      fixture: localFixture(1),
      seed: 7,
      cases: 12,
    });

    expect(first).toEqual(second);
  });

  test("classifies transport-level adapter timeouts distinctly from crashes", async () => {
    const process = {
      request: vi.fn(async () => {
        throw new AdapterTimeoutError("native parser timed out");
      }),
      restart: vi.fn(async () => undefined),
      close: vi.fn(async () => undefined),
    };
    const runtime: RuntimeProvider = {
      runtime: "test",
      adapters: vi.fn(async () => [
        {
          id: "slow-parser",
          availability: "available" as const,
          process,
          timeoutMs: 1_000,
          expected: IMPLEMENTATION,
        },
      ]),
      close: vi.fn(async () => undefined),
    };

    const result = await runDifferentialFuzz({
      provider: runtime,
      fixture: localFixture(0),
      seed: 1,
      cases: 1,
    });

    expect(result.cases[0]?.outcomes["slow-parser"]).toMatchObject({
      classification: "timeout",
      detail: "native parser timed out",
    });
    expect(process.restart).toHaveBeenCalledOnce();
  });
});
