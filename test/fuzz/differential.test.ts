import { describe, expect, test, vi } from "vitest";
import {
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
