import { describe, expect, test, vi } from "vitest";
import type { NegotiatedAdapter } from "../../src/protocol/types.js";
import type { ScenarioDefinition } from "../../src/scenarios/definition.js";
import { runScenarioCatalog, ScenarioAssertionError } from "../../src/scenarios/engine.js";

interface TestContext {
  calls: string[];
}

const rustAdapter: NegotiatedAdapter = {
  implementation: {
    name: "rust-bitcoin",
    version: "0.1.0",
    artifactDigest: `sha256:${"a".repeat(64)}`,
    sourceRevision: "bitcoin-crate-0.32.102",
  },
  capabilities: {
    operations: ["hello", "roundtrip", "sign", "finalize-inputs"],
    roles: ["parser", "signer", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["fixture-commitment-sha256"],
  },
};

function scenario(
  id: string,
  run: ScenarioDefinition<TestContext>["run"],
  overrides: Partial<ScenarioDefinition<TestContext>> = {},
): ScenarioDefinition<TestContext> {
  return {
    id,
    title: id,
    category: "interop",
    summary: `${id} summary`,
    requirements: [],
    run,
    ...overrides,
  };
}

describe("scenario engine", () => {
  test("runs supported scenarios in catalog order", async () => {
    const context: TestContext = { calls: [] };
    const catalog = [
      scenario("first", async (value) => {
        value.calls.push("first");
        return { summary: "first passed", assertions: [] };
      }),
      scenario("second", async (value) => {
        value.calls.push("second");
        return { summary: "second passed", assertions: [] };
      }),
    ];

    const results = await runScenarioCatalog(catalog, context, new Map());

    expect(context.calls).toEqual(["first", "second"]);
    expect(results.map(({ id, outcome }) => ({ id, outcome }))).toEqual([
      { id: "first", outcome: "passed" },
      { id: "second", outcome: "passed" },
    ]);
  });

  test("classifies missing adapter capabilities as unsupported without running", async () => {
    const run = vi.fn();
    const catalog = [
      scenario("taproot-sign", run, {
        requirements: [
          {
            adapter: "rust-bitcoin",
            operations: ["sign"],
            roles: ["signer"],
            psbtVersions: [2],
            scriptTypes: ["p2tr-keypath"],
            features: ["fixture-commitment-sha256", "taproot-sighash-validation"],
          },
        ],
      }),
    ];

    const [result] = await runScenarioCatalog(
      catalog,
      { calls: [] },
      new Map([["rust-bitcoin", rustAdapter]]),
    );

    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      id: "taproot-sign",
      outcome: "unsupported",
      missingCapabilities: [
        { adapter: "rust-bitcoin", kind: "psbtVersion", value: 2 },
        { adapter: "rust-bitcoin", kind: "scriptType", value: "p2tr-keypath" },
        {
          adapter: "rust-bitcoin",
          kind: "feature",
          value: "taproot-sighash-validation",
        },
      ],
    });
  });

  test("reports a missing implementation as one stable capability failure", async () => {
    const [result] = await runScenarioCatalog(
      [scenario("missing", vi.fn(), { requirements: [{ adapter: "bitcoinjs-lib" }] })],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({
      outcome: "unsupported",
      missingCapabilities: [{ adapter: "bitcoinjs-lib", kind: "adapter", value: "bitcoinjs-lib" }],
    });
  });

  test("continues after an expected assertion failure and preserves sanitized evidence", async () => {
    const context: TestContext = { calls: [] };
    const catalog = [
      scenario("bad-roundtrip", async (value) => {
        value.calls.push("bad-roundtrip");
        throw new ScenarioAssertionError("Metadata changed", [
          {
            name: "roundtrip-preserves-fields",
            policy: "roundtrip",
            passed: false,
            exactBytesEqual: false,
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "global" },
                keyType: 252,
                completeKeySha256: "b".repeat(64),
                keyBytes: 5,
                before: { valueSha256: "c".repeat(64), valueBytes: 12 },
              },
            ],
          },
        ]);
      }),
      scenario("still-runs", async (value) => {
        value.calls.push("still-runs");
        return { summary: "continued", assertions: [] };
      }),
    ];

    const results = await runScenarioCatalog(catalog, context, new Map());

    expect(context.calls).toEqual(["bad-roundtrip", "still-runs"]);
    expect(results[0]).toMatchObject({
      outcome: "failed",
      summary: "Metadata changed",
      assertions: [
        {
          policy: "roundtrip",
          passed: false,
          failures: [{ code: "ENTRY_REMOVED", keyType: 252 }],
        },
      ],
    });
    expect(JSON.stringify(results[0])).not.toContain("secret");
    expect(results[1]).toMatchObject({ outcome: "passed" });
  });

  test("cannot report passed when returned assertion evidence contains a failure", async () => {
    const [result] = await runScenarioCatalog(
      [
        scenario("false-green", async () => ({
          summary: "adapter returned",
          assertions: [{ name: "intent-preserved", passed: false }],
        })),
      ],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({
      id: "false-green",
      outcome: "failed",
      assertions: [{ name: "intent-preserved", passed: false }],
    });
  });

  test("aborts immediately on an infrastructure error", async () => {
    const later = vi.fn();
    const catalog = [
      scenario("core-down", async () => {
        throw new Error("Bitcoin Core unavailable");
      }),
      scenario("later", later),
    ];

    await expect(runScenarioCatalog(catalog, { calls: [] }, new Map())).rejects.toThrow(
      /Core unavailable/,
    );
    expect(later).not.toHaveBeenCalled();
  });

  test("supports an explicit deterministic skip without executing the scenario", async () => {
    const run = vi.fn();
    const [result] = await runScenarioCatalog(
      [scenario("optional", run, { skip: async () => "not selected by this suite" })],
      { calls: [] },
      new Map(),
    );

    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      outcome: "skipped",
      skipReason: "not selected by this suite",
    });
  });
});
