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
    operationScriptTypes: {
      roundtrip: ["p2wsh"],
      sign: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
    features: ["fixture-commitment-sha256"],
  },
};

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const TESTNET_WIF = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

function passingEvidence(name: string) {
  return [{ name, passed: true }] as const;
}

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
        return { summary: "first passed", assertions: passingEvidence("first-completed") };
      }),
      scenario("second", async (value) => {
        value.calls.push("second");
        return { summary: "second passed", assertions: passingEvidence("second-completed") };
      }),
    ];

    const results = await runScenarioCatalog(catalog, context, new Map());

    expect(context.calls).toEqual(["first", "second"]);
    expect(results.map(({ id, outcome }) => ({ id, outcome }))).toEqual([
      { id: "first", outcome: "passed" },
      { id: "second", outcome: "passed" },
    ]);
  });

  test("preserves and redacts compatibility findings without failing a completed scenario", async () => {
    const [result] = await runScenarioCatalog(
      [
        scenario("known-divergence", async () => ({
          assertions: passingEvidence("probe-completed"),
          findings: [
            {
              id: "parser-accepted-duplicate-key",
              implementation: "example-parser",
              summary: `Accepted invalid input; wif=${TESTNET_WIF}`,
            },
          ],
        })),
      ],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({
      outcome: "passed",
      findings: [
        {
          id: "parser-accepted-duplicate-key",
          implementation: "example-parser",
          summary: "Accepted invalid input; wif=[redacted:secret]",
        },
      ],
    });
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

  test("does not treat operation and script capabilities as an unrestricted cross-product", async () => {
    const run = vi.fn(async () => ({ assertions: passingEvidence("unexpected-run") }));
    const operationScopedAdapter = {
      ...rustAdapter,
      capabilities: {
        ...rustAdapter.capabilities,
        scriptTypes: ["p2wsh", "p2tr-keypath"],
        operationScriptTypes: {
          roundtrip: ["p2wsh", "p2tr-keypath"],
          sign: ["p2wsh", "p2tr-keypath"],
          "finalize-inputs": ["p2wsh"],
        },
      },
    } as unknown as NegotiatedAdapter;

    const [result] = await runScenarioCatalog(
      [
        scenario("taproot-finalize", run, {
          requirements: [
            {
              adapter: "rust-bitcoin",
              operations: ["finalize-inputs"],
              scriptTypes: ["p2tr-keypath"],
            },
          ],
        }),
      ],
      { calls: [] },
      new Map([["rust-bitcoin", operationScopedAdapter]]),
    );

    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      outcome: "unsupported",
      missingCapabilities: [
        {
          adapter: "rust-bitcoin",
          kind: "operationScriptType",
          value: "finalize-inputs:p2tr-keypath",
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

  test("rejects capabilities whose map key does not match the negotiated identity", async () => {
    const run = vi.fn();
    const mismatchedAdapter: NegotiatedAdapter = {
      ...rustAdapter,
      implementation: { ...rustAdapter.implementation, name: "bitcoinjs-lib" },
    };

    const [result] = await runScenarioCatalog(
      [
        scenario("identity-mismatch", run, {
          requirements: [{ adapter: "rust-bitcoin", operations: ["sign"] }],
        }),
      ],
      { calls: [] },
      new Map([["rust-bitcoin", mismatchedAdapter]]),
    );

    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      outcome: "unsupported",
      missingCapabilities: [{ adapter: "rust-bitcoin", kind: "identity", value: "bitcoinjs-lib" }],
    });
  });

  test("accepts a validated external adapter registered under its manifest id", async () => {
    const run = vi.fn(async () => ({ assertions: passingEvidence("external-ran") }));
    const externalAdapter: NegotiatedAdapter = {
      ...rustAdapter,
      registryId: "wallet-alias",
      implementation: { ...rustAdapter.implementation, name: "actual-wallet-library" },
    };

    const [result] = await runScenarioCatalog(
      [
        scenario("external-alias", run, {
          requirements: [{ adapter: "wallet-alias", operations: ["sign"] }],
        }),
      ],
      { calls: [] },
      new Map([["wallet-alias", externalAdapter]]),
    );

    expect(run).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ outcome: "passed" });
  });

  test.each([
    ["operation", { operations: ["combine"] }, "combine"],
    ["role", { roles: ["combiner"] }, "combiner"],
  ] as const)("reports an explicitly missing %s", async (kind, requirement, value) => {
    const run = vi.fn();
    const [result] = await runScenarioCatalog(
      [
        scenario(`missing-${kind}`, run, {
          requirements: [{ adapter: "rust-bitcoin", ...requirement }],
        }),
      ],
      { calls: [] },
      new Map([["rust-bitcoin", rustAdapter]]),
    );

    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      outcome: "unsupported",
      missingCapabilities: [{ adapter: "rust-bitcoin", kind, value }],
    });
  });

  test("continues after an expected assertion failure and preserves sanitized evidence", async () => {
    const context: TestContext = { calls: [] };
    const catalog = [
      scenario("bad-roundtrip", async (value) => {
        value.calls.push("bad-roundtrip");
        const leakedAssertion = {
          name: "roundtrip-preserves-fields",
          policy: "roundtrip",
          passed: false,
          exactBytesEqual: false,
          likelyImplementation: "rust-bitcoin",
          failures: [
            {
              code: "ENTRY_REMOVED",
              location: { kind: "global" },
              keyType: 252,
              completeKeySha256: "b".repeat(64),
              keyBytes: 5,
              before: { valueSha256: "c".repeat(64), valueBytes: 12 },
              field: {
                scope: "global",
                keyType: 252,
                keyTypeHex: "0xfc",
                symbol: "PSBT_GLOBAL_PROPRIETARY",
                displayName: "Proprietary global field",
                bip: "BIP174",
                kind: "proprietary",
              },
              guidance: {
                code: "RESTORE_EXTENSION_METADATA",
                severity: "stop",
                summary: "An extension field was removed during the roundtrip transition.",
                nextSteps: ["Return to the previous checkpoint."],
              },
              rawPsbt: Buffer.from(MINIMAL_PSBT, "base64"),
            },
          ],
          summary: `Metadata exposed ${MINIMAL_PSBT}; wif=${TESTNET_WIF}`,
          rawPsbt: Buffer.from(MINIMAL_PSBT, "base64"),
        } as const;
        throw new ScenarioAssertionError(
          `Metadata changed: ${MINIMAL_PSBT}; private key=${TESTNET_WIF}`,
          [leakedAssertion],
        );
      }),
      scenario("still-runs", async (value) => {
        value.calls.push("still-runs");
        return { summary: "continued", assertions: passingEvidence("continued-after-failure") };
      }),
    ];

    const results = await runScenarioCatalog(catalog, context, new Map());

    expect(context.calls).toEqual(["bad-roundtrip", "still-runs"]);
    expect(results[0]).toMatchObject({
      outcome: "failed",
      summary: "Metadata changed: [redacted:psbt]; private key=[redacted:secret]",
      assertions: [
        {
          name: "roundtrip-preserves-fields",
          policy: "roundtrip",
          passed: false,
          likelyImplementation: "rust-bitcoin",
          summary: "Metadata exposed [redacted:psbt]; wif=[redacted:secret]",
          failures: [
            {
              code: "ENTRY_REMOVED",
              location: { kind: "global" },
              keyType: 252,
              completeKeySha256: "b".repeat(64),
              keyBytes: 5,
              before: { valueSha256: "c".repeat(64), valueBytes: 12 },
              field: {
                scope: "global",
                keyType: 252,
                keyTypeHex: "0xfc",
                symbol: "PSBT_GLOBAL_PROPRIETARY",
                displayName: "Proprietary global field",
                bip: "BIP174",
                kind: "proprietary",
              },
              guidance: {
                code: "RESTORE_EXTENSION_METADATA",
                severity: "stop",
                summary: "An extension field was removed during the roundtrip transition.",
                nextSteps: ["Return to the previous checkpoint."],
              },
            },
          ],
        },
      ],
    });
    expect(JSON.stringify(results[0])).not.toContain(MINIMAL_PSBT);
    expect(JSON.stringify(results[0])).not.toContain(TESTNET_WIF);
    expect(JSON.stringify(results[0])).not.toContain("rawPsbt");
    expect(JSON.stringify(results[0])).not.toContain('"type":"Buffer"');
    expect(results[1]).toMatchObject({ outcome: "passed" });
  });

  test("redacts returned summaries and whitelist-copies passing assertion evidence", async () => {
    const evidence = {
      name: "roundtrip-completed",
      passed: true,
      summary: `Compared ${MINIMAL_PSBT}`,
      rawPsbt: Buffer.from(MINIMAL_PSBT, "base64"),
    } as const;
    const [result] = await runScenarioCatalog(
      [
        scenario("sanitized-pass", async () => ({
          summary: `Returned ${MINIMAL_PSBT}`,
          assertions: [evidence],
        })),
      ],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({
      outcome: "passed",
      summary: "Returned [redacted:psbt]",
      assertions: [
        {
          name: "roundtrip-completed",
          passed: true,
          summary: "Compared [redacted:psbt]",
        },
      ],
    });
    expect(result?.assertions[0]).not.toHaveProperty("rawPsbt");
  });

  test("cannot report passed without assertion evidence", async () => {
    const [result] = await runScenarioCatalog(
      [scenario("empty-evidence", async () => ({ assertions: [] }))],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({ outcome: "failed", assertions: [] });
  });

  test("cannot report passed when passing evidence contains failures", async () => {
    const [result] = await runScenarioCatalog(
      [
        scenario("contradictory-evidence", async () => ({
          assertions: [
            {
              name: "roundtrip-preserved",
              passed: true,
              failures: [
                {
                  code: "ENTRY_CHANGED",
                  location: { kind: "input", index: 0 },
                  keyType: 1,
                  completeKeySha256: "d".repeat(64),
                  keyBytes: 1,
                },
              ],
            },
          ],
        })),
      ],
      { calls: [] },
      new Map(),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [{ name: "roundtrip-preserved", passed: true }],
    });
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

  test.each(["", "../escape", "contains spaces", "a".repeat(65)])(
    "rejects unsafe catalog identifier %j before running anything",
    async (id) => {
      const run = vi.fn();
      const catalog = [scenario("would-run-first", run), scenario(id, vi.fn())];

      await expect(runScenarioCatalog(catalog, { calls: [] }, new Map())).rejects.toThrow(
        /catalog index 1.*safe identifier/i,
      );
      expect(run).not.toHaveBeenCalled();
    },
  );

  test("rejects duplicate catalog identifiers before running anything", async () => {
    const first = vi.fn();
    const second = vi.fn();

    await expect(
      runScenarioCatalog(
        [scenario("duplicate", first), scenario("duplicate", second)],
        { calls: [] },
        new Map(),
      ),
    ).rejects.toThrow(/duplicate scenario identifier: duplicate/i);
    expect(first).not.toHaveBeenCalled();
    expect(second).not.toHaveBeenCalled();
  });
});
