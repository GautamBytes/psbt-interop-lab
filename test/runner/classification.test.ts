import { describe, expect, test } from "vitest";
import { classifyScenario } from "../../src/runner/classification.js";
import type { ScenarioResult } from "../../src/scenarios/definition.js";

function scenario(overrides: Partial<ScenarioResult>): ScenarioResult {
  return {
    id: "classification-fixture",
    title: "Classification fixture",
    category: "test",
    outcome: "failed",
    summary: "A deterministic report fixture",
    durationMs: 1,
    assertions: [],
    ...overrides,
  };
}

describe("report classification", () => {
  test("classifies removed proprietary fields as implementation-owned metadata loss", () => {
    const classifications = classifyScenario(
      scenario({
        assertions: [
          {
            name: "metadata-preserved",
            passed: false,
            likelyImplementation: "rust-bitcoin",
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "input", index: 0 },
                keyType: 0xfc,
                completeKeySha256: "a".repeat(64),
                keyBytes: 4,
                field: {
                  scope: "input",
                  keyType: 0xfc,
                  keyTypeHex: "0xfc",
                  symbol: "PSBT_IN_PROPRIETARY",
                  displayName: "Proprietary input field",
                  kind: "proprietary",
                },
                guidance: {
                  code: "RESTORE_EXTENSION_METADATA",
                  severity: "stop",
                  summary: "An extension field was removed.",
                  nextSteps: ["Restore the field."],
                },
              },
            ],
          },
        ],
      }),
    );

    expect(classifications).toEqual([
      {
        id: "metadata-loss",
        label: "Metadata loss",
        severity: "stop",
        likelyOwner: "rust-bitcoin",
        repairability: "code-or-dependency-change",
        confidence: "high",
        summary: "One or more PSBT metadata fields were removed during a handoff.",
        evidence: ["ENTRY_REMOVED:PSBT_IN_PROPRIETARY"],
      },
    ]);
  });

  test("separates transaction intent mutation and signature loss", () => {
    const classifications = classifyScenario(
      scenario({
        assertions: [
          {
            name: "signing-transition",
            passed: false,
            likelyImplementation: "wallet-adapter",
            failures: [
              {
                code: "TRANSACTION_IDENTITY_CHANGED",
                location: { kind: "global" },
                keyType: 0,
                completeKeySha256: "b".repeat(64),
                keyBytes: 1,
              },
              {
                code: "ENTRY_REMOVED",
                location: { kind: "input", index: 0 },
                keyType: 2,
                completeKeySha256: "c".repeat(64),
                keyBytes: 34,
                field: {
                  scope: "input",
                  keyType: 2,
                  keyTypeHex: "0x02",
                  symbol: "PSBT_IN_PARTIAL_SIG",
                  displayName: "Partial signature",
                  kind: "standard",
                },
              },
            ],
          },
        ],
      }),
    );

    expect(classifications.map(({ id }) => id)).toEqual([
      "transaction-intent-mutation",
      "signature-loss",
    ]);
    expect(classifications.every(({ severity }) => severity === "stop")).toBe(true);
  });

  test("labels unsupported scenarios as capability gaps rather than code defects", () => {
    const classifications = classifyScenario(
      scenario({
        outcome: "unsupported",
        missingCapabilities: [
          { adapter: "example-wallet", kind: "scriptType", value: "p2tr-scriptpath" },
        ],
      }),
    );

    expect(classifications).toEqual([
      expect.objectContaining({
        id: "capability-mismatch",
        severity: "info",
        likelyOwner: "example-wallet",
        repairability: "not-a-code-defect",
        confidence: "high",
        evidence: ["scriptType:p2tr-scriptpath"],
      }),
    ]);
  });

  test("labels recorded findings as implementation divergences requiring investigation", () => {
    const classifications = classifyScenario(
      scenario({
        outcome: "passed",
        findings: [
          {
            id: "duplicate-global-key",
            implementation: "btcsuite-go",
            summary: "Accepted a duplicate global key.",
          },
        ],
      }),
    );

    expect(classifications).toEqual([
      expect.objectContaining({
        id: "implementation-divergence",
        severity: "review",
        likelyOwner: "btcsuite-go",
        repairability: "investigation-required",
        confidence: "medium",
        evidence: ["finding:duplicate-global-key"],
      }),
    ]);
  });
});
