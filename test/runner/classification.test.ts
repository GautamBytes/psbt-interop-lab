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
        observedAt: "rust-bitcoin",
        repairability: "code-or-dependency-change",
        confidence: "high",
        summary: "An extension field was removed.",
        evidence: [
          `assertion=metadata-preserved; location=input[0]; failure=ENTRY_REMOVED; field=PSBT_IN_PROPRIETARY; keyType=0xfc; keySha256=${"a".repeat(64)}`,
        ],
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
                guidance: {
                  code: "TRANSACTION_INTENT_CHANGED",
                  severity: "stop",
                  summary: "The transaction changed.",
                  nextSteps: ["Stop."],
                },
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
                guidance: {
                  code: "RESTORE_AND_RESIGN",
                  severity: "stop",
                  summary: "A signature was removed.",
                  nextSteps: ["Restore and sign again."],
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
        observedAt: "example-wallet",
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
        observedAt: "btcsuite-go",
        repairability: "investigation-required",
        confidence: "medium",
        evidence: ["finding:duplicate-global-key"],
      }),
    ]);
  });

  test("does not infer a specific category when structured guidance is absent", () => {
    const classifications = classifyScenario(
      scenario({
        assertions: [
          {
            name: "unstructured-transition",
            passed: false,
            likelyImplementation: "example-wallet",
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "output", index: 1 },
                keyType: 0x06,
                completeKeySha256: "d".repeat(64),
                keyBytes: 1,
              },
            ],
          },
        ],
      }),
    );

    expect(classifications).toEqual([
      expect.objectContaining({
        id: "workflow-failure",
        severity: "review",
        observedAt: "example-wallet",
        repairability: "investigation-required",
        confidence: "low",
      }),
    ]);
  });

  test("describes a policy-forbidden removal without calling the field BIP-required", () => {
    const classifications = classifyScenario(
      scenario({
        assertions: [
          {
            name: "wallet-roundtrip",
            passed: false,
            likelyImplementation: "example-wallet",
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "global" },
                keyType: 0x01,
                completeKeySha256: "e".repeat(64),
                keyBytes: 1,
                guidance: {
                  code: "RESTORE_REMOVED_FIELD",
                  severity: "stop",
                  summary: "A global xpub was removed.",
                  nextSteps: ["Restore the field."],
                },
              },
            ],
          },
        ],
      }),
    );

    expect(classifications).toEqual([
      expect.objectContaining({
        id: "unexpected-field-loss",
        label: "Unexpected field loss",
      }),
    ]);
  });
});
