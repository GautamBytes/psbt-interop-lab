import { describe, expect, test } from "vitest";
import type { RunManifest } from "../../src/runner/artifacts.js";
import {
  generateHtmlReport,
  generateJsonReport,
  generateMarkdownReport,
} from "../../src/runner/report.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const TESTNET_WIF = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const TEST_MNEMONIC =
  "abandon ability able about above absent absorb abstract absurd abuse access accident";
const TEST_SLIP132_PRIVATE_KEY = `yprv${"A".repeat(107)}`;

function manifest(): RunManifest {
  return {
    schema: "psbt-lab.run/0.1",
    runId: "report-run",
    suite: "proof",
    startedAt: "2026-07-16T00:00:00.000Z",
    completedAt: "2026-07-16T00:00:01.000Z",
    outcome: "failed",
    selectors: {
      requested: { scenarios: ["metadata-preservation"], category: "metadata-preservation" },
      executed: {
        scenarios: ["metadata-preservation"],
        categories: ["metadata-preservation"],
      },
    },
    core: {
      version: 310100,
      subversion: "/Satoshi:31.1.0/",
      blocks: 109,
      connections: 0,
    },
    adapters: [
      {
        name: "rust-bitcoin",
        version: "0.1.0",
        artifactDigest: `sha256:${"a".repeat(64)}`,
      },
    ],
    scenarios: [
      {
        id: "metadata-preservation",
        title: "Metadata <script>alert(1)</script>",
        category: "metadata-preservation",
        outcome: "failed",
        summary: `Adapter leaked wif=${TESTNET_WIF}, ${TEST_SLIP132_PRIVATE_KEY}, mnemonic: ${TEST_MNEMONIC}; PSBT ${MINIMAL_PSBT}`,
        durationMs: 12.5,
        assertions: [
          {
            name: "fields-preserved",
            policy: "roundtrip",
            passed: false,
            exactBytesEqual: false,
            likelyImplementation: "rust-bitcoin",
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "input", index: 0 },
                keyType: 252,
                completeKeySha256: "b".repeat(64),
                keyBytes: 10,
                before: { valueSha256: "c".repeat(64), valueBytes: 14 },
                field: {
                  scope: "input",
                  keyType: 252,
                  keyTypeHex: "0xfc",
                  symbol: "PSBT_IN_PROPRIETARY",
                  displayName: "Proprietary input field",
                  bip: "BIP174",
                  kind: "proprietary",
                },
                guidance: {
                  code: "RESTORE_EXTENSION_METADATA",
                  severity: "stop",
                  summary: "An extension field was removed during the roundtrip transition.",
                  nextSteps: [
                    "Return to the previous checkpoint.",
                    "Use an implementation that preserves unknown and proprietary fields.",
                  ],
                },
              },
            ],
          },
        ],
        findings: [
          {
            id: "known-parser-divergence",
            ruleId: "bip174.map-keys.unique",
            implementation: "btcsuite-go",
            summary: "Accepted a duplicate global key",
            actual: "btcsuite accepted a duplicate global key.",
          },
        ],
      },
      {
        id: "taproot",
        title: "Taproot handoff",
        category: "taproot",
        outcome: "unsupported",
        summary: "No compatible signer",
        durationMs: 0.2,
        assertions: [],
        missingCapabilities: [
          { adapter: "rust-bitcoin", kind: "scriptType", value: "p2tr-keypath" },
        ],
      },
    ],
    checkpoints: [],
  };
}

describe("HTML report", () => {
  test("renders a self-contained, escaped, secret-safe compatibility report", () => {
    const html = generateHtmlReport(manifest());

    expect(html).toContain("PSBT Interop Lab");
    expect(html).toContain("Metadata &lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("ENTRY_REMOVED");
    expect(html).toContain("PSBT_IN_PROPRIETARY");
    expect(html).toContain("Proprietary input field");
    expect(html).toContain("BIP174");
    expect(html).toContain("Observed implementation");
    expect(html).toContain("rust-bitcoin");
    expect(html).toContain("RESTORE_EXTENSION_METADATA");
    expect(html).toContain("Return to the previous checkpoint.");
    expect(html).toContain("UNSUPPORTED");
    expect(html).toContain("Compatibility findings");
    expect(html).toContain("Accepted a duplicate global key");
    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("metadata-preservation");
    expect(html).toContain("Filtered run");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain(TESTNET_WIF);
    expect(html).not.toContain(TEST_SLIP132_PRIVATE_KEY);
    expect(html).not.toContain(TEST_MNEMONIC);
    expect(html).not.toContain(MINIMAL_PSBT);
    expect(html).toContain("[redacted:secret]");
    expect(html).toContain("[redacted:psbt]");
  });

  test("renders structured diagnostics in JSON and Markdown", () => {
    const value = manifest();
    const json = JSON.stringify(generateJsonReport(value));
    const markdown = generateMarkdownReport(value);

    for (const report of [json, markdown]) {
      expect(report).toContain("PSBT_IN_PROPRIETARY");
      expect(report).toContain("Proprietary input field");
      expect(report).toContain("BIP174");
      expect(report).toContain("rust-bitcoin");
      expect(report).toContain("RESTORE_EXTENSION_METADATA");
      expect(report).toContain("Return to the previous checkpoint.");
      expect(report).toContain("metadata-preservation");
      expect(report).toContain("metadata-loss");
      expect(report).toContain("Metadata loss");
      expect(report).toContain("code-or-dependency-change");
    }
    expect(markdown).toContain("Filtered run");
    expect(markdown).toContain("Observed at: `rust-bitcoin`");
    expect(markdown).toContain("Capability mismatch");
  });

  test("renders classifications in the HTML report", () => {
    const html = generateHtmlReport(manifest());

    expect(html).toContain("Classification");
    expect(html).toContain("Metadata loss");
    expect(html).toContain("Observed at");
    expect(html).toContain("rust-bitcoin");
    expect(html).toContain("Code or dependency change");
    expect(html).toContain("Capability mismatch");
  });
});
