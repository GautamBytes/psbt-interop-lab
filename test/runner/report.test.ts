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

function manifestWithInfrastructureError(): RunManifest {
  const value = manifest();
  return {
    ...value,
    scenarios: [
      ...value.scenarios,
      {
        id: "core-down",
        title: "Core transport unavailable",
        category: "runtime",
        outcome: "failed",
        summary: "core-down failed before producing scenario assertions.",
        durationMs: 5,
        assertions: [
          {
            name: "scenario-executed",
            passed: false,
            likelyImplementation: "scenario-runtime",
            summary: `Error: Bitcoin Core unavailable for ${MINIMAL_PSBT}; wif=${TESTNET_WIF}`,
          },
        ],
        infrastructureError: {
          errorClass: "Error",
          message: `Bitcoin Core unavailable for ${MINIMAL_PSBT}; wif=${TESTNET_WIF}`,
        },
      },
    ],
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
    const html = generateHtmlReport(value);

    for (const report of [json, markdown, html]) {
      expect(report).toContain("PSBT_IN_PROPRIETARY");
      expect(report).toContain("Proprietary input field");
      expect(report).toContain("BIP174");
      expect(report).toContain("rust-bitcoin");
      expect(report).toContain("RESTORE_EXTENSION_METADATA");
      expect(report).toContain("Return to the previous checkpoint.");
      expect(report).toContain("metadata-preservation");
      expect(report).toContain("metadata-loss");
      expect(report).toContain("Metadata loss");
      expect(report).toContain("bip174.unknown-keypairs.preserved");
      expect(report).toContain("must");
      expect(report).toContain(
        "Unknown and proprietary keypairs are preserved when a PSBT is reserialized.",
      );
      expect(report).toContain("An extension field was removed during the roundtrip transition.");
      expect(report).toContain("https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki");
    }
    expect(markdown).toContain("Filtered run");
    expect(json).toContain("code-or-dependency-change");
    expect(markdown).toContain("code-or-dependency-change");
    expect(html).toContain("Code or dependency change");
    expect(markdown).toContain("Observed at: `rust-bitcoin`");
    expect(markdown).toContain("Capability mismatch");
    expect(markdown).toContain("Normative level: `must`");
    expect(html).toContain('href="https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki"');
  });

  test("distinguishes policy-accepted and Core-confirmed transaction ids", () => {
    const value = manifest();
    const firstScenario = value.scenarios[0];
    if (!firstScenario) throw new Error("Missing report fixture scenario");
    const acceptedTxid = "1".repeat(64);
    const confirmedTxid = "2".repeat(64);
    const valueWithTransactionIds: RunManifest = {
      ...value,
      scenarios: [
        {
          ...firstScenario,
          id: "policy-accepted",
          title: "Policy-accepted transaction",
          outcome: "passed",
          policyAccepted: true,
          transactionId: acceptedTxid,
        },
        {
          ...firstScenario,
          id: "policy-unavailable",
          title: "Core-confirmed transaction",
          outcome: "passed",
          summary: "Core confirmed the transaction identity; policy evaluation is unavailable.",
          transactionId: confirmedTxid,
        },
      ],
    };

    const markdown = generateMarkdownReport(valueWithTransactionIds);

    expect(markdown).toContain(`Policy-accepted txid: \`${acceptedTxid}\``);
    expect(markdown).toContain(`Core-confirmed txid: \`${confirmedTxid}\``);
    expect(markdown).not.toContain(`Policy-accepted txid: \`${confirmedTxid}\``);
  });

  test("redacts dynamic strings in Markdown reports even when the manifest is not pre-redacted", () => {
    const value = manifest();
    const firstScenario = value.scenarios[0];
    if (!firstScenario?.findings?.[0]) throw new Error("Missing report fixture finding");
    const valueWithSecretFinding: RunManifest = {
      ...value,
      scenarios: [
        {
          ...firstScenario,
          findings: [
            {
              ...firstScenario.findings[0],
              summary: `Accepted a duplicate global key with mnemonic: ${TEST_MNEMONIC}`,
              actual: `btcsuite accepted a duplicate global key with wif=${TESTNET_WIF}.`,
              evidence: [`seed=${TEST_MNEMONIC}`],
            },
          ],
        },
        ...value.scenarios.slice(1),
      ],
    };

    const markdown = generateMarkdownReport(valueWithSecretFinding);

    expect(markdown).not.toContain(TESTNET_WIF);
    expect(markdown).not.toContain(TEST_SLIP132_PRIVATE_KEY);
    expect(markdown).not.toContain(TEST_MNEMONIC);
    expect(markdown).not.toContain(MINIMAL_PSBT);
    expect(markdown).toContain("[redacted:secret]");
    expect(markdown).toContain("[redacted:psbt]");
  });

  test("escapes raw HTML and Markdown delimiters in dynamic Markdown report strings", () => {
    const value = manifest();
    const firstScenario = value.scenarios[0];
    if (!firstScenario?.findings?.[0]) throw new Error("Missing report fixture finding");
    const unsafeManifest: RunManifest = {
      ...value,
      runId: "run`\n# injected heading",
      scenarios: [
        {
          ...firstScenario,
          title: "<script>alert(1)</script> **spoofed title**",
          summary: "Summary\n- injected list",
          findings: [
            {
              ...firstScenario.findings[0],
              summary: '<img src=x onerror="alert(1)"> [spoofed](https://example.invalid)',
              actual: "Observed **critical** behavior.",
              evidence: ["evidence`\n# injected evidence"],
            },
          ],
        },
        ...value.scenarios.slice(1),
      ],
    };

    const markdown = generateMarkdownReport(unsafeManifest);

    expect(markdown).not.toContain("<script>");
    expect(markdown).not.toContain("<img");
    expect(markdown).not.toContain("\n# injected heading");
    expect(markdown).not.toContain("\n- injected list");
    expect(markdown).not.toContain("**spoofed title**");
    expect(markdown).not.toContain("[spoofed](https://example.invalid)");
    expect(markdown).toContain("&lt;script&gt;alert\\(1\\)&lt;/script&gt;");
    expect(markdown).toContain("\\*\\*spoofed title\\*\\*");
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

  test("renders infrastructure failures in human and machine reports", () => {
    const value = manifestWithInfrastructureError();
    const json = JSON.stringify(generateJsonReport(value));
    const markdown = generateMarkdownReport(value);
    const html = generateHtmlReport(value);

    expect(json).toContain('"infrastructureError"');
    expect(json).toContain("Bitcoin Core unavailable");
    expect(markdown).toContain("Infrastructure error: `Error`");
    expect(markdown).toContain("Bitcoin Core unavailable");
    expect(html).toContain("Infrastructure error");
    expect(html).toContain("Bitcoin Core unavailable");
    for (const report of [json, markdown, html]) {
      expect(report).not.toContain(TESTNET_WIF);
      expect(report).not.toContain(MINIMAL_PSBT);
      expect(report).toContain("[redacted:secret]");
      expect(report).toContain("[redacted:psbt]");
    }
  });

  test("renders adapter cells in human and machine reports", () => {
    const value = manifest();
    const firstScenario = value.scenarios[0];
    if (!firstScenario) throw new Error("Missing report fixture scenario");
    const valueWithCells: RunManifest = {
      ...value,
      scenarios: [
        {
          ...firstScenario,
          adapterCells: [
            {
              adapter: "rust-bitcoin",
              operation: "sign",
              requestId: "request-7",
              status: "failed",
              detail: `AdapterTimeoutError: timed out while signing ${MINIMAL_PSBT}; seed=${TEST_MNEMONIC}`,
              durationMs: 50,
              errorClass: "AdapterTimeoutError",
              restarted: true,
            },
            {
              adapter: "bitcoinjs-lib",
              operation: "roundtrip",
              requestId: "request-8",
              status: "passed",
              detail: "ok",
              durationMs: 5,
            },
          ],
        },
        ...value.scenarios.slice(1),
      ],
    };

    const json = JSON.stringify(generateJsonReport(valueWithCells));
    const markdown = generateMarkdownReport(valueWithCells);
    const html = generateHtmlReport(valueWithCells);

    expect(json).toContain("adapterCells");
    for (const report of [json, markdown, html]) {
      expect(report).toContain("rust-bitcoin");
      expect(report).toContain("request-7");
      expect(report).toContain("AdapterTimeoutError");
      expect(report).toContain("restarted");
      expect(report).not.toContain(TEST_MNEMONIC);
      expect(report).not.toContain(MINIMAL_PSBT);
      expect(report).toContain("[redacted:secret]");
      expect(report).toContain("[redacted:psbt]");
    }
    expect(markdown).toContain("Adapter cells:");
    expect(markdown).toContain("FAILED");
    expect(markdown).toContain("PASSED");
    expect(html).toContain("Adapter cells");
  });
});
