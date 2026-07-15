import { describe, expect, test } from "vitest";
import type { RunManifest } from "../../src/runner/artifacts.js";
import { generateHtmlReport } from "../../src/runner/report.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const TESTNET_WIF = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

function manifest(): RunManifest {
  return {
    schema: "psbt-lab.run/0.1",
    runId: "report-run",
    suite: "proof",
    startedAt: "2026-07-16T00:00:00.000Z",
    completedAt: "2026-07-16T00:00:01.000Z",
    outcome: "failed",
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
        summary: `Adapter leaked wif=${TESTNET_WIF} and ${MINIMAL_PSBT}`,
        durationMs: 12.5,
        assertions: [
          {
            name: "fields-preserved",
            policy: "roundtrip",
            passed: false,
            exactBytesEqual: false,
            failures: [
              {
                code: "ENTRY_REMOVED",
                location: { kind: "input", index: 0 },
                keyType: 252,
                completeKeySha256: "b".repeat(64),
                keyBytes: 10,
                before: { valueSha256: "c".repeat(64), valueBytes: 14 },
              },
            ],
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
    expect(html).toContain("UNSUPPORTED");
    expect(html).toContain("Content-Security-Policy");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain(TESTNET_WIF);
    expect(html).not.toContain(MINIMAL_PSBT);
    expect(html).toContain("[redacted:secret]");
    expect(html).toContain("[redacted:psbt]");
  });
});
