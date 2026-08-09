import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import type { RunManifest } from "../../src/runner/artifacts.js";
import {
  generateJunitReport,
  generateSarifReport,
  writeCiReports,
} from "../../src/runner/ci-reports.js";

const TEST_WIF = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

function manifest(): RunManifest {
  return {
    schema: "psbt-lab.run/0.1",
    runId: "ci-report-run",
    suite: "proof",
    startedAt: "2026-07-26T00:00:00.000Z",
    completedAt: "2026-07-26T00:00:01.000Z",
    outcome: "failed",
    adapters: [],
    checkpoints: [],
    scenarios: [
      {
        id: "passed-case",
        title: "Passed <case>",
        category: "unit",
        outcome: "passed",
        summary: "All checks passed",
        durationMs: 12.5,
        assertions: [{ name: "intent-preserved", passed: true }],
      },
      {
        id: "failed-case",
        title: 'Failed "case"',
        category: "unit",
        outcome: "failed",
        summary: `Signer leaked wif=${TEST_WIF}`,
        durationMs: 3,
        assertions: [
          {
            name: "taproot-fields-preserved",
            passed: false,
            likelyImplementation: "wallet-adapter",
            summary: `Mismatch with wif=${TEST_WIF}`,
          },
        ],
        findings: [
          {
            id: "known-divergence",
            ruleId: "bip174.map-keys.unique",
            implementation: "wallet-adapter",
            summary: "Accepted a duplicate key",
            actual: "Duplicate key was accepted",
          },
        ],
      },
      {
        id: "unsupported-case",
        title: "Unsupported case",
        category: "unit",
        outcome: "unsupported",
        summary: "Missing parser",
        durationMs: 0,
        assertions: [],
      },
      {
        id: "skipped-case",
        title: "Skipped case",
        category: "unit",
        outcome: "skipped",
        summary: "Not selected",
        durationMs: 0,
        assertions: [],
      },
    ],
  };
}

describe("CI reports", () => {
  test("renders one escaped and redacted JUnit case per scenario", () => {
    const report = generateJunitReport(manifest());

    expect(report).toContain(
      '<testsuite name="psbt-interop-lab" tests="4" failures="2" skipped="1"',
    );
    expect(report).toContain('name="Passed &lt;case&gt;"');
    expect(report).toContain('name="Failed &quot;case&quot;"');
    expect(report).toContain('<failure message="Signer leaked wif=[redacted:secret]">');
    expect(report).toContain('<failure type="capability.unsupported" message="Missing parser">');
    expect(report.match(/<skipped /g)).toHaveLength(1);
    expect(report).not.toContain(TEST_WIF);
  });

  test("renders findings and failed assertions as stable SARIF results", () => {
    const report = JSON.parse(generateSarifReport(manifest())) as {
      version: string;
      runs: Array<{
        tool: { driver: { version: string; rules: Array<{ id: string }> } };
        results: Array<{
          ruleId: string;
          message: { text: string };
          properties: Record<string, unknown>;
        }>;
      }>;
    };

    expect(report.version).toBe("2.1.0");
    expect(report.runs[0]?.tool.driver.version).toBe("0.10.0");
    expect(report.runs[0]?.tool.driver.rules.map(({ id }) => id)).toEqual([
      "bip174.map-keys.unique",
      "psbt-lab.assertion.taproot-fields-preserved",
      "psbt-lab.scenario.unsupported",
    ]);
    expect(report.runs[0]?.results).toHaveLength(3);
    expect(report.runs[0]?.results[0]).toMatchObject({
      ruleId: "bip174.map-keys.unique",
      properties: { scenario: "failed-case", implementation: "wallet-adapter" },
    });
    expect(report.runs[0]?.results[1]?.message.text).toContain("[redacted:secret]");
    expect(report.runs[0]?.results[2]).toMatchObject({
      ruleId: "psbt-lab.scenario.unsupported",
      properties: { scenario: "unsupported-case", outcome: "unsupported" },
    });
    expect(JSON.stringify(report)).not.toContain(TEST_WIF);
  });

  test("emits a run-policy error when a failed manifest contains only skipped scenarios", () => {
    const skippedOnly = {
      ...manifest(),
      scenarios: [
        {
          id: "skipped-case",
          title: "Skipped case",
          category: "unit",
          outcome: "skipped" as const,
          summary: "Required runtime was unavailable",
          durationMs: 0,
          assertions: [],
        },
      ],
    };

    expect(generateJunitReport(skippedOnly)).toContain(
      '<testcase classname="run-policy" name="PSBT Interop Lab run outcome"',
    );
    const sarif = JSON.parse(generateSarifReport(skippedOnly)) as {
      runs: Array<{ results: Array<{ ruleId: string }> }>;
    };
    expect(sarif.runs[0]?.results).toEqual([
      expect.objectContaining({ ruleId: "psbt-lab.run.failed" }),
    ]);
  });

  test("writes requested reports with private file permissions", async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "psbt-ci-reports-"));
    const junit = resolve(directory, "nested", "junit.xml");
    const sarif = resolve(directory, "nested", "report.sarif");

    try {
      await writeCiReports(manifest(), { junit, sarif });

      expect(await readFile(junit, "utf8")).toContain("<testsuite");
      expect(JSON.parse(await readFile(sarif, "utf8"))).toMatchObject({ version: "2.1.0" });
      expect((await stat(junit)).mode & 0o777).toBe(0o600);
      expect((await stat(sarif)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
