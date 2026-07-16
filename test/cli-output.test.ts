import { describe, expect, test } from "vitest";
import {
  doctorHasBlockingFailure,
  formatDoctorChecks,
  formatProofSummary,
  formatReplaySummary,
  formatScenarioCatalog,
} from "../src/cli-output.js";

describe("CLI output", () => {
  test("prints concise scenario and artifact results", () => {
    const output = formatProofSummary({
      artifactDirectory: "/tmp/artifacts/run-1",
      manifest: {
        schema: "psbt-lab.run/0.1",
        runId: "run-1",
        suite: "proof",
        startedAt: "2026-07-15T00:00:00.000Z",
        completedAt: "2026-07-15T00:00:01.000Z",
        outcome: "passed",
        core: {
          version: 310100,
          subversion: "/Satoshi:31.1.0/",
          blocks: 103,
          connections: 0,
        },
        adapters: [],
        scenarios: [
          {
            id: "happy-path",
            title: "Core to rust-bitcoin signing handoff",
            category: "cross-library-signing",
            outcome: "passed",
            summary: "Policy accepted",
            durationMs: 12,
            assertions: [{ name: "core-policy-accepted", passed: true }],
            findings: [
              {
                id: "known-parser-divergence",
                implementation: "btcsuite-go",
                summary: "Accepted a duplicate global key",
              },
            ],
          },
        ],
        checkpoints: [],
      },
    });

    expect(output).toContain("PASS  happy-path");
    expect(output).toContain("PSBT Interop Lab: PASSED (1 FINDING)");
    expect(output).toContain("FIND  known-parser-divergence: btcsuite-go");
    expect(output).toContain("/tmp/artifacts/run-1");
    expect(output).not.toContain("cHNidP8");
  });

  test("prints replay verification count", () => {
    const output = formatReplaySummary({
      runId: "run-2",
      outcome: "passed",
      verifiedCheckpoints: 5,
      scenarios: [
        {
          id: "invalid-inputs",
          title: "Invalid inputs",
          category: "invalid-inputs",
          outcome: "passed",
          summary: "Parser probes completed",
          durationMs: 1,
          assertions: [{ name: "probe-completed", passed: true }],
          findings: [
            {
              id: "known-parser-divergence",
              implementation: "btcsuite-go",
              summary: "Accepted a duplicate global key",
            },
          ],
        },
      ],
    });
    expect(output).toContain("Verified checkpoints: 5");
    expect(output).toContain("FIND  known-parser-divergence: btcsuite-go");
  });

  test("keeps unsupported and skipped outcomes distinct from failures", () => {
    const base = {
      title: "Scenario",
      category: "test",
      durationMs: 1,
      assertions: [],
      summary: "Recorded outcome",
    } as const;
    const output = formatReplaySummary({
      runId: "run-outcomes",
      outcome: "failed",
      verifiedCheckpoints: 0,
      scenarios: [
        { ...base, id: "unsupported-case", outcome: "unsupported" },
        { ...base, id: "skipped-case", outcome: "skipped" },
        { ...base, id: "failed-case", outcome: "failed" },
      ],
    });

    expect(output).toContain("UNSUP  unsupported-case");
    expect(output).toContain("SKIP  skipped-case");
    expect(output).toContain("FAIL  failed-case");
  });

  test("reports an unbuilt image without failing the preflight", () => {
    const checks = [
      { name: "Docker", ok: true, required: true, detail: "29.1.3" },
      {
        name: "Image psbt-interop-lab/core:31.1",
        ok: false,
        required: false,
        detail: "not built (the run command builds it automatically)",
      },
    ];

    expect(formatDoctorChecks(checks)).toContain("MISS  Image psbt-interop-lab/core:31.1");
    expect(doctorHasBlockingFailure(checks)).toBe(false);
  });

  test("keeps required runtime failures blocking", () => {
    const checks = [{ name: "Docker", ok: false, required: true, detail: "unavailable" }];

    expect(formatDoctorChecks(checks)).toBe("FAIL  Docker: unavailable");
    expect(doctorHasBlockingFailure(checks)).toBe(true);
  });

  test("prints a readable scenario catalog", () => {
    const output = formatScenarioCatalog([
      {
        id: "parallel-sign-and-combine",
        title: "Parallel signing",
        category: "parallel-signing",
      },
    ]);

    expect(output).toContain("CATEGORY");
    expect(output).toContain("parallel-sign-and-combine");
    expect(output).toContain("Parallel signing");
  });
});
