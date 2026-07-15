import { describe, expect, test } from "vitest";
import {
  doctorHasBlockingFailure,
  formatDoctorChecks,
  formatProofSummary,
  formatReplaySummary,
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
            outcome: "passed",
            summary: "Policy accepted",
          },
        ],
        checkpoints: [],
      },
    });

    expect(output).toContain("PASS  happy-path");
    expect(output).toContain("/tmp/artifacts/run-1");
    expect(output).not.toContain("cHNidP8");
  });

  test("prints replay verification count", () => {
    expect(
      formatReplaySummary({
        runId: "run-2",
        outcome: "passed",
        verifiedCheckpoints: 5,
        scenarios: [],
      }),
    ).toContain("Verified checkpoints: 5");
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
});
