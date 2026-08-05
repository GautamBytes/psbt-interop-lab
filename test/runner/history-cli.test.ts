import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import type { RunManifest, ScenarioRecord } from "../../src/runner/artifacts.js";

function scenario(outcome: ScenarioRecord["outcome"]): ScenarioRecord {
  return {
    id: "wallet-handoff",
    title: "Wallet handoff",
    category: "compatibility-history",
    outcome,
    summary: `Wallet handoff ${outcome}`,
    durationMs: 1,
    assertions: [{ name: "compatible", passed: outcome === "passed" }],
    ...(outcome === "failed"
      ? {
          findings: [
            {
              id: "policy-rejected",
              ruleId: "core.transaction.policy-accepted",
              implementation: "wallet",
              summary: "Core rejected the transaction",
              actual: "The transaction was rejected",
            },
          ],
        }
      : {}),
  };
}

function writeRun(
  root: string,
  runId: string,
  completedAt: string,
  outcome: RunManifest["outcome"],
): string {
  const directory = resolve(root, runId);
  mkdirSync(directory);
  const manifest: RunManifest = {
    schema: "psbt-lab.run/0.1",
    runId,
    suite: "proof",
    startedAt: completedAt,
    completedAt,
    outcome,
    adapters: [
      {
        name: "wallet",
        version: "1.0.0",
        sourceRevision: "wallet-v1",
        artifactDigest: `sha256:${"a".repeat(64)}`,
      },
    ],
    scenarios: [scenario(outcome)],
    checkpoints: [],
  };
  writeFileSync(resolve(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return directory;
}

describe("compatibility history CLI", () => {
  test("exports ordered history and ignores an older regression when the newest run improves", () => {
    const root = mkdtempSync(resolve(tmpdir(), "psbt-history-cli-"));
    const entrypoint = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
    const baseRunId = "base\u202eREORDER";
    const base = writeRun(root, baseRunId, "2026-07-24T00:00:01.000Z", "passed");
    const middle = writeRun(root, "middle", "2026-07-25T00:00:01.000Z", "failed");
    const head = writeRun(root, "head", "2026-07-26T00:00:01.000Z", "passed");
    const output = resolve(root, "history-output");

    try {
      const result = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          entrypoint,
          "history",
          base,
          middle,
          head,
          "--output",
          output,
          "--json",
          "--fail-on-regression",
        ],
        { encoding: "utf8", timeout: 30_000 },
      );

      expect(result.status, result.stderr).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({
        schema: "psbt-lab.compatibility-history/0.1",
        transitions: [
          { baseRunId, headRunId: "middle", classification: "regression" },
          { baseRunId: "middle", headRunId: "head", classification: "improvement" },
        ],
      });
      expect(result.stdout).toContain("\\u202eREORDER");
      expect(result.stdout).not.toContain("\u202e");
      expect(result.stdout).not.toContain(root);
      expect(readdirSync(output).sort()).toEqual(["history.json", "history.md"]);
      expect(readFileSync(resolve(output, "history.md"), "utf8")).toContain("middle` -> `head");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 35_000);

  test("prints Markdown before failing on a newest regression", () => {
    const root = mkdtempSync(resolve(tmpdir(), "psbt-history-cli-"));
    const entrypoint = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
    const base = writeRun(root, "base", "2026-07-24T00:00:01.000Z", "passed");
    const head = writeRun(root, "head", "2026-07-25T00:00:01.000Z", "failed");

    try {
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", entrypoint, "history", base, head, "--fail-on-regression"],
        { encoding: "utf8", timeout: 30_000 },
      );

      expect(result.status, result.stderr).toBe(1);
      expect(result.stderr).toBe("");
      expect(result.stdout).toContain("# PSBT Compatibility History");
      expect(result.stdout).toContain("base` -> `head`: REGRESSION");
      expect(result.stdout).not.toContain(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 35_000);
});
