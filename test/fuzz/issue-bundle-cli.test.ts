import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const IMPLEMENTATION = {
  name: "permissive-wallet-parser",
  version: "1.0.0",
  sourceRevision: "permissive-wallet-parser-v1",
  artifactDigest: `sha256:${"c".repeat(64)}`,
};

function digest(contents: string): string {
  return `sha256:${createHash("sha256").update(contents, "utf8").digest("hex")}`;
}

describe("parser issue bundle CLI", () => {
  test("exports and replays a minimized external-parser divergence", () => {
    const root = mkdtempSync(resolve(tmpdir(), "psbt-issue-bundle-cli-"));
    const manifestPath = resolve(root, "adapter-manifest.json");
    const bundlePath = resolve(root, "issue-bundle");
    const entrypoint = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
    const adapter = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
    writeFileSync(
      manifestPath,
      `${JSON.stringify({
        schema: "psbt-lab.adapters/0.1",
        adapters: [
          {
            id: "permissive-wallet",
            command: process.execPath,
            args: [adapter, "permissive-parser"],
            expected: IMPLEMENTATION,
          },
        ],
      })}\n`,
      { mode: 0o600 },
    );

    try {
      const exported = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          entrypoint,
          "fuzz",
          "--runtime",
          "local",
          "--adapter-manifest",
          manifestPath,
          "--fixture",
          "bip174-minimal-v0",
          "--seed",
          "42",
          "--cases",
          "8",
          "--issue-bundle",
          bundlePath,
        ],
        { encoding: "utf8", timeout: 60_000 },
      );

      expect(exported.status, exported.stderr).toBe(0);
      expect(exported.stderr).toBe("");
      expect(exported.stdout).toMatch(/semantic-invalid=\d+/);
      expect(readdirSync(bundlePath).sort()).toEqual([
        "issue.md",
        "manifest.json",
        "regression-suite.json",
      ]);
      const issue = readFileSync(resolve(bundlePath, "issue.md"), "utf8");
      const suite = readFileSync(resolve(bundlePath, "regression-suite.json"), "utf8");
      const manifest = JSON.parse(readFileSync(resolve(bundlePath, "manifest.json"), "utf8"));
      expect(manifest.schema).toBe("psbt-lab.issue-bundle/0.2");
      expect(manifest.outputAmountSemantics).toEqual({
        status: "not-evaluated",
        findings: [],
      });
      expect(manifest).toMatchObject({
        implementations: { "permissive-wallet": IMPLEMENTATION },
        files: {
          "issue.md": digest(issue),
          "regression-suite.json": digest(suite),
        },
      });
      expect(issue).toContain("## Lab semantic assessment");
      expect(issue).not.toContain(adapter);
      expect(issue).not.toContain(process.execPath);

      const replayed = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          entrypoint,
          "parse-matrix",
          "--runtime",
          "local",
          "--adapter-manifest",
          manifestPath,
          "--suite-manifest",
          resolve(bundlePath, "regression-suite.json"),
          "--json",
        ],
        { encoding: "utf8", timeout: 60_000 },
      );

      expect(replayed.status, replayed.stderr).toBe(0);
      expect(replayed.stderr).toBe("");
      expect(JSON.parse(replayed.stdout)).toMatchObject({
        runtime: "local+external",
        outcome: "passed",
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);
});
