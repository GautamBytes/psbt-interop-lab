import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readFile: vi.fn((path: unknown, options?: unknown) => {
      if (String(path).endsWith("manifest.json")) {
        throw new Error("comparison reopened manifest.json after verification");
      }
      return Reflect.apply(actual.readFile, actual, [path, options]);
    }),
  };
});

import type { RunManifest } from "../../src/runner/artifacts.js";
import { compareRuns } from "../../src/runner/compare.js";

const roots: string[] = [];

async function temporaryRun(runId: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-verified-compare-"));
  roots.push(root);
  const manifest: RunManifest = {
    schema: "psbt-lab.run/0.1",
    runId,
    suite: "proof",
    startedAt: "2026-07-24T00:00:00.000Z",
    completedAt: "2026-07-24T00:00:01.000Z",
    outcome: "passed",
    adapters: [],
    scenarios: [],
    checkpoints: [],
  };
  await writeFile(join(root, "manifest.json"), `${JSON.stringify(manifest)}\n`);
  return root;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("compareRuns verified manifest handling", () => {
  test("does not reopen manifest.json after replay verification", async () => {
    const base = await temporaryRun("base-run");
    const head = await temporaryRun("head-run");

    await expect(compareRuns(base, head)).resolves.toMatchObject({
      changed: false,
      base: { runId: "base-run" },
      head: { runId: "head-run" },
    });
  });
});
