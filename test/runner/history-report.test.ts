import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import type {
  CompatibilityHistoryReport,
  CompatibilityHistoryTransition,
} from "../../src/runner/history.js";
import {
  createCompatibilityHistoryBundle,
  formatCompatibilityHistory,
  writeCompatibilityHistoryBundle,
} from "../../src/runner/history-report.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function transition(
  baseRunId: string,
  headRunId: string,
  classification: CompatibilityHistoryTransition["classification"],
): CompatibilityHistoryTransition {
  return {
    baseRunId,
    headRunId,
    classification,
    signals: {
      regressions: classification === "regression" || classification === "mixed" ? 1 : 0,
      improvements: classification === "improvement" || classification === "mixed" ? 1 : 0,
      neutral: classification === "changed" ? 1 : 0,
    },
    changes:
      classification === "regression"
        ? [
            {
              direction: "regression",
              change: { kind: "run-outcome-changed", before: "passed", after: "failed" },
            },
          ]
        : classification === "changed"
          ? [
              {
                direction: "neutral",
                change: {
                  kind: "adapter-changed",
                  adapter: "wallet``` [forged](https://example.invalid)",
                  before: "1.0.0",
                  after: "2.0.0",
                },
              },
            ]
          : [],
  };
}

function report(): CompatibilityHistoryReport {
  const transitions = [
    transition("run-1", "run-2", "unchanged"),
    transition("run-2", "run-3", "regression"),
    transition("run-3", "run-4", "improvement"),
    transition("run-4", "run-5", "mixed"),
    transition("run-5", "run-6", "changed"),
  ];
  return {
    schema: "psbt-lab.compatibility-history/0.1",
    runs: Array.from({ length: 6 }, (_, index) => ({
      runId: `run-${index + 1}`,
      completedAt: `2026-07-${String(index + 20).padStart(2, "0")}T00:00:01.000Z`,
      outcome: index === 2 ? ("failed" as const) : ("passed" as const),
      verifiedCheckpoints: index,
    })),
    transitions,
    summary: {
      runs: 6,
      transitions: 5,
      unchanged: 1,
      regressions: 1,
      improvements: 1,
      mixed: 1,
      changed: 1,
    },
  };
}

describe("compatibility history report", () => {
  test("renders deterministic JSON and Markdown for every transition class", () => {
    const first = createCompatibilityHistoryBundle(report());
    const second = createCompatibilityHistoryBundle(report());

    expect(first).toEqual(second);
    expect(first.map(({ path }) => path)).toEqual(["history.json", "history.md"]);
    const files = Object.fromEntries(first.map((file) => [file.path, file.contents]));
    const json = files["history.json"];
    const markdown = files["history.md"];
    if (!json || !markdown) throw new Error("Incomplete compatibility history bundle");

    expect(JSON.parse(json)).toEqual(report());
    expect(markdown).toContain("# PSBT Compatibility History");
    expect(markdown).toContain("regressions=1 improvements=1 mixed=1 changed=1 unchanged=1");
    for (const classification of ["UNCHANGED", "REGRESSION", "IMPROVEMENT", "MIXED", "CHANGED"]) {
      expect(markdown).toContain(classification);
    }
    expect(markdown).toContain("```` wallet``` [forged](https://example.invalid) ````");
    expect(markdown).not.toContain("wallet\\`\\`\\`");
    expect(formatCompatibilityHistory(report())).toBe(markdown);
  });

  test("writes privately to a new directory and refuses existing entries", async () => {
    const root = await mkdtemp(join(tmpdir(), "psbt-history-report-"));
    roots.push(root);
    const destination = join(root, "history");
    await writeCompatibilityHistoryBundle(destination, report());

    await expect(readFile(join(destination, "history.md"), "utf8")).resolves.toContain(
      "Compatibility History",
    );
    await expect(writeCompatibilityHistoryBundle(destination, report())).rejects.toThrow(
      /already exists/i,
    );

    const file = join(root, "existing-file");
    const link = join(root, "existing-link");
    await writeFile(file, "keep\n", { mode: 0o600 });
    await symlink(file, link);
    await expect(writeCompatibilityHistoryBundle(file, report())).rejects.toThrow(
      /already exists/i,
    );
    await expect(writeCompatibilityHistoryBundle(link, report())).rejects.toThrow(
      /already exists/i,
    );
    await expect(readFile(file, "utf8")).resolves.toBe("keep\n");
    await expect(lstat(link)).resolves.toMatchObject({});
  });
});
