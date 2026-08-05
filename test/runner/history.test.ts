import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { RunManifest, ScenarioRecord } from "../../src/runner/artifacts.js";
import type { RunComparisonChange } from "../../src/runner/compare.js";
import {
  buildCompatibilityHistory,
  classifyCompatibilityChange,
  historyHasLatestRegression,
} from "../../src/runner/history.js";
import * as replay from "../../src/runner/replay.js";

const roots: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function scenario(id: string, outcome: ScenarioRecord["outcome"], passed: boolean): ScenarioRecord {
  return {
    id,
    title: id,
    category: "compatibility-history",
    outcome,
    summary: `${id} ${outcome}`,
    durationMs: 1,
    assertions: [{ name: "compatible", passed }],
    ...(outcome === "failed"
      ? {
          findings: [
            {
              id: "compatibility-regression",
              ruleId: "core.transaction.policy-accepted",
              implementation: "wallet",
              summary: "Compatibility regressed",
              actual: "The checked behavior changed",
            },
          ],
        }
      : {}),
  };
}

function manifest(
  runId: string,
  completedAt: string,
  outcome: RunManifest["outcome"],
  scenarios: ScenarioRecord[] = [scenario("handoff", outcome, outcome === "passed")],
): RunManifest {
  return {
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
    scenarios,
    checkpoints: [],
  };
}

async function temporaryRun(value: RunManifest): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-history-"));
  roots.push(root);
  await writeFile(join(root, "manifest.json"), `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
  });
  return root;
}

describe("classifyCompatibilityChange", () => {
  test.each<[RunComparisonChange, string]>([
    [{ kind: "run-outcome-changed", before: "passed", after: "failed" }, "regression"],
    [{ kind: "run-outcome-changed", before: "failed", after: "passed" }, "improvement"],
    [
      {
        kind: "scenario-outcome-changed",
        scenarioId: "handoff",
        before: "passed",
        after: "unsupported",
      },
      "regression",
    ],
    [
      {
        kind: "scenario-outcome-changed",
        scenarioId: "handoff",
        before: "failed",
        after: "passed",
      },
      "improvement",
    ],
    [
      {
        kind: "assertion-changed",
        scenarioId: "handoff",
        assertionName: "compatible",
        before: "passed",
        after: "failed",
      },
      "regression",
    ],
    [
      {
        kind: "assertion-changed",
        scenarioId: "handoff",
        assertionName: "compatible",
        before: "failed",
        after: "passed",
      },
      "improvement",
    ],
    [
      {
        kind: "finding-added",
        scenarioId: "handoff",
        findingId: "regression",
        implementation: "wallet",
      },
      "regression",
    ],
    [
      {
        kind: "finding-removed",
        scenarioId: "handoff",
        findingId: "regression",
        implementation: "wallet",
      },
      "improvement",
    ],
  ])("classifies directional change %#", (change, expected) => {
    expect(classifyCompatibilityChange(change)).toBe(expected);
  });

  test.each<RunComparisonChange>([
    {
      kind: "scenario-outcome-changed",
      scenarioId: "handoff",
      before: "passed",
      after: "skipped",
    },
    { kind: "scenario-added", scenarioId: "new-coverage", after: "failed" },
    { kind: "scenario-removed", scenarioId: "old-coverage", before: "failed" },
    {
      kind: "finding-changed",
      scenarioId: "handoff",
      findingId: "detail",
      implementation: "wallet",
    },
    { kind: "adapter-changed", adapter: "wallet", before: "1.0.0", after: "2.0.0" },
    { kind: "adapter-capabilities-changed", adapter: "wallet" },
    { kind: "checkpoint-added", scenarioId: "handoff", stage: "signed" },
  ])("keeps non-directional change neutral: $kind", (change) => {
    expect(classifyCompatibilityChange(change)).toBe("neutral");
  });
});

describe("buildCompatibilityHistory", () => {
  test("replay-verifies each input artifact exactly once", async () => {
    const base = await temporaryRun(manifest("base", "2026-07-24T00:00:01.000Z", "passed"));
    const middle = await temporaryRun(manifest("middle", "2026-07-25T00:00:01.000Z", "failed"));
    const head = await temporaryRun(manifest("head", "2026-07-26T00:00:01.000Z", "passed"));
    const load = vi.spyOn(replay, "loadVerifiedReplay");

    await buildCompatibilityHistory([base, middle, head]);

    expect(load).toHaveBeenCalledTimes(3);
    expect(load.mock.calls.map(([directory]) => directory)).toEqual([base, middle, head]);
  });

  test("builds ordered regression and improvement transitions", async () => {
    const base = await temporaryRun(manifest("base", "2026-07-24T00:00:01.000Z", "passed"));
    const middle = await temporaryRun(manifest("middle", "2026-07-25T00:00:01.000Z", "failed"));
    const head = await temporaryRun(manifest("head", "2026-07-26T00:00:01.000Z", "passed"));

    const history = await buildCompatibilityHistory([base, middle, head]);

    expect(history).toMatchObject({
      schema: "psbt-lab.compatibility-history/0.1",
      runs: [
        { runId: "base", outcome: "passed", verifiedCheckpoints: 0 },
        { runId: "middle", outcome: "failed", verifiedCheckpoints: 0 },
        { runId: "head", outcome: "passed", verifiedCheckpoints: 0 },
      ],
      transitions: [
        { baseRunId: "base", headRunId: "middle", classification: "regression" },
        { baseRunId: "middle", headRunId: "head", classification: "improvement" },
      ],
      summary: {
        runs: 3,
        transitions: 2,
        unchanged: 0,
        regressions: 1,
        improvements: 1,
        mixed: 0,
        changed: 0,
      },
    });
    expect(historyHasLatestRegression(history)).toBe(false);
  });

  test("distinguishes unchanged, neutral-only, and mixed transitions", async () => {
    const unchangedBase = await temporaryRun(
      manifest("unchanged-base", "2026-07-24T00:00:01.000Z", "passed"),
    );
    const unchangedHead = await temporaryRun(
      manifest("unchanged-head", "2026-07-25T00:00:01.000Z", "passed"),
    );
    const neutralHeadManifest = manifest("neutral-head", "2026-07-26T00:00:01.000Z", "passed");
    const neutralAdapter = neutralHeadManifest.adapters[0];
    if (!neutralAdapter) throw new Error("Expected a history test adapter");
    neutralHeadManifest.adapters[0] = { ...neutralAdapter, version: "2.0.0" };
    const neutralHead = await temporaryRun(neutralHeadManifest);
    const mixedHead = await temporaryRun(
      manifest("mixed-head", "2026-07-27T00:00:01.000Z", "failed", [
        scenario("handoff", "failed", false),
        scenario("recovered", "passed", true),
      ]),
    );
    const mixedBase = await temporaryRun(
      manifest("mixed-base", "2026-07-26T12:00:01.000Z", "failed", [
        scenario("handoff", "passed", true),
        scenario("recovered", "failed", false),
      ]),
    );

    await expect(buildCompatibilityHistory([unchangedBase, unchangedHead])).resolves.toMatchObject({
      transitions: [{ classification: "unchanged" }],
    });
    await expect(buildCompatibilityHistory([unchangedHead, neutralHead])).resolves.toMatchObject({
      transitions: [{ classification: "changed" }],
    });
    const mixed = await buildCompatibilityHistory([mixedBase, mixedHead]);
    expect(mixed.transitions[0]?.classification).toBe("mixed");
    expect(historyHasLatestRegression(mixed)).toBe(true);
  });

  test("bounds input before reading artifacts", async () => {
    await expect(buildCompatibilityHistory(["one"])).rejects.toThrow(/between 2 and 64/i);
    await expect(
      buildCompatibilityHistory(Array.from({ length: 65 }, () => "never-read")),
    ).rejects.toThrow(/between 2 and 64/i);
  });

  test("rejects duplicate run ids", async () => {
    const first = await temporaryRun(manifest("same", "2026-07-24T00:00:01.000Z", "passed"));
    const second = await temporaryRun(manifest("same", "2026-07-25T00:00:01.000Z", "passed"));

    await expect(buildCompatibilityHistory([first, second])).rejects.toThrow(
      /duplicate run id "same"/i,
    );
  });

  test("rejects invalid and decreasing completion timestamps", async () => {
    const invalid = await temporaryRun(manifest("invalid", "not-a-time", "passed"));
    const valid = await temporaryRun(manifest("valid", "2026-07-25T00:00:01.000Z", "passed"));
    await expect(buildCompatibilityHistory([invalid, valid])).rejects.toThrow(
      /completedAt.*timestamp/i,
    );

    const later = await temporaryRun(manifest("later", "2026-07-26T00:00:01.000Z", "passed"));
    const earlier = await temporaryRun(manifest("earlier", "2026-07-25T00:00:01.000Z", "passed"));
    await expect(buildCompatibilityHistory([later, earlier])).rejects.toThrow(/oldest-to-newest/i);
  });

  test("does not reflect terminal control characters in validation errors", async () => {
    const invalid = await temporaryRun(manifest("bad\u001b[31m\u202e", "not-a-time", "passed"));
    const valid = await temporaryRun(manifest("valid", "2026-07-25T00:00:01.000Z", "passed"));

    const error = await buildCompatibilityHistory([invalid, valid]).catch((reason: unknown) =>
      String(reason),
    );

    expect(error).toContain("\\u001b");
    expect(error).toContain("\\u{202e}");
    expect(error).not.toContain("\u001b");
    expect(error).not.toContain("\u202e");
  });
});
