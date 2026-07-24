import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import type { RunManifest } from "../../src/runner/artifacts.js";
import { compareRuns } from "../../src/runner/compare.js";

const roots: string[] = [];

async function temporaryRun(manifest: RunManifest): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-compare-"));
  roots.push(root);
  await writeFile(join(root, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return root;
}

function manifest(overrides: Partial<RunManifest> = {}): RunManifest {
  return {
    schema: "psbt-lab.run/0.1",
    runId: "base-run",
    suite: "proof",
    startedAt: "2026-07-24T00:00:00.000Z",
    completedAt: "2026-07-24T00:00:01.000Z",
    outcome: "passed",
    adapters: [
      {
        name: "rust-bitcoin",
        version: "0.1.0",
        sourceRevision: "bitcoin-crate-0.32.102",
        artifactDigest: `sha256:${"a".repeat(64)}`,
      },
    ],
    scenarios: [
      {
        id: "happy-path",
        title: "Happy path",
        category: "cross-library-signing",
        outcome: "passed",
        summary: "Policy accepted",
        durationMs: 12,
        assertions: [{ name: "core-policy-accepted", passed: true }],
      },
    ],
    checkpoints: [],
    ...overrides,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("compareRuns", () => {
  test("reports changed outcomes, assertions, findings, and adapter identities", async () => {
    const base = await temporaryRun(manifest());
    const head = await temporaryRun(
      manifest({
        runId: "head-run",
        outcome: "failed",
        adapters: [
          {
            name: "rust-bitcoin",
            version: "0.2.0",
            sourceRevision: "bitcoin-crate-0.33.0",
            artifactDigest: `sha256:${"b".repeat(64)}`,
          },
        ],
        scenarios: [
          {
            id: "happy-path",
            title: "Happy path",
            category: "cross-library-signing",
            outcome: "failed",
            summary: "Policy rejected",
            durationMs: 9,
            assertions: [{ name: "core-policy-accepted", passed: false }],
            findings: [
              {
                id: "policy-rejected",
                ruleId: "core.transaction.policy-accepted",
                implementation: "rust-bitcoin",
                summary: "Core rejected the transaction",
                actual: "testmempoolaccept rejected the transaction",
              },
            ],
          },
        ],
      }),
    );

    const comparison = await compareRuns(base, head);

    expect(comparison).toMatchObject({
      changed: true,
      base: { runId: "base-run", outcome: "passed", verifiedCheckpoints: 0 },
      head: { runId: "head-run", outcome: "failed", verifiedCheckpoints: 0 },
      summary: {
        runOutcomeChanged: true,
        scenarioChanges: 1,
        assertionChanges: 1,
        findingChanges: 1,
        adapterChanges: 1,
      },
      changes: expect.arrayContaining([
        expect.objectContaining({
          kind: "run-outcome-changed",
          before: "passed",
          after: "failed",
        }),
        expect.objectContaining({
          kind: "scenario-outcome-changed",
          scenarioId: "happy-path",
          before: "passed",
          after: "failed",
        }),
        expect.objectContaining({
          kind: "assertion-changed",
          scenarioId: "happy-path",
          assertionName: "core-policy-accepted",
          before: "passed",
          after: "failed",
        }),
        expect.objectContaining({
          kind: "finding-added",
          scenarioId: "happy-path",
          findingId: "policy-rejected",
          implementation: "rust-bitcoin",
        }),
        expect.objectContaining({
          kind: "adapter-changed",
          adapter: "rust-bitcoin",
          before: "0.1.0",
          after: "0.2.0",
        }),
      ]),
    });
  });

  test("reports an unchanged comparison when replay manifests match", async () => {
    const baseManifest = manifest();
    const base = await temporaryRun(baseManifest);
    const head = await temporaryRun(manifest({ runId: "head-run" }));

    await expect(compareRuns(base, head)).resolves.toMatchObject({
      changed: false,
      summary: {
        runOutcomeChanged: false,
        scenarioChanges: 0,
        assertionChanges: 0,
        findingChanges: 0,
        adapterChanges: 0,
      },
      changes: [],
    });
  });
});
