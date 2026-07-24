import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import type { AdapterHelloCapabilities } from "../../src/protocol/types.js";
import { ArtifactRun, type RunManifest } from "../../src/runner/artifacts.js";
import { compareRuns } from "../../src/runner/compare.js";

const roots: string[] = [];
const magic = Buffer.from("70736274ff", "hex");
const publicKey = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
const signature = Buffer.concat([
  Buffer.from("30440220", "hex"),
  Buffer.alloc(32, 1),
  Buffer.from("0220", "hex"),
  Buffer.alloc(32, 2),
  Buffer.from([1]),
]);

async function temporaryRun(manifest: RunManifest): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-compare-"));
  roots.push(root);
  await writeFile(join(root, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return root;
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function psbt(inputEntries: readonly Buffer[] = []): string {
  const transaction = Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 1),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fcffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("2a000000", "hex"),
  ]);
  return Buffer.concat([
    magic,
    map(entry(0x00, transaction)),
    map(...inputEntries),
    map(),
  ]).toString("base64");
}

async function temporaryArtifactRun(
  runId: string,
  encodedPsbt: string,
  overrides: Partial<RunManifest> = {},
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-compare-artifacts-"));
  roots.push(root);
  const run = await ArtifactRun.create(root, runId);
  const checkpoint = await run.checkpoint("happy-path", "handoff", encodedPsbt);
  await run.writeManifest(manifest({ runId, checkpoints: [checkpoint], ...overrides }));
  return run.directory;
}

function capabilities(overrides: Partial<AdapterHelloCapabilities> = {}): AdapterHelloCapabilities {
  return {
    operations: ["hello", "native-parse", "roundtrip"],
    roles: ["parser"],
    psbtVersions: [0],
    scriptTypes: ["p2wpkh"],
    operationScriptTypes: { roundtrip: ["p2wpkh"] },
    features: ["fixture-commitment-sha256"],
    ...overrides,
  };
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
        capabilityChanges: 0,
        checkpointChanges: 0,
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
        capabilityChanges: 0,
        checkpointChanges: 0,
      },
      changes: [],
    });
  });

  test("reports checkpoint fact changes even when scenario outcomes still pass", async () => {
    const base = await temporaryArtifactRun("base-run", psbt());
    const head = await temporaryArtifactRun("head-run", psbt([entry(0x02, signature, publicKey)]));

    await expect(compareRuns(base, head)).resolves.toMatchObject({
      changed: true,
      summary: {
        runOutcomeChanged: false,
        scenarioChanges: 0,
        assertionChanges: 0,
        findingChanges: 0,
        adapterChanges: 0,
        capabilityChanges: 0,
        checkpointChanges: 1,
      },
      changes: [
        expect.objectContaining({
          kind: "checkpoint-facts-changed",
          scenarioId: "happy-path",
          stage: "handoff",
        }),
      ],
    });
  });

  test("reports adapter capability changes separately from adapter identity changes", async () => {
    const base = await temporaryRun(
      manifest({
        adapters: [
          {
            name: "rust-bitcoin",
            version: "0.1.0",
            artifactDigest: `sha256:${"a".repeat(64)}`,
            capabilities: capabilities(),
          },
        ],
      }),
    );
    const head = await temporaryRun(
      manifest({
        runId: "head-run",
        adapters: [
          {
            name: "rust-bitcoin",
            version: "0.1.0",
            artifactDigest: `sha256:${"a".repeat(64)}`,
            capabilities: capabilities({
              operations: ["hello", "native-parse", "roundtrip", "sign"],
              roles: ["parser", "signer"],
              operationScriptTypes: { roundtrip: ["p2wpkh"], sign: ["p2wpkh"] },
            }),
          },
        ],
      }),
    );

    await expect(compareRuns(base, head)).resolves.toMatchObject({
      changed: true,
      summary: {
        runOutcomeChanged: false,
        scenarioChanges: 0,
        assertionChanges: 0,
        findingChanges: 0,
        adapterChanges: 0,
        capabilityChanges: 1,
        checkpointChanges: 0,
      },
      changes: [
        expect.objectContaining({
          kind: "adapter-capabilities-changed",
          adapter: "rust-bitcoin",
        }),
      ],
    });
  });
});
