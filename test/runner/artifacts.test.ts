import { mkdtemp, readFile, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { ArtifactRun, type RunManifest } from "../../src/runner/artifacts.js";
import { verifyReplay } from "../../src/runner/replay.js";
import { redactValue } from "../../src/runner/report.js";

const roots: string[] = [];
const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "psbt-lab-artifacts-"));
  roots.push(root);
  return root;
}

function manifest(
  runId: string,
  checkpoint: Awaited<ReturnType<ArtifactRun["checkpoint"]>>,
): RunManifest {
  return {
    schema: "psbt-lab.run/0.1",
    runId,
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
        summary: "Core accepted the finalized transaction",
        durationMs: 12,
        assertions: [{ name: "core-policy-accepted", passed: true }],
      },
    ],
    checkpoints: [checkpoint],
  };
}

afterEach(() => {
  roots.length = 0;
});

describe("ArtifactRun", () => {
  test("writes private PSBT checkpoints and public-safe facts", async () => {
    const root = await temporaryRoot();
    const run = await ArtifactRun.create(root, "run-1");

    const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);

    expect(checkpoint.facts.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(await readFile(join(run.directory, checkpoint.psbtPath), "utf8")).toBe(
      `${MINIMAL_PSBT}\n`,
    );
    expect((await stat(join(run.directory, checkpoint.psbtPath))).mode & 0o777).toBe(0o600);
    expect((await stat(run.directory)).mode & 0o777).toBe(0o700);
  });

  test("rejects path-like identifiers", async () => {
    const root = await temporaryRoot();

    await expect(ArtifactRun.create(root, "../outside")).rejects.toThrow(/identifier/i);
  });

  test("writes a replayable manifest atomically", async () => {
    const root = await temporaryRoot();
    const run = await ArtifactRun.create(root, "run-2");
    const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
    await run.writeManifest(manifest("run-2", checkpoint));

    await expect(verifyReplay(run.directory)).resolves.toMatchObject({
      runId: "run-2",
      verifiedCheckpoints: 1,
      outcome: "passed",
    });
  });

  test("replay detects a modified checkpoint", async () => {
    const root = await temporaryRoot();
    const run = await ArtifactRun.create(root, "run-3");
    const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
    await run.writeManifest(manifest("run-3", checkpoint));
    await writeFile(join(run.directory, checkpoint.psbtPath), "tampered\n", {
      mode: 0o600,
    });

    await expect(verifyReplay(run.directory)).rejects.toThrow(/hash|base64/i);
  });

  test("replay rejects more than 1000 checkpoints before opening files", async () => {
    const root = await temporaryRoot();
    const run = await ArtifactRun.create(root, "run-many");
    const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
    const value = manifest("run-many", checkpoint);
    value.checkpoints = Array.from({ length: 1_001 }, () => checkpoint);
    await run.writeManifest(value);

    await expect(verifyReplay(run.directory)).rejects.toThrow(/checkpoint limit/i);
  });

  test("replay rejects a checkpoint symlink", async () => {
    const root = await temporaryRoot();
    const run = await ArtifactRun.create(root, "run-link");
    const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
    await run.writeManifest(manifest("run-link", checkpoint));
    const target = join(run.directory, "target.psbt");
    await writeFile(target, `${MINIMAL_PSBT}\n`);
    await unlink(join(run.directory, checkpoint.psbtPath));
    await symlink(target, join(run.directory, checkpoint.psbtPath));

    await expect(verifyReplay(run.directory)).rejects.toThrow(/regular file/i);
  });
});

describe("redactValue", () => {
  test("removes PSBTs and private-key-shaped fields from reports", () => {
    expect(
      redactValue({
        psbt: MINIMAL_PSBT,
        keyWif: "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA",
        summary: "adapter error wif=cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA",
        sha256: "a".repeat(64),
      }),
    ).toEqual({
      psbt: "[redacted:psbt]",
      keyWif: "[redacted:secret]",
      summary: "adapter error wif=[redacted:secret]",
      sha256: "a".repeat(64),
    });
  });
});
