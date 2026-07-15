import { randomBytes } from "node:crypto";
import { chmod, type FileHandle, mkdir, open, rename, unlink } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { AdapterImplementation } from "../protocol/types.js";
import { extractWireFacts, type PsbtWireFacts } from "../psbt/wire-facts.js";
import type { ScenarioResult } from "../scenarios/definition.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface CheckpointRecord {
  scenario: string;
  stage: string;
  psbtPath: string;
  factsPath: string;
  facts: PsbtWireFacts;
}

export type ScenarioRecord = ScenarioResult;

export interface RunManifest {
  schema: "psbt-lab.run/0.1";
  runId: string;
  suite: "proof";
  startedAt: string;
  completedAt: string;
  outcome: "passed" | "failed";
  core: {
    version: number;
    subversion: string;
    blocks: number;
    connections: number;
  };
  adapters: AdapterImplementation[];
  scenarios: ScenarioRecord[];
  checkpoints: CheckpointRecord[];
}

function requireIdentifier(value: string, label: string): void {
  if (!SAFE_IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must be a safe identifier`);
  }
}

function assertContained(root: string, candidate: string): void {
  const pathFromRoot = relative(root, candidate);
  if (pathFromRoot.startsWith("..") || pathFromRoot.startsWith("/")) {
    throw new Error("Artifact path escapes its run directory");
  }
}

async function atomicWrite(path: string, contents: string): Promise<void> {
  const temporary = `${path}.tmp-${randomBytes(8).toString("hex")}`;
  let handle: FileHandle | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export class ArtifactRun {
  #checkpointCounter = 0;

  private constructor(
    readonly directory: string,
    readonly runId: string,
  ) {}

  static async create(root: string, runId: string): Promise<ArtifactRun> {
    requireIdentifier(runId, "Run identifier");
    const resolvedRoot = resolve(root);
    await mkdir(resolvedRoot, { recursive: true, mode: 0o700 });
    const directory = resolve(resolvedRoot, runId);
    assertContained(resolvedRoot, directory);
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
    return new ArtifactRun(directory, runId);
  }

  async checkpoint(scenario: string, stage: string, psbt: string): Promise<CheckpointRecord> {
    requireIdentifier(scenario, "Scenario identifier");
    requireIdentifier(stage, "Checkpoint stage");
    const facts = extractWireFacts(psbt);
    this.#checkpointCounter += 1;
    const prefix = `${String(this.#checkpointCounter).padStart(2, "0")}-${stage}`;
    const relativeDirectory = join("checkpoints", scenario);
    const directory = resolve(this.directory, relativeDirectory);
    assertContained(this.directory, directory);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);

    const psbtPath = join(relativeDirectory, `${prefix}.psbt`);
    const factsPath = join(relativeDirectory, `${prefix}.facts.json`);
    const resolvedPsbtPath = resolve(this.directory, psbtPath);
    const resolvedFactsPath = resolve(this.directory, factsPath);
    assertContained(this.directory, resolvedPsbtPath);
    assertContained(this.directory, resolvedFactsPath);
    await atomicWrite(resolvedPsbtPath, `${psbt}\n`);
    await atomicWrite(resolvedFactsPath, `${JSON.stringify(facts, null, 2)}\n`);

    return { scenario, stage, psbtPath, factsPath, facts };
  }

  async writeManifest(manifest: RunManifest): Promise<void> {
    if (manifest.runId !== this.runId || manifest.schema !== "psbt-lab.run/0.1") {
      throw new Error("Manifest identity does not match the artifact run");
    }
    await atomicWrite(
      join(this.directory, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
  }

  async writeReportJson(value: unknown): Promise<void> {
    await atomicWrite(join(this.directory, "report.json"), `${JSON.stringify(value, null, 2)}\n`);
  }

  async writeReportMarkdown(value: string): Promise<void> {
    await atomicWrite(join(this.directory, "report.md"), `${value.trimEnd()}\n`);
  }

  async writeReportHtml(value: string): Promise<void> {
    await atomicWrite(join(this.directory, "report.html"), `${value.trimEnd()}\n`);
  }
}
