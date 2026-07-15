import { constants } from "node:fs";
import { type FileHandle, open, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { extractWireFacts, type PsbtWireFacts } from "../psbt/wire-facts.js";
import type { CheckpointRecord, RunManifest } from "./artifacts.js";

const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_REPLAY_CHECKPOINTS = 1_000;

function optionalOpenFlag(name: string): number {
  const value: unknown = Reflect.get(constants, name);
  return typeof value === "number" ? value : 0;
}

const REPLAY_OPEN_FLAGS =
  constants.O_RDONLY | optionalOpenFlag("O_NOFOLLOW") | optionalOpenFlag("O_NONBLOCK");

export interface ReplaySummary {
  runId: string;
  outcome: "passed" | "failed";
  verifiedCheckpoints: number;
  scenarios: RunManifest["scenarios"];
}

function parseManifest(value: unknown): RunManifest {
  if (typeof value !== "object" || value === null) {
    throw new Error("Replay manifest is not an object");
  }
  const manifest = value as Partial<RunManifest>;
  if (
    manifest.schema !== "psbt-lab.run/0.1" ||
    typeof manifest.runId !== "string" ||
    (manifest.outcome !== "passed" && manifest.outcome !== "failed") ||
    !Array.isArray(manifest.checkpoints) ||
    !Array.isArray(manifest.scenarios)
  ) {
    throw new Error("Replay manifest does not match psbt-lab.run/0.1");
  }
  return manifest as RunManifest;
}

function containedPath(directory: string, path: string): string {
  if (isAbsolute(path)) {
    throw new Error("Replay checkpoint path must be relative");
  }
  const candidate = resolve(directory, path);
  const fromDirectory = relative(directory, candidate);
  if (fromDirectory.startsWith("..") || fromDirectory.startsWith("/")) {
    throw new Error("Replay checkpoint path escapes the artifact directory");
  }
  return candidate;
}

async function readRegularFile(path: string, maxBytes: number): Promise<string> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, REPLAY_OPEN_FLAGS);
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      throw new Error("Replay checkpoint must be a regular file");
    }
    if (metadata.size > maxBytes) {
      throw new Error("Replay checkpoint exceeds its size limit");
    }
    const contents = Buffer.allocUnsafe(maxBytes + 1);
    let offset = 0;
    while (offset < contents.length) {
      const { bytesRead } = await handle.read(contents, offset, contents.length - offset, null);
      if (bytesRead === 0) {
        break;
      }
      offset += bytesRead;
    }
    if (offset > maxBytes) {
      throw new Error("Replay checkpoint exceeds its size limit");
    }
    return contents.toString("utf8", 0, offset);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error("Replay checkpoint must be a regular file");
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function verifyCheckpoint(directory: string, checkpoint: CheckpointRecord): Promise<void> {
  if (
    typeof checkpoint.psbtPath !== "string" ||
    typeof checkpoint.factsPath !== "string" ||
    typeof checkpoint.facts?.sha256 !== "string"
  ) {
    throw new Error("Replay checkpoint record is invalid");
  }
  const psbtText = await readRegularFile(
    containedPath(directory, checkpoint.psbtPath),
    4 * 1024 * 1024 + 1,
  );
  if (!psbtText.endsWith("\n") || psbtText.slice(0, -1).includes("\n")) {
    throw new Error("Replay PSBT checkpoint has invalid line framing");
  }
  let facts: PsbtWireFacts;
  try {
    facts = extractWireFacts(psbtText.slice(0, -1));
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid PSBT";
    throw new Error(
      `Replay checkpoint hash cannot be verified for ${checkpoint.psbtPath}: ${message}`,
    );
  }
  if (facts.sha256 !== checkpoint.facts.sha256) {
    throw new Error(`Replay checkpoint hash mismatch for ${checkpoint.psbtPath}`);
  }

  const factsText = await readRegularFile(
    containedPath(directory, checkpoint.factsPath),
    MAX_MANIFEST_BYTES,
  );
  let storedFacts: unknown;
  try {
    storedFacts = JSON.parse(factsText);
  } catch {
    throw new Error(`Replay facts are invalid JSON for ${checkpoint.factsPath}`);
  }
  if (
    typeof storedFacts !== "object" ||
    storedFacts === null ||
    (storedFacts as Record<string, unknown>)["sha256"] !== facts.sha256
  ) {
    throw new Error(`Replay facts hash mismatch for ${checkpoint.factsPath}`);
  }
}

export async function verifyReplay(directory: string): Promise<ReplaySummary> {
  const canonicalDirectory = await realpath(resolve(directory));
  if (!(await stat(canonicalDirectory)).isDirectory()) {
    throw new Error("Replay path is not a directory");
  }
  const manifestText = await readRegularFile(
    resolve(canonicalDirectory, "manifest.json"),
    MAX_MANIFEST_BYTES,
  );
  let decoded: unknown;
  try {
    decoded = JSON.parse(manifestText);
  } catch {
    throw new Error("Replay manifest is not valid JSON");
  }
  const manifest = parseManifest(decoded);
  if (manifest.checkpoints.length > MAX_REPLAY_CHECKPOINTS) {
    throw new Error(`Replay manifest exceeds the ${MAX_REPLAY_CHECKPOINTS} checkpoint limit`);
  }
  for (const checkpoint of manifest.checkpoints) {
    await verifyCheckpoint(canonicalDirectory, checkpoint);
  }
  return {
    runId: manifest.runId,
    outcome: manifest.outcome,
    verifiedCheckpoints: manifest.checkpoints.length,
    scenarios: manifest.scenarios,
  };
}
