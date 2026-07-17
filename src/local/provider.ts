import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdtemp, open, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { AdapterProcess, type AdapterProcessOptions } from "../protocol/adapter-process.js";
import type {
  RuntimeAdapter,
  RuntimeAdapterProcess,
  RuntimeProvider,
} from "../runtime/provider.js";
import {
  type LocalRuntimeManifest,
  loadLocalRuntimeManifest,
  parseLocalRuntimeManifest,
} from "./manifest.js";

const MAX_ADAPTER_BYTES = 16 * 1024 * 1024;

export interface CreateLocalRuntimeProviderOptions {
  readonly packageDirectory: string;
  readonly manifest?: unknown;
  readonly manifestPath?: string;
  readonly createProcess?: (options: AdapterProcessOptions) => RuntimeAdapterProcess;
}

function isContained(parent: string, child: string): boolean {
  const path = relative(parent, child);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

async function verifiedArtifact(
  packageDirectory: string,
  adapterId: string,
  artifactPath: string,
  expectedDigest: string,
  executable: boolean,
): Promise<{ readonly canonical: string; readonly bytes: Buffer }> {
  const candidate = resolve(packageDirectory, artifactPath);
  if (!isContained(packageDirectory, candidate)) {
    throw new Error(`Local adapter ${adapterId} path is outside the package directory`);
  }
  const candidateStat = await lstat(candidate);
  if (candidateStat.isSymbolicLink()) {
    const target = await realpath(candidate);
    if (!isContained(packageDirectory, target)) {
      throw new Error(`Local adapter ${adapterId} path resolves outside the package directory`);
    }
    throw new Error(`Local adapter ${adapterId} path must not be a symbolic link`);
  }
  const canonical = await realpath(candidate);
  if (!isContained(packageDirectory, canonical)) {
    throw new Error(`Local adapter ${adapterId} path resolves outside the package directory`);
  }
  const handle = await open(canonical, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_ADAPTER_BYTES) {
      throw new Error(`Local adapter ${adapterId} must be a regular file no larger than 16 MiB`);
    }
    if (executable && process.platform !== "win32" && (stat.mode & 0o111) === 0) {
      throw new Error(`Local adapter ${adapterId} is not executable`);
    }
    const bytes = await handle.readFile();
    const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    if (digest !== expectedDigest) {
      throw new Error(`Local adapter checksum mismatch for ${adapterId}`);
    }
    return { canonical, bytes };
  } finally {
    await handle.close();
  }
}

async function privateSnapshot(
  directory: string,
  adapterId: string,
  sourcePath: string,
  bytes: Buffer,
  executable: boolean,
): Promise<string> {
  const extension = basename(sourcePath).includes(".") ? `.${basename(sourcePath).split(".").pop()}` : "";
  const path = join(directory, `${adapterId}${extension}`);
  const handle = await open(path, "wx", executable ? 0o500 : 0o400);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(path, executable ? 0o500 : 0o400);
  return path;
}

async function resolveManifest(
  options: CreateLocalRuntimeProviderOptions,
): Promise<LocalRuntimeManifest> {
  if (options.manifest !== undefined && options.manifestPath !== undefined) {
    throw new TypeError("Provide either a local runtime manifest or a manifest path, not both");
  }
  if (options.manifest !== undefined) return parseLocalRuntimeManifest(options.manifest);
  if (options.manifestPath !== undefined) return loadLocalRuntimeManifest(options.manifestPath);
  throw new TypeError("A local runtime manifest or manifest path is required");
}

export async function createLocalRuntimeProvider(
  options: CreateLocalRuntimeProviderOptions,
): Promise<RuntimeProvider> {
  const packageDirectory = await realpath(options.packageDirectory);
  const manifest = await resolveManifest(options);
  const createProcess =
    options.createProcess ?? ((processOptions) => new AdapterProcess(processOptions));
  const adapters: RuntimeAdapter[] = [];
  const snapshotDirectory = await mkdtemp(join(tmpdir(), "psbt-lab-local-adapters-"));
  await chmod(snapshotDirectory, 0o700);

  try {
    for (const definition of manifest.adapters) {
      if (definition.availability === "unsupported") {
        adapters.push(definition);
        continue;
      }
      const verified = await verifiedArtifact(
        packageDirectory,
        definition.id,
        definition.launch.path,
        definition.launch.sha256,
        definition.launch.kind === "executable",
      );
      const artifact = await privateSnapshot(
        snapshotDirectory,
        definition.id,
        verified.canonical,
        verified.bytes,
        definition.launch.kind === "executable",
      );
      const processOptions: AdapterProcessOptions =
        definition.launch.kind === "node"
          ? { command: process.execPath, args: [artifact], cwd: packageDirectory }
          : { command: artifact, args: [], cwd: packageDirectory };
      adapters.push({
        id: definition.id,
        availability: "available",
        process: createProcess(processOptions),
        timeoutMs: definition.timeoutMs,
        expected: definition.expected,
      });
    }
  } catch (error) {
    await Promise.allSettled(
      adapters.flatMap((adapter) =>
        adapter.availability === "available" ? [adapter.process.close()] : [],
      ),
    );
    await rm(snapshotDirectory, { recursive: true, force: true });
    throw error;
  }

  let closed = false;
  return {
    runtime: "local",
    async adapters() {
      return [...adapters];
    },
    async close() {
      if (closed) return;
      closed = true;
      await Promise.all(
        adapters.flatMap((adapter) =>
          adapter.availability === "available" ? [adapter.process.close()] : [],
        ),
      );
      await rm(snapshotDirectory, { recursive: true, force: true });
    },
  };
}
