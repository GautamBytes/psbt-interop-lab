import { lstat, mkdir, open, rm } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { isAbsolute, normalize } from "node:path/posix";
import type { GeneratedFile } from "./model.js";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown filesystem failure";
}

async function requireDirectory(path: string): Promise<void> {
  try {
    const entry = await lstat(path);
    if (!entry.isDirectory()) throw new TypeError("Destination parent must be a real directory");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new TypeError("Destination parent must be an existing directory", { cause: error });
    }
    throw error;
  }
}

async function requireAbsent(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new TypeError(`Destination already exists: ${path}`);
}

function validateGeneratedFiles(files: readonly GeneratedFile[]): readonly GeneratedFile[] {
  const seen = new Set<string>();
  return [...files]
    .sort((left, right) => left.path.localeCompare(right.path))
    .map((file) => {
      const normalized = normalize(file.path);
      if (
        file.path.length === 0 ||
        file.path.includes("\\") ||
        file.path.includes("\0") ||
        isAbsolute(file.path) ||
        normalized === "." ||
        normalized === ".." ||
        normalized !== file.path ||
        normalized.startsWith("../") ||
        seen.has(file.path)
      ) {
        throw new TypeError(`Invalid generated file path: ${file.path}`);
      }
      seen.add(file.path);
      return file;
    });
}

function assertContained(root: string, candidate: string): void {
  const pathFromRoot = relative(root, candidate);
  if (
    pathFromRoot === ".." ||
    pathFromRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
  ) {
    throw new TypeError(`Generated file path escapes destination: ${candidate}`);
  }
}

async function writeExclusive(path: string, contents: string): Promise<void> {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
  } finally {
    await handle.close();
  }
}

export async function writeGeneratedProject(
  destination: string,
  files: readonly GeneratedFile[],
): Promise<void> {
  const validated = validateGeneratedFiles(files);
  const resolvedDestination = resolve(destination);
  const parent = dirname(resolvedDestination);
  await requireDirectory(parent);
  await requireAbsent(resolvedDestination);

  let ownedDestination = false;
  try {
    await mkdir(resolvedDestination, { mode: 0o700 });
    ownedDestination = true;
    for (const file of validated) {
      const path = resolve(resolvedDestination, file.path);
      assertContained(resolvedDestination, path);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeExclusive(path, file.contents);
    }
  } catch (error) {
    if (ownedDestination) {
      try {
        await rm(resolvedDestination, { recursive: true, force: true });
      } catch (cleanupError) {
        throw new Error(`${errorMessage(error)}; cleanup failed: ${errorMessage(cleanupError)}`, {
          cause: error,
        });
      }
    }
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new TypeError(`Destination already exists: ${resolvedDestination}`, { cause: error });
    }
    throw error;
  }
}
