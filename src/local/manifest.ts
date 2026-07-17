import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";

export const LOCAL_RUNTIME_MANIFEST_SCHEMA = "psbt-lab.local-runtime/0.1" as const;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_SHA256 = /^sha256:[0-9a-f]{64}$/;
const SAFE_PATH_SEGMENT = /^[A-Za-z0-9._-]+$/;

export interface LocalAdapterIdentity {
  readonly name: string;
  readonly version: string;
  readonly sourceRevision: string;
  readonly artifactDigest: string;
}

export interface LocalAdapterLaunch {
  readonly kind: "node" | "executable";
  readonly path: string;
  readonly sha256: string;
}

export interface AvailableLocalAdapterDefinition {
  readonly id: string;
  readonly availability: "available";
  readonly launch: LocalAdapterLaunch;
  readonly timeoutMs: number;
  readonly expected: LocalAdapterIdentity;
}

export interface UnsupportedLocalAdapterDefinition {
  readonly id: string;
  readonly availability: "unsupported";
  readonly reason: string;
}

export type LocalAdapterDefinition =
  | AvailableLocalAdapterDefinition
  | UnsupportedLocalAdapterDefinition;

export interface LocalRuntimeManifest {
  readonly schema: typeof LOCAL_RUNTIME_MANIFEST_SCHEMA;
  readonly adapters: readonly LocalAdapterDefinition[];
}

function manifestError(detail: string): TypeError {
  return new TypeError(`Invalid local runtime manifest: ${detail}`);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw manifestError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw manifestError(`${label} has unknown ${unknown.join(", ")}`);
  }
}

function boundedString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw manifestError(`${label} must be a non-empty string no longer than ${maxLength}`);
  }
  return value;
}

function safeId(value: unknown, label: string): string {
  const id = boundedString(value, label, 64);
  if (!SAFE_ID.test(id)) throw manifestError(`${label} is not a safe identifier`);
  return id;
}

function safeDigest(value: unknown, label: string): string {
  const digest = boundedString(value, label, 71);
  if (!SAFE_SHA256.test(digest)) throw manifestError(`${label} must be a sha256 digest`);
  return digest;
}

function safeRelativePath(value: unknown): string {
  const path = boundedString(value, "launch.path", 4096);
  const segments = path.split("/");
  if (
    isAbsolute(path) ||
    path.includes("\\") ||
    segments.some(
      (segment) =>
        segment.length === 0 ||
        segment === "." ||
        segment === ".." ||
        !SAFE_PATH_SEGMENT.test(segment),
    )
  ) {
    throw manifestError("launch.path must be a safe package-relative path");
  }
  return path;
}

function timeout(value: unknown): number {
  const resolved = value ?? 10_000;
  if (
    !Number.isSafeInteger(resolved) ||
    (resolved as number) < 100 ||
    (resolved as number) > 120_000
  ) {
    throw manifestError("timeoutMs must be an integer from 100 through 120000");
  }
  return resolved as number;
}

function parseIdentity(value: unknown): LocalAdapterIdentity {
  const identity = record(value, "expected");
  exactKeys(identity, ["name", "version", "sourceRevision", "artifactDigest"], "expected");
  return {
    name: boundedString(identity["name"], "expected.name", 128),
    version: boundedString(identity["version"], "expected.version", 128),
    sourceRevision: boundedString(identity["sourceRevision"], "expected.sourceRevision", 256),
    artifactDigest: safeDigest(identity["artifactDigest"], "expected.artifactDigest"),
  };
}

function parseLaunch(value: unknown): LocalAdapterLaunch {
  const launch = record(value, "launch");
  exactKeys(launch, ["kind", "path", "sha256"], "launch");
  if (launch["kind"] !== "node" && launch["kind"] !== "executable") {
    throw manifestError("launch.kind must be node or executable");
  }
  return {
    kind: launch["kind"],
    path: safeRelativePath(launch["path"]),
    sha256: safeDigest(launch["sha256"], "launch.sha256"),
  };
}

function parseAdapter(value: unknown): LocalAdapterDefinition {
  const adapter = record(value, "adapter");
  if (adapter["availability"] === "unsupported") {
    exactKeys(adapter, ["id", "availability", "reason"], "unsupported adapter");
    return {
      id: safeId(adapter["id"], "adapter.id"),
      availability: "unsupported",
      reason: boundedString(adapter["reason"], "adapter.reason", 512),
    };
  }
  if (adapter["availability"] !== "available") {
    throw manifestError("adapter.availability must be available or unsupported");
  }
  exactKeys(
    adapter,
    ["id", "availability", "launch", "timeoutMs", "expected"],
    "available adapter",
  );
  const launch = parseLaunch(adapter["launch"]);
  const expected = parseIdentity(adapter["expected"]);
  if (launch.sha256 !== expected.artifactDigest) {
    throw manifestError("launch.sha256 must match expected.artifactDigest");
  }
  return {
    id: safeId(adapter["id"], "adapter.id"),
    availability: "available",
    launch,
    timeoutMs: timeout(adapter["timeoutMs"]),
    expected,
  };
}

export function parseLocalRuntimeManifest(value: unknown): LocalRuntimeManifest {
  const manifest = record(value, "manifest");
  exactKeys(manifest, ["schema", "adapters"], "manifest");
  if (manifest["schema"] !== LOCAL_RUNTIME_MANIFEST_SCHEMA) {
    throw manifestError(`schema must be ${LOCAL_RUNTIME_MANIFEST_SCHEMA}`);
  }
  if (
    !Array.isArray(manifest["adapters"]) ||
    manifest["adapters"].length === 0 ||
    manifest["adapters"].length > 32
  ) {
    throw manifestError("adapters must contain between 1 and 32 entries");
  }
  const adapters = manifest["adapters"].map(parseAdapter);
  const ids = new Set<string>();
  for (const adapter of adapters) {
    if (ids.has(adapter.id)) throw manifestError(`duplicate adapter id ${adapter.id}`);
    ids.add(adapter.id);
  }
  return { schema: LOCAL_RUNTIME_MANIFEST_SCHEMA, adapters };
}

export async function loadLocalRuntimeManifest(path: string): Promise<LocalRuntimeManifest> {
  const handle = await open(path, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_MANIFEST_BYTES) {
      throw manifestError("file must be a regular file no larger than 1 MiB");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_MANIFEST_BYTES) {
      throw manifestError("file grew beyond the 1 MiB limit while reading");
    }
    try {
      return parseLocalRuntimeManifest(JSON.parse(bytes.toString("utf8")));
    } catch (error) {
      if (
        error instanceof TypeError &&
        error.message.startsWith("Invalid local runtime manifest:")
      ) {
        throw error;
      }
      throw manifestError("file is not valid JSON");
    }
  } finally {
    await handle.close();
  }
}
