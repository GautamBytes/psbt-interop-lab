import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Ajv } from "ajv";
import type { AdapterProcessOptions } from "../protocol/adapter-process.js";
import manifestSchema from "./adapter-manifest.schema.json" with { type: "json" };

export const ADAPTER_MANIFEST_SCHEMA = "psbt-lab.adapters/0.1" as const;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

interface RawExpectedAdapter {
  name: string;
  version: string;
  sourceRevision: string;
  artifactDigest?: string;
}

interface RawAdapterEntry {
  id: string;
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  expected: RawExpectedAdapter;
}

interface RawAdapterManifest {
  schema: typeof ADAPTER_MANIFEST_SCHEMA;
  adapters: RawAdapterEntry[];
}

export interface ExpectedExternalAdapter {
  readonly name: string;
  readonly version: string;
  readonly sourceRevision: string;
  readonly artifactDigest?: string;
}

export interface ExternalAdapterDefinition {
  readonly id: string;
  readonly process: AdapterProcessOptions;
  readonly timeoutMs: number;
  readonly expected: ExpectedExternalAdapter;
}

export interface AdapterManifest {
  readonly schema: typeof ADAPTER_MANIFEST_SCHEMA;
  readonly adapters: readonly ExternalAdapterDefinition[];
}

const ajv = new Ajv({ allErrors: true, strict: true });
const validateManifest = ajv.compile<RawAdapterManifest>(manifestSchema);

function manifestError(detail: string): TypeError {
  return new TypeError(`Invalid adapter manifest: ${detail}`);
}

export function parseAdapterManifest(value: unknown, baseDirectory: string): AdapterManifest {
  if (!validateManifest(value)) {
    const details = (validateManifest.errors ?? [])
      .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
      .join("; ");
    throw manifestError(details);
  }
  const ids = new Set<string>();
  const adapters = value.adapters.map((entry) => {
    if (ids.has(entry.id)) throw manifestError(`duplicate adapter id ${entry.id}`);
    ids.add(entry.id);
    return {
      id: entry.id,
      process: {
        command: entry.command,
        args: [...(entry.args ?? [])],
        cwd: resolve(baseDirectory, entry.cwd ?? "."),
        ...(entry.env === undefined ? {} : { env: { ...entry.env } }),
      },
      timeoutMs: entry.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      expected: {
        name: entry.expected.name,
        version: entry.expected.version,
        sourceRevision: entry.expected.sourceRevision,
        ...(entry.expected.artifactDigest === undefined
          ? {}
          : { artifactDigest: entry.expected.artifactDigest }),
      },
    } satisfies ExternalAdapterDefinition;
  });
  return { schema: ADAPTER_MANIFEST_SCHEMA, adapters };
}

export async function loadAdapterManifest(path: string): Promise<AdapterManifest> {
  const absolutePath = resolve(path);
  const handle = await open(absolutePath, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_MANIFEST_BYTES) {
      throw manifestError("file must be a regular file no larger than 1 MiB");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_MANIFEST_BYTES) {
      throw manifestError("file grew beyond the 1 MiB limit while reading");
    }
    let value: unknown;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw manifestError("file is not valid JSON");
    }
    return parseAdapterManifest(value, dirname(absolutePath));
  } finally {
    await handle.close();
  }
}
