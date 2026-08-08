#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const sourcePath = process.argv[2];
if (!sourcePath) {
  throw new TypeError("Usage: node scripts/import-bip375-vectors.mjs <bip375_test_vectors.json>");
}

const source = await readFile(resolve(sourcePath), "utf8");
const parsed = JSON.parse(source);
if (parsed.version !== "1.1" || !Array.isArray(parsed.valid) || !Array.isArray(parsed.invalid)) {
  throw new TypeError("Expected the BIP375 v1.1 test-vector document");
}
if (parsed.valid.length !== 19 || parsed.invalid.length !== 22) {
  throw new TypeError(
    `Expected 19 valid and 22 invalid BIP375 vectors, found ${parsed.valid.length} and ${parsed.invalid.length}`,
  );
}

function vector(item, index, prefix) {
  if (
    typeof item !== "object" ||
    item === null ||
    typeof item.description !== "string" ||
    typeof item.psbt !== "string" ||
    typeof item.supplementary !== "object" ||
    item.supplementary === null
  ) {
    throw new TypeError(`Malformed ${prefix} BIP375 vector ${index + 1}`);
  }
  const stage = item.description.split(":", 1)[0];
  return {
    id: `${prefix}-${String(index + 1).padStart(2, "0")}`,
    title: item.description,
    base64: item.psbt,
    supplementary: item.supplementary,
    ...(prefix === "invalid" ? { expectedStage: stage } : {}),
  };
}

const valid = parsed.valid.map((item, index) => vector(item, index, "valid"));
const invalid = parsed.invalid.map((item, index) => vector(item, index, "invalid"));
const stages = new Set(invalid.map(({ expectedStage }) => expectedStage));
const expectedStages = new Set([
  "psbt structure",
  "ecdh coverage",
  "input eligibility",
  "output scripts",
]);
if (
  stages.size !== expectedStages.size ||
  [...stages].some((stage) => !expectedStages.has(stage))
) {
  throw new TypeError(`Unexpected BIP375 validation stages: ${[...stages].join(", ")}`);
}

const sourceSha256 = createHash("sha256").update(source).digest("hex");
const corpusSha256 = createHash("sha256")
  .update(JSON.stringify({ version: parsed.version, valid, invalid }))
  .digest("hex");
const generated = `// Generated from Bitcoin BIP375 at commit b217897a628e3d5db369497d2697f76e5bab7f4d.
// Source: https://github.com/bitcoin/bips/blob/b217897a628e3d5db369497d2697f76e5bab7f4d/bip-0375/bip375_test_vectors.json

export type Bip375VectorStage =
  | "psbt structure"
  | "ecdh coverage"
  | "input eligibility"
  | "output scripts";

export interface Bip375Vector {
  readonly id: string;
  readonly title: string;
  readonly base64: string;
  readonly supplementary: Readonly<Record<string, unknown>>;
  readonly expectedStage?: Bip375VectorStage;
}

export const BIP375_VECTOR_VERSION = ${JSON.stringify(parsed.version)};
export const BIP375_SOURCE_SHA256 = "${sourceSha256}";
export const BIP375_CORPUS_SHA256 = "${corpusSha256}";

export const BIP375_VALID_VECTORS = ${JSON.stringify(valid, null, 2)} as const satisfies readonly Bip375Vector[];

export const BIP375_INVALID_VECTORS = ${JSON.stringify(invalid, null, 2)} as const satisfies readonly Bip375Vector[];
`;

const outputPath = resolve("src/psbt/bip375-vectors.ts");
await writeFile(outputPath, generated, {
  encoding: "utf8",
  mode: 0o644,
});
execFileSync(resolve("node_modules/.bin/biome"), ["format", "--write", outputPath], {
  stdio: "inherit",
});
