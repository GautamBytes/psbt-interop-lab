#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const sourcePath = process.argv[2];
if (!sourcePath) {
  throw new TypeError("Usage: node scripts/import-bip371-vectors.mjs <bip-0371.mediawiki>");
}

const source = await readFile(resolve(sourcePath), "utf8");
const start = source.indexOf("==Test Vectors==");
const validMarker = source.indexOf("The following are valid PSBTs:", start);
const end = source.indexOf("==Rationale==", validMarker);
if (start < 0 || validMarker < 0 || end < 0) {
  throw new TypeError("BIP371 test-vector sections were not found");
}

const vectorPattern = /\* Case: ([^\n]+)[\s\S]*?\*\* Base64 String: <pre>([^<]+)<\/pre>/g;

function extract(section, prefix) {
  return [...section.matchAll(vectorPattern)].map((match, index) => ({
    id: `${prefix}-${String(index + 1).padStart(2, "0")}`,
    title: match[1].replaceAll(/<[^>]+>/g, "").trim(),
    base64: match[2].trim(),
  }));
}

const invalid = extract(source.slice(start, validMarker), "invalid");
const valid = extract(source.slice(validMarker, end), "valid");
if (valid.length !== 6 || invalid.length !== 11) {
  throw new TypeError(
    `Expected 6 valid and 11 invalid BIP371 vectors, found ${valid.length} and ${invalid.length}`,
  );
}

const sourceSha256 = createHash("sha256").update(source).digest("hex");
const corpusSha256 = createHash("sha256").update(JSON.stringify({ valid, invalid })).digest("hex");
const generated = `// Generated from Bitcoin BIP371 at commit b289d016b99c81527623c10e995e0318f744ebf3.
// Source: https://github.com/bitcoin/bips/blob/b289d016b99c81527623c10e995e0318f744ebf3/bip-0371.mediawiki

export interface Bip371Vector {
  readonly id: string;
  readonly title: string;
  readonly base64: string;
}

export const BIP371_SOURCE_SHA256 = "${sourceSha256}";
export const BIP371_CORPUS_SHA256 = "${corpusSha256}";

export const BIP371_VALID_VECTORS = ${JSON.stringify(valid, null, 2)} as const satisfies readonly Bip371Vector[];

export const BIP371_INVALID_VECTORS = ${JSON.stringify(invalid, null, 2)} as const satisfies readonly Bip371Vector[];
`;

await writeFile(resolve("src/psbt/bip371-vectors.ts"), generated, {
  encoding: "utf8",
  mode: 0o644,
});
