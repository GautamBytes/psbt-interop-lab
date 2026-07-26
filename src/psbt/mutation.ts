import {
  type PsbtDocument,
  type PsbtDocumentEntry,
  type PsbtMapLocation,
  parsePsbtDocument,
} from "./document.js";

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");
export const MAX_FUZZ_CASES = 512;

interface EntrySelector {
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly keyDataHex?: string;
}

export type PsbtMutationRecipe =
  | (EntrySelector & { readonly kind: "replace-value"; readonly valueHex: string })
  | (EntrySelector & { readonly kind: "set-entry"; readonly valueHex: string })
  | (EntrySelector & { readonly kind: "delete-entry" })
  | (EntrySelector & { readonly kind: "duplicate-entry" })
  | { readonly kind: "xor-byte"; readonly offset: number; readonly mask: number }
  | { readonly kind: "truncate"; readonly byteLength: number }
  | { readonly kind: "append-bytes"; readonly valueHex: string };

export interface GeneratedMutationCase {
  readonly index: number;
  readonly seed: number;
  readonly recipes: readonly PsbtMutationRecipe[];
  readonly mutatedPsbt: string;
}

interface MutableEntry {
  completeKey: Buffer;
  value: Buffer;
}

interface MutableMap {
  location: PsbtMapLocation;
  entries: MutableEntry[];
}

function encodeCompactSize(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("CompactSize value must be a non-negative safe integer");
  }
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = 0xfd;
    encoded.writeUInt16LE(value, 1);
    return encoded;
  }
  if (value <= 0xffff_ffff) {
    const encoded = Buffer.alloc(5);
    encoded[0] = 0xfe;
    encoded.writeUInt32LE(value, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(9);
  encoded[0] = 0xff;
  encoded.writeBigUInt64LE(BigInt(value), 1);
  return encoded;
}

function serializeEntry(entry: MutableEntry): Buffer {
  return Buffer.concat([
    encodeCompactSize(entry.completeKey.byteLength),
    entry.completeKey,
    encodeCompactSize(entry.value.byteLength),
    entry.value,
  ]);
}

function mutableMaps(document: PsbtDocument): MutableMap[] {
  return document.maps.map((map) => ({
    location: map.location.kind === "global" ? { kind: "global" } : { ...map.location },
    entries: map.entries.map((entry) => ({
      completeKey: Buffer.from(entry.completeKey),
      value: Buffer.from(entry.value),
    })),
  }));
}

function serializeMaps(maps: readonly MutableMap[]): Buffer {
  return Buffer.concat([
    PSBT_MAGIC,
    ...maps.flatMap((map) => [...map.entries.map(serializeEntry), Buffer.from([0x00])]),
  ]);
}

export function serializePsbtDocument(document: PsbtDocument): Buffer {
  return serializeMaps(mutableMaps(document));
}

function decodeHex(value: string, label: string): Buffer {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new TypeError(`${label} must be an even-length hexadecimal string`);
  }
  return Buffer.from(value, "hex");
}

function sameLocation(left: PsbtMapLocation, right: PsbtMapLocation): boolean {
  return (
    left.kind === right.kind &&
    (left.kind === "global" || (right.kind !== "global" && left.index === right.index))
  );
}

function selectedKey(recipe: EntrySelector): Buffer {
  if (!Number.isInteger(recipe.keyType) || recipe.keyType < 0 || recipe.keyType > 0xff) {
    throw new TypeError("PSBT key type must be an unsigned byte");
  }
  return Buffer.concat([
    Buffer.from([recipe.keyType]),
    decodeHex(recipe.keyDataHex ?? "", "PSBT key data"),
  ]);
}

function selectedMap(maps: MutableMap[], location: PsbtMapLocation): MutableMap {
  const map = maps.find((candidate) => sameLocation(candidate.location, location));
  if (!map) {
    throw new RangeError(
      location.kind === "global"
        ? "PSBT has no global map"
        : `PSBT has no ${location.kind} map at index ${location.index}`,
    );
  }
  return map;
}

function selectedEntryIndex(map: MutableMap, key: Buffer): number {
  const matches = map.entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => entry.completeKey.equals(key));
  if (matches.length !== 1) {
    throw new RangeError(
      `PSBT mutation selector matched ${matches.length} entries for key ${key.toString("hex")}`,
    );
  }
  return matches[0]?.index as number;
}

function applyMapRecipe(maps: MutableMap[], recipe: Extract<PsbtMutationRecipe, EntrySelector>) {
  const map = selectedMap(maps, recipe.location);
  const key = selectedKey(recipe);
  if (recipe.kind === "set-entry") {
    const value = decodeHex(recipe.valueHex, "PSBT entry value");
    const index = map.entries.findIndex((entry) => entry.completeKey.equals(key));
    if (index === -1) {
      map.entries.push({ completeKey: key, value });
    } else {
      map.entries[index] = { completeKey: key, value };
    }
    return;
  }

  const index = selectedEntryIndex(map, key);
  if (recipe.kind === "delete-entry") {
    map.entries.splice(index, 1);
    return;
  }
  if (recipe.kind === "duplicate-entry") {
    const entry = map.entries[index] as MutableEntry;
    map.entries.splice(index + 1, 0, {
      completeKey: Buffer.from(entry.completeKey),
      value: Buffer.from(entry.value),
    });
    return;
  }
  map.entries[index] = {
    completeKey: Buffer.from(key),
    value: decodeHex(recipe.valueHex, "PSBT entry value"),
  };
}

function isMapRecipe(
  recipe: PsbtMutationRecipe,
): recipe is Extract<PsbtMutationRecipe, EntrySelector> {
  return (
    recipe.kind === "replace-value" ||
    recipe.kind === "set-entry" ||
    recipe.kind === "delete-entry" ||
    recipe.kind === "duplicate-entry"
  );
}

function applyRawRecipe(bytes: Buffer, recipe: Exclude<PsbtMutationRecipe, EntrySelector>): Buffer {
  if (recipe.kind === "append-bytes") {
    return Buffer.concat([bytes, decodeHex(recipe.valueHex, "Appended bytes")]);
  }
  if (recipe.kind === "truncate") {
    if (
      !Number.isSafeInteger(recipe.byteLength) ||
      recipe.byteLength < PSBT_MAGIC.byteLength ||
      recipe.byteLength >= bytes.byteLength
    ) {
      throw new RangeError(
        "Truncated PSBT length must retain the magic and remove at least one byte",
      );
    }
    return Buffer.from(bytes.subarray(0, recipe.byteLength));
  }
  if (
    !Number.isSafeInteger(recipe.offset) ||
    recipe.offset < 0 ||
    recipe.offset >= bytes.byteLength
  ) {
    throw new RangeError("XOR offset is outside the PSBT");
  }
  if (!Number.isInteger(recipe.mask) || recipe.mask < 1 || recipe.mask > 0xff) {
    throw new RangeError("XOR mask must be between 1 and 255");
  }
  const mutated = Buffer.from(bytes);
  mutated[recipe.offset] = (mutated[recipe.offset] as number) ^ recipe.mask;
  return mutated;
}

export function applyPsbtMutations(
  encoded: string,
  recipes: readonly PsbtMutationRecipe[],
): string {
  const maps = mutableMaps(parsePsbtDocument(encoded));
  let bytes: Buffer | undefined;
  for (const recipe of recipes) {
    if (isMapRecipe(recipe)) {
      if (bytes) throw new TypeError("Map mutations must precede raw byte mutations");
      applyMapRecipe(maps, recipe);
      continue;
    }
    bytes = applyRawRecipe(bytes ?? serializeMaps(maps), recipe);
  }
  return (bytes ?? serializeMaps(maps)).toString("base64");
}

function createRandom(seed: number): () => number {
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffff_ffff) {
    throw new RangeError("Mutation seed must be an unsigned 32-bit integer");
  }
  let state = seed || 0x6d2b_79f5;
  return () => {
    state |= 0;
    state = (state + 0x6d2b_79f5) | 0;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value ^= value + Math.imul(value ^ (value >>> 7), 61 | value);
    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function randomIndex(random: () => number, length: number): number {
  return Math.min(length - 1, Math.floor(random() * length));
}

function selectorFromEntry(location: PsbtMapLocation, entry: PsbtDocumentEntry): EntrySelector {
  return {
    location,
    keyType: entry.keyType,
    ...(entry.keyData.byteLength > 0 ? { keyDataHex: entry.keyData.toString("hex") } : {}),
  };
}

export function generateBoundedMutations(
  encoded: string,
  seed: number,
  cases: number,
): readonly GeneratedMutationCase[] {
  if (!Number.isSafeInteger(cases) || cases < 1 || cases > MAX_FUZZ_CASES) {
    throw new RangeError(`Fuzz case count must be between 1 and ${MAX_FUZZ_CASES}`);
  }
  const document = parsePsbtDocument(encoded);
  const bytes = document.bytes;
  const entries = document.maps.flatMap((map) =>
    map.entries.map((entry) => ({ location: map.location, entry })),
  );
  const random = createRandom(seed);
  const generated: GeneratedMutationCase[] = [];

  for (let index = 0; index < cases; index += 1) {
    const operation = randomIndex(random, 6);
    let recipe: PsbtMutationRecipe;
    if (operation === 0) {
      recipe = {
        kind: "xor-byte",
        offset:
          PSBT_MAGIC.byteLength +
          randomIndex(random, Math.max(1, bytes.byteLength - PSBT_MAGIC.byteLength)),
        mask: 1 << randomIndex(random, 8),
      };
    } else if (operation === 1) {
      const removable = Math.min(8, bytes.byteLength - PSBT_MAGIC.byteLength);
      recipe = {
        kind: "truncate",
        byteLength: bytes.byteLength - 1 - randomIndex(random, removable),
      };
    } else if (operation === 2) {
      recipe = {
        kind: "append-bytes",
        valueHex: Math.floor(random() * 256)
          .toString(16)
          .padStart(2, "0"),
      };
    } else {
      const selected = entries[randomIndex(random, entries.length)] as {
        location: PsbtMapLocation;
        entry: PsbtDocumentEntry;
      };
      const selector = selectorFromEntry(selected.location, selected.entry);
      if (operation === 3) {
        recipe = { kind: "duplicate-entry", ...selector };
      } else if (operation === 4 && selected.entry.value.byteLength > 0) {
        const value = Buffer.from(selected.entry.value);
        const offset = randomIndex(random, value.byteLength);
        value[offset] = (value[offset] as number) ^ (1 << randomIndex(random, 8));
        recipe = { kind: "replace-value", ...selector, valueHex: value.toString("hex") };
      } else {
        recipe = { kind: "delete-entry", ...selector };
      }
    }
    const recipes = [recipe] as const;
    generated.push({
      index,
      seed,
      recipes,
      mutatedPsbt: applyPsbtMutations(encoded, recipes),
    });
  }
  return generated;
}
