import { createHash } from "node:crypto";
import { CompactSizeError, readCompactSize } from "./compact-size.js";

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");

export class PsbtWireError extends Error {
  override readonly name = "PsbtWireError";
}

export interface PsbtWireLimits {
  maxPsbtBytes?: number;
  maxKeyBytes?: number;
  maxValueBytes?: number;
  maxMaps?: number;
  maxEntriesPerMap?: number;
}

export interface PsbtEntryFacts {
  keyType: number;
  keyDataBytes: number;
  valueBytes: number;
}

export interface PsbtMapFacts {
  kind: "global" | "input" | "output";
  index: number;
  entryCount: number;
  entries: PsbtEntryFacts[];
}

export interface PsbtWireFacts {
  format: "psbt";
  psbtVersion: number;
  byteLength: number;
  sha256: string;
  inputCount: number;
  outputCount: number;
  mapCount: number;
  maps: PsbtMapFacts[];
}

interface ResolvedLimits {
  maxPsbtBytes: number;
  maxKeyBytes: number;
  maxValueBytes: number;
  maxMaps: number;
  maxEntriesPerMap: number;
}

interface ParsedEntry {
  key: Buffer;
  value: Buffer;
  facts: PsbtEntryFacts;
}

interface ParsedMap {
  entries: ParsedEntry[];
  nextOffset: number;
}

function resolveLimits(limits: PsbtWireLimits): ResolvedLimits {
  const resolved: ResolvedLimits = {
    maxPsbtBytes: limits.maxPsbtBytes ?? 4 * 1024 * 1024,
    maxKeyBytes: limits.maxKeyBytes ?? 1024 * 1024,
    maxValueBytes: limits.maxValueBytes ?? 4 * 1024 * 1024,
    maxMaps: limits.maxMaps ?? 10_000,
    maxEntriesPerMap: limits.maxEntriesPerMap ?? 10_000,
  };
  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new PsbtWireError(`${name} must be a positive safe integer`);
    }
  }
  return resolved;
}

function decodeCanonicalBase64(encoded: string): Buffer {
  if (
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    throw new PsbtWireError("PSBT is not canonical base64");
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) {
    throw new PsbtWireError("PSBT is not canonical base64");
  }
  return decoded;
}

function compactSize(buffer: Buffer, offset: number, context: string) {
  try {
    return readCompactSize(buffer, offset);
  } catch (error) {
    if (error instanceof CompactSizeError) {
      throw new PsbtWireError(`${context}: ${error.message}`);
    }
    throw error;
  }
}

function assertAvailable(buffer: Buffer, offset: number, count: number, context: string): void {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(count) ||
    offset < 0 ||
    count < 0 ||
    offset + count > buffer.length
  ) {
    throw new PsbtWireError(`${context}: truncated data`);
  }
}

function parseMap(buffer: Buffer, startOffset: number, limits: ResolvedLimits): ParsedMap {
  let offset = startOffset;
  const entries: ParsedEntry[] = [];
  const keys = new Set<string>();

  while (true) {
    if (offset >= buffer.length) {
      throw new PsbtWireError("PSBT map is truncated before its terminator");
    }
    const keyLength = compactSize(buffer, offset, "PSBT key length");
    offset = keyLength.nextOffset;
    if (keyLength.value === 0) {
      return { entries, nextOffset: offset };
    }
    if (keyLength.value > limits.maxKeyBytes) {
      throw new PsbtWireError("PSBT key exceeds the configured key limit");
    }
    if (entries.length >= limits.maxEntriesPerMap) {
      throw new PsbtWireError("PSBT map exceeds the configured entry limit");
    }

    assertAvailable(buffer, offset, keyLength.value, "PSBT key");
    const key = buffer.subarray(offset, offset + keyLength.value);
    offset += keyLength.value;
    const keyHex = key.toString("hex");
    if (keys.has(keyHex)) {
      throw new PsbtWireError("PSBT map contains a duplicate complete key");
    }
    keys.add(keyHex);
    const keyType = compactSize(key, 0, "PSBT key type");

    const valueLength = compactSize(buffer, offset, "PSBT value length");
    offset = valueLength.nextOffset;
    if (valueLength.value > limits.maxValueBytes) {
      throw new PsbtWireError("PSBT value exceeds the configured value limit");
    }
    assertAvailable(buffer, offset, valueLength.value, "PSBT value");
    const value = buffer.subarray(offset, offset + valueLength.value);
    offset += valueLength.value;

    entries.push({
      key,
      value,
      facts: {
        keyType: keyType.value,
        keyDataBytes: key.byteLength - keyType.nextOffset,
        valueBytes: value.byteLength,
      },
    });
  }
}

function globalValue(entries: ParsedEntry[], keyType: number): Buffer | undefined {
  return entries.find((entry) => entry.key.byteLength === 1 && entry.key[0] === keyType)?.value;
}

function parseUnsignedTransactionCounts(transaction: Buffer): {
  inputCount: number;
  outputCount: number;
} {
  let offset = 0;
  assertAvailable(transaction, offset, 4, "unsigned transaction version");
  offset += 4;

  const inputCountValue = compactSize(transaction, offset, "unsigned transaction input count");
  const inputCount = inputCountValue.value;
  offset = inputCountValue.nextOffset;
  if (inputCount === 0) {
    throw new PsbtWireError("Unsigned transaction must use legacy serialization and have inputs");
  }

  for (let index = 0; index < inputCount; index += 1) {
    assertAvailable(transaction, offset, 36, "unsigned transaction input");
    offset += 36;
    const scriptLength = compactSize(transaction, offset, "unsigned transaction scriptSig length");
    offset = scriptLength.nextOffset;
    if (scriptLength.value !== 0) {
      throw new PsbtWireError("PSBT unsigned transaction scriptSig must be empty");
    }
    assertAvailable(transaction, offset, 4, "unsigned transaction sequence");
    offset += 4;
  }

  const outputCountValue = compactSize(transaction, offset, "unsigned transaction output count");
  const outputCount = outputCountValue.value;
  offset = outputCountValue.nextOffset;
  for (let index = 0; index < outputCount; index += 1) {
    assertAvailable(transaction, offset, 8, "unsigned transaction output value");
    offset += 8;
    const scriptLength = compactSize(transaction, offset, "unsigned transaction script length");
    offset = scriptLength.nextOffset;
    assertAvailable(transaction, offset, scriptLength.value, "unsigned transaction output script");
    offset += scriptLength.value;
  }

  assertAvailable(transaction, offset, 4, "unsigned transaction locktime");
  offset += 4;
  if (offset !== transaction.length) {
    throw new PsbtWireError("Unsigned transaction contains trailing data");
  }
  return { inputCount, outputCount };
}

function parseCountValue(value: Buffer, label: string): number {
  const decoded = compactSize(value, 0, label);
  if (decoded.nextOffset !== value.length) {
    throw new PsbtWireError(`${label} contains trailing data`);
  }
  return decoded.value;
}

function determineVersion(entries: ParsedEntry[]): number {
  const version = globalValue(entries, 0xfb);
  if (!version) {
    return 0;
  }
  if (version.byteLength !== 4) {
    throw new PsbtWireError("PSBT global version must contain four bytes");
  }
  return version.readUInt32LE(0);
}

function determineCounts(entries: ParsedEntry[], version: number) {
  if (version === 0) {
    const transaction = globalValue(entries, 0x00);
    if (!transaction) {
      throw new PsbtWireError("PSBTv0 is missing its unsigned transaction");
    }
    return parseUnsignedTransactionCounts(transaction);
  }
  if (version === 2) {
    const inputCount = globalValue(entries, 0x04);
    const outputCount = globalValue(entries, 0x05);
    if (!inputCount || !outputCount) {
      throw new PsbtWireError("PSBTv2 is missing its declared map counts");
    }
    return {
      inputCount: parseCountValue(inputCount, "PSBTv2 input count"),
      outputCount: parseCountValue(outputCount, "PSBTv2 output count"),
    };
  }
  throw new PsbtWireError(`Unsupported PSBT version ${version}`);
}

export function extractWireFacts(encoded: string, limits: PsbtWireLimits = {}): PsbtWireFacts {
  const resolved = resolveLimits(limits);
  const buffer = decodeCanonicalBase64(encoded);
  if (buffer.byteLength > resolved.maxPsbtBytes) {
    throw new PsbtWireError("PSBT exceeds the configured size limit");
  }
  if (
    buffer.byteLength < PSBT_MAGIC.byteLength ||
    !buffer.subarray(0, PSBT_MAGIC.byteLength).equals(PSBT_MAGIC)
  ) {
    throw new PsbtWireError("Invalid PSBT magic bytes");
  }

  let offset = PSBT_MAGIC.byteLength;
  const globalMap = parseMap(buffer, offset, resolved);
  offset = globalMap.nextOffset;
  const psbtVersion = determineVersion(globalMap.entries);
  const { inputCount, outputCount } = determineCounts(globalMap.entries, psbtVersion);
  const expectedMapCount = 1 + inputCount + outputCount;
  if (expectedMapCount > resolved.maxMaps) {
    throw new PsbtWireError("PSBT exceeds the configured map limit");
  }

  const maps: PsbtMapFacts[] = [
    {
      kind: "global",
      index: 0,
      entryCount: globalMap.entries.length,
      entries: globalMap.entries.map((entry) => entry.facts),
    },
  ];

  for (let index = 0; index < inputCount; index += 1) {
    const parsed = parseMap(buffer, offset, resolved);
    offset = parsed.nextOffset;
    maps.push({
      kind: "input",
      index,
      entryCount: parsed.entries.length,
      entries: parsed.entries.map((entry) => entry.facts),
    });
  }
  for (let index = 0; index < outputCount; index += 1) {
    const parsed = parseMap(buffer, offset, resolved);
    offset = parsed.nextOffset;
    maps.push({
      kind: "output",
      index,
      entryCount: parsed.entries.length,
      entries: parsed.entries.map((entry) => entry.facts),
    });
  }
  if (offset !== buffer.length) {
    throw new PsbtWireError("PSBT contains trailing bytes after its expected maps");
  }

  return {
    format: "psbt",
    psbtVersion,
    byteLength: buffer.byteLength,
    sha256: createHash("sha256").update(buffer).digest("hex"),
    inputCount,
    outputCount,
    mapCount: expectedMapCount,
    maps,
  };
}
