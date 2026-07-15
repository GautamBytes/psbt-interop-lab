import { createHash } from "node:crypto";
import { CompactSizeError, readCompactSize } from "./compact-size.js";

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");

export class PsbtDocumentError extends Error {
  override readonly name = "PsbtDocumentError";
}

export interface PsbtDocumentLimits {
  maxPsbtBytes?: number;
  maxKeyBytes?: number;
  maxValueBytes?: number;
  maxMaps?: number;
  maxEntriesPerMap?: number;
}

export type PsbtMapLocation =
  | { readonly kind: "global" }
  | { readonly kind: "input" | "output"; readonly index: number };

export interface PsbtDocumentEntry {
  readonly keyType: number;
  readonly keyData: Buffer;
  readonly completeKey: Buffer;
  readonly value: Buffer;
  readonly keyBytes: number;
  readonly valueBytes: number;
  readonly completeKeySha256: string;
  readonly valueSha256: string;
}

export interface PsbtDocumentMap {
  readonly location: PsbtMapLocation;
  readonly entries: readonly PsbtDocumentEntry[];
}

interface ResolvedLimits {
  maxPsbtBytes: number;
  maxKeyBytes: number;
  maxValueBytes: number;
  maxMaps: number;
  maxEntriesPerMap: number;
}

interface InternalEntry {
  keyType: number;
  keyData: Buffer;
  completeKey: Buffer;
  value: Buffer;
  completeKeySha256: string;
  valueSha256: string;
}

interface InternalMap {
  location: PsbtMapLocation;
  entries: InternalEntry[];
}

interface ParsedMap {
  entries: InternalEntry[];
  nextOffset: number;
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function resolveLimits(limits: PsbtDocumentLimits): ResolvedLimits {
  const resolved: ResolvedLimits = {
    maxPsbtBytes: limits.maxPsbtBytes ?? 4 * 1024 * 1024,
    maxKeyBytes: limits.maxKeyBytes ?? 1024 * 1024,
    maxValueBytes: limits.maxValueBytes ?? 4 * 1024 * 1024,
    maxMaps: limits.maxMaps ?? 10_000,
    maxEntriesPerMap: limits.maxEntriesPerMap ?? 10_000,
  };
  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new PsbtDocumentError(`${name} must be a positive safe integer`);
    }
  }
  return resolved;
}

function decodeCanonicalBase64(encoded: string, maxDecodedBytes: number): Buffer {
  const maxEncodedLength = 4 * Math.ceil(maxDecodedBytes / 3);
  if (encoded.length > maxEncodedLength) {
    throw new PsbtDocumentError("PSBT exceeds the configured size limit");
  }
  if (
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    throw new PsbtDocumentError("PSBT is not canonical base64");
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) {
    throw new PsbtDocumentError("PSBT is not canonical base64");
  }
  return decoded;
}

function compactSize(buffer: Buffer, offset: number, context: string) {
  try {
    return readCompactSize(buffer, offset);
  } catch (error) {
    if (error instanceof CompactSizeError) {
      throw new PsbtDocumentError(`${context}: ${error.message}`);
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
    throw new PsbtDocumentError(`${context}: truncated data`);
  }
}

function parseMap(buffer: Buffer, startOffset: number, limits: ResolvedLimits): ParsedMap {
  let offset = startOffset;
  const entries: InternalEntry[] = [];
  const keys = new Set<string>();

  while (true) {
    if (offset >= buffer.length) {
      throw new PsbtDocumentError("PSBT map is truncated before its terminator");
    }
    const keyLength = compactSize(buffer, offset, "PSBT key length");
    offset = keyLength.nextOffset;
    if (keyLength.value === 0) {
      return { entries, nextOffset: offset };
    }
    if (keyLength.value > limits.maxKeyBytes) {
      throw new PsbtDocumentError("PSBT key exceeds the configured key limit");
    }
    if (entries.length >= limits.maxEntriesPerMap) {
      throw new PsbtDocumentError("PSBT map exceeds the configured entry limit");
    }

    assertAvailable(buffer, offset, keyLength.value, "PSBT key");
    const completeKey = Buffer.from(buffer.subarray(offset, offset + keyLength.value));
    offset += keyLength.value;
    const keyHex = completeKey.toString("hex");
    if (keys.has(keyHex)) {
      throw new PsbtDocumentError("PSBT map contains a duplicate complete key");
    }
    keys.add(keyHex);
    const keyType = compactSize(completeKey, 0, "PSBT key type");

    const valueLength = compactSize(buffer, offset, "PSBT value length");
    offset = valueLength.nextOffset;
    if (valueLength.value > limits.maxValueBytes) {
      throw new PsbtDocumentError("PSBT value exceeds the configured value limit");
    }
    assertAvailable(buffer, offset, valueLength.value, "PSBT value");
    const value = Buffer.from(buffer.subarray(offset, offset + valueLength.value));
    offset += valueLength.value;

    entries.push({
      keyType: keyType.value,
      keyData: Buffer.from(completeKey.subarray(keyType.nextOffset)),
      completeKey,
      value,
      completeKeySha256: sha256(completeKey),
      valueSha256: sha256(value),
    });
  }
}

function globalValue(entries: InternalEntry[], keyType: number): Buffer | undefined {
  return entries.find(
    (entry) => entry.completeKey.byteLength === 1 && entry.completeKey[0] === keyType,
  )?.value;
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
    throw new PsbtDocumentError(
      "Unsigned transaction must use legacy serialization and have inputs",
    );
  }

  for (let index = 0; index < inputCount; index += 1) {
    assertAvailable(transaction, offset, 36, "unsigned transaction input");
    offset += 36;
    const scriptLength = compactSize(transaction, offset, "unsigned transaction scriptSig length");
    offset = scriptLength.nextOffset;
    if (scriptLength.value !== 0) {
      throw new PsbtDocumentError("PSBT unsigned transaction scriptSig must be empty");
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
    throw new PsbtDocumentError("Unsigned transaction contains trailing data");
  }
  return { inputCount, outputCount };
}

function parseCountValue(value: Buffer, label: string): number {
  const decoded = compactSize(value, 0, label);
  if (decoded.nextOffset !== value.length) {
    throw new PsbtDocumentError(`${label} contains trailing data`);
  }
  return decoded.value;
}

function determineVersion(entries: InternalEntry[]): number {
  const version = globalValue(entries, 0xfb);
  if (!version) {
    return 0;
  }
  if (version.byteLength !== 4) {
    throw new PsbtDocumentError("PSBT global version must contain four bytes");
  }
  return version.readUInt32LE(0);
}

function determineCounts(entries: InternalEntry[], version: number) {
  if (version === 0) {
    const transaction = globalValue(entries, 0x00);
    if (!transaction) {
      throw new PsbtDocumentError("PSBTv0 is missing its unsigned transaction");
    }
    return parseUnsignedTransactionCounts(transaction);
  }
  if (version === 2) {
    const inputCount = globalValue(entries, 0x04);
    const outputCount = globalValue(entries, 0x05);
    if (!inputCount || !outputCount) {
      throw new PsbtDocumentError("PSBTv2 is missing its declared map counts");
    }
    return {
      inputCount: parseCountValue(inputCount, "PSBTv2 input count"),
      outputCount: parseCountValue(outputCount, "PSBTv2 output count"),
    };
  }
  throw new PsbtDocumentError(`Unsupported PSBT version ${version}`);
}

function cloneLocation(location: PsbtMapLocation): PsbtMapLocation {
  return location.kind === "global" ? { kind: "global" } : { ...location };
}

function cloneEntry(entry: InternalEntry): PsbtDocumentEntry {
  return {
    keyType: entry.keyType,
    keyData: Buffer.from(entry.keyData),
    completeKey: Buffer.from(entry.completeKey),
    value: Buffer.from(entry.value),
    keyBytes: entry.completeKey.byteLength,
    valueBytes: entry.value.byteLength,
    completeKeySha256: entry.completeKeySha256,
    valueSha256: entry.valueSha256,
  };
}

export class PsbtDocument {
  private constructor(
    private readonly raw: Buffer,
    private readonly parsedMaps: InternalMap[],
    readonly psbtVersion: number,
    readonly inputCount: number,
    readonly outputCount: number,
  ) {}

  static parse(encoded: string, limits: PsbtDocumentLimits = {}): PsbtDocument {
    const resolved = resolveLimits(limits);
    const buffer = decodeCanonicalBase64(encoded, resolved.maxPsbtBytes);
    if (buffer.byteLength > resolved.maxPsbtBytes) {
      throw new PsbtDocumentError("PSBT exceeds the configured size limit");
    }
    if (
      buffer.byteLength < PSBT_MAGIC.byteLength ||
      !buffer.subarray(0, PSBT_MAGIC.byteLength).equals(PSBT_MAGIC)
    ) {
      throw new PsbtDocumentError("Invalid PSBT magic bytes");
    }

    let offset = PSBT_MAGIC.byteLength;
    const globalMap = parseMap(buffer, offset, resolved);
    offset = globalMap.nextOffset;
    const psbtVersion = determineVersion(globalMap.entries);
    const { inputCount, outputCount } = determineCounts(globalMap.entries, psbtVersion);
    const expectedMapCount = 1 + inputCount + outputCount;
    if (!Number.isSafeInteger(expectedMapCount) || expectedMapCount > resolved.maxMaps) {
      throw new PsbtDocumentError("PSBT exceeds the configured map limit");
    }

    const maps: InternalMap[] = [{ location: { kind: "global" }, entries: globalMap.entries }];
    for (let index = 0; index < inputCount; index += 1) {
      const parsed = parseMap(buffer, offset, resolved);
      offset = parsed.nextOffset;
      maps.push({ location: { kind: "input", index }, entries: parsed.entries });
    }
    for (let index = 0; index < outputCount; index += 1) {
      const parsed = parseMap(buffer, offset, resolved);
      offset = parsed.nextOffset;
      maps.push({ location: { kind: "output", index }, entries: parsed.entries });
    }
    if (offset !== buffer.length) {
      throw new PsbtDocumentError("PSBT contains trailing bytes after its expected maps");
    }

    return new PsbtDocument(Buffer.from(buffer), maps, psbtVersion, inputCount, outputCount);
  }

  get byteLength(): number {
    return this.raw.byteLength;
  }

  get sha256(): string {
    return sha256(this.raw);
  }

  get mapCount(): number {
    return this.parsedMaps.length;
  }

  get bytes(): Buffer {
    return Buffer.from(this.raw);
  }

  get maps(): readonly PsbtDocumentMap[] {
    return this.parsedMaps.map((map) => ({
      location: cloneLocation(map.location),
      entries: map.entries.map(cloneEntry),
    }));
  }
}

export function parsePsbtDocument(encoded: string, limits: PsbtDocumentLimits = {}): PsbtDocument {
  return PsbtDocument.parse(encoded, limits);
}
