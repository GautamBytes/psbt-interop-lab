import { createHash, ECDH } from "node:crypto";
import { CompactSizeError, readCompactSize } from "./compact-size.js";

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");
const TAPROOT_EXPLICIT_SIGHASH_TYPES = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

export type PsbtDocumentErrorCode =
  | "INVALID_PSBT"
  | "INVALID_FIELD"
  | "MISSING_REQUIRED_FIELD"
  | "FORBIDDEN_FIELD";

interface PsbtDocumentErrorOptions {
  code?: PsbtDocumentErrorCode;
  location?: PsbtMapLocation;
  keyType?: number;
}

export class PsbtDocumentError extends Error {
  override readonly name = "PsbtDocumentError";
  readonly code: PsbtDocumentErrorCode;
  readonly location: PsbtMapLocation | undefined;
  readonly keyType: number | undefined;

  constructor(message: string, options: PsbtDocumentErrorOptions = {}) {
    super(message);
    this.code = options.code ?? "INVALID_PSBT";
    this.location = options.location;
    this.keyType = options.keyType;
  }
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

function fieldError(
  code: PsbtDocumentErrorCode,
  location: PsbtMapLocation,
  keyType: number,
  message: string,
): never {
  throw new PsbtDocumentError(message, { code, location: cloneLocation(location), keyType });
}

function invalidField(
  location: PsbtMapLocation,
  entry: InternalEntry,
  label: string,
  reason: string,
): never {
  return fieldError("INVALID_FIELD", location, entry.keyType, `${label} ${reason}`);
}

function forbiddenField(
  location: PsbtMapLocation,
  entry: InternalEntry,
  label: string,
  version: number,
): never {
  return fieldError(
    "FORBIDDEN_FIELD",
    location,
    entry.keyType,
    `${label} is forbidden in PSBTv${version}`,
  );
}

function requireField(
  entries: InternalEntry[],
  location: PsbtMapLocation,
  keyType: number,
  label: string,
): void {
  if (!entries.some((entry) => entry.keyType === keyType)) {
    fieldError("MISSING_REQUIRED_FIELD", location, keyType, `${label} is required`);
  }
}

function assertNoKeyData(entry: InternalEntry, location: PsbtMapLocation, label: string): void {
  if (entry.keyData.byteLength !== 0) {
    invalidField(location, entry, label, "must not contain key data");
  }
}

function assertKeyDataLength(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
  length: number,
): void {
  if (entry.keyData.byteLength !== length) {
    invalidField(location, entry, label, `key data must contain ${length} bytes`);
  }
}

function assertValueLength(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
  length: number,
): void {
  if (entry.value.byteLength !== length) {
    invalidField(location, entry, label, `value must contain ${length} bytes`);
  }
}

function assertValueLengths(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
  lengths: readonly number[],
): void {
  if (!lengths.includes(entry.value.byteLength)) {
    invalidField(location, entry, label, `value has an invalid byte length`);
  }
}

function assertNonEmptyValue(entry: InternalEntry, location: PsbtMapLocation, label: string): void {
  if (entry.value.byteLength === 0) {
    invalidField(location, entry, label, "value must not be empty");
  }
}

function assertSerializedPubkey(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  const prefix = entry.keyData[0];
  const compressed = entry.keyData.byteLength === 33 && (prefix === 0x02 || prefix === 0x03);
  const uncompressed = entry.keyData.byteLength === 65 && prefix === 0x04;
  if (!compressed && !uncompressed) {
    invalidField(location, entry, label, "key data must contain a serialized public key");
  }
}

function isValidSecp256k1PublicKey(publicKey: Buffer): boolean {
  try {
    ECDH.convertKey(publicKey, "secp256k1", undefined, undefined, "compressed");
    return true;
  } catch {
    return false;
  }
}

function assertSerializedExtendedPublicKey(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  assertKeyDataLength(entry, location, label, 78);
  const publicKey = entry.keyData.subarray(45);
  if (publicKey.every((byte) => byte === 0)) {
    invalidField(location, entry, label, "public key payload must not be all zero");
  }

  const marker = publicKey[0];
  if (marker !== 0x02 && marker !== 0x03) {
    invalidField(location, entry, label, "key data must contain a compressed public key");
  }
  if (!isValidSecp256k1PublicKey(publicKey)) {
    invalidField(location, entry, label, "key data contains an invalid secp256k1 public key");
  }

  const depth = entry.keyData[4] as number;
  if (depth === 0 && entry.keyData.subarray(5, 13).some((byte) => byte !== 0)) {
    invalidField(location, entry, label, "master key metadata must be zero");
  }
}

function assertXOnlyPublicKey(
  publicKey: Buffer,
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  if (
    publicKey.byteLength !== 32 ||
    !isValidSecp256k1PublicKey(Buffer.concat([Buffer.from([0x02]), publicKey]))
  ) {
    invalidField(location, entry, label, "contains an invalid x-only secp256k1 public key");
  }
}

function assertTaprootSignature(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  assertValueLengths(entry, location, label, [64, 65]);
  if (
    entry.value.byteLength === 65 &&
    !TAPROOT_EXPLICIT_SIGHASH_TYPES.has(entry.value[64] as number)
  ) {
    invalidField(location, entry, label, "value contains an invalid explicit sighash type");
  }
}

function assertDerivationValue(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  if (entry.value.byteLength < 4 || (entry.value.byteLength - 4) % 4 !== 0) {
    invalidField(location, entry, label, "value must contain a fingerprint and derivation path");
  }
}

function readFieldCompactSize(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
  offset: number,
) {
  try {
    return readCompactSize(entry.value, offset);
  } catch (error) {
    if (error instanceof CompactSizeError) {
      invalidField(location, entry, label, "contains an invalid CompactSize value");
    }
    throw error;
  }
}

function assertCompactSizeValue(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  const decoded = readFieldCompactSize(entry, location, label, 0);
  if (decoded.nextOffset !== entry.value.byteLength) {
    invalidField(location, entry, label, "value contains trailing data");
  }
}

function assertTxOut(entry: InternalEntry, location: PsbtMapLocation, label: string): void {
  if (entry.value.byteLength < 9) {
    invalidField(location, entry, label, "value is not a serialized transaction output");
  }
  const scriptLength = readFieldCompactSize(entry, location, label, 8);
  if (scriptLength.nextOffset + scriptLength.value !== entry.value.byteLength) {
    invalidField(location, entry, label, "value is not a serialized transaction output");
  }
}

function assertScriptWitness(entry: InternalEntry, location: PsbtMapLocation, label: string): void {
  const itemCount = readFieldCompactSize(entry, location, label, 0);
  let offset = itemCount.nextOffset;
  for (let index = 0; index < itemCount.value; index += 1) {
    const itemLength = readFieldCompactSize(entry, location, label, offset);
    offset = itemLength.nextOffset + itemLength.value;
    if (offset > entry.value.byteLength) {
      invalidField(location, entry, label, "value is not a serialized script witness");
    }
  }
  if (offset !== entry.value.byteLength) {
    invalidField(location, entry, label, "value is not a serialized script witness");
  }
}

function assertProprietaryKey(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  try {
    const identifier = readCompactSize(entry.keyData, 0);
    const subtypeOffset = identifier.nextOffset + identifier.value;
    if (subtypeOffset > entry.keyData.byteLength) {
      invalidField(location, entry, label, "key data has a truncated identifier");
    }
    readCompactSize(entry.keyData, subtypeOffset);
  } catch (error) {
    if (error instanceof CompactSizeError) {
      invalidField(location, entry, label, "key data is not a proprietary key");
    }
    throw error;
  }
}

function assertTaprootDerivation(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  assertKeyDataLength(entry, location, label, 32);
  const hashCount = readFieldCompactSize(entry, location, label, 0);
  const hashesEnd = hashCount.nextOffset + hashCount.value * 32;
  if (
    !Number.isSafeInteger(hashesEnd) ||
    hashesEnd + 4 > entry.value.byteLength ||
    (entry.value.byteLength - hashesEnd - 4) % 4 !== 0
  ) {
    invalidField(location, entry, label, "value has an invalid taproot derivation path");
  }
}

function assertTaprootControlBlock(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
): void {
  const length = entry.keyData.byteLength;
  if (length < 33 || length > 33 + 32 * 128 || (length - 33) % 32 !== 0) {
    invalidField(location, entry, label, "key data is not a taproot control block");
  }
  assertXOnlyPublicKey(entry.keyData.subarray(1, 33), entry, location, label);
  assertNonEmptyValue(entry, location, label);
}

function assertTaprootLeafVersion(
  entry: InternalEntry,
  location: PsbtMapLocation,
  label: string,
  leafVersion: number,
): void {
  if ((leafVersion & 1) !== 0 || leafVersion === 0x50) {
    invalidField(location, entry, label, "value contains an invalid taproot leaf version");
  }
}

function assertTaprootTree(entry: InternalEntry, location: PsbtMapLocation, label: string): void {
  assertNoKeyData(entry, location, label);
  if (entry.value.byteLength === 0) {
    invalidField(location, entry, label, "value must contain at least one leaf");
  }
  let offset = 0;
  const subtreeDepths: number[] = [];
  while (offset < entry.value.byteLength) {
    if (offset + 2 > entry.value.byteLength) {
      invalidField(location, entry, label, "value has a truncated taproot leaf");
    }
    const depth = entry.value[offset] as number;
    const leafVersion = entry.value[offset + 1] as number;
    if (depth > 128) {
      invalidField(location, entry, label, "value contains a taproot leaf depth greater than 128");
    }
    assertTaprootLeafVersion(entry, location, label, leafVersion);
    const scriptLength = readFieldCompactSize(entry, location, label, offset + 2);
    offset = scriptLength.nextOffset + scriptLength.value;
    if (offset > entry.value.byteLength) {
      invalidField(location, entry, label, "value has a truncated taproot leaf");
    }

    subtreeDepths.push(depth);
    while (
      subtreeDepths.length >= 2 &&
      subtreeDepths[subtreeDepths.length - 1] === subtreeDepths[subtreeDepths.length - 2]
    ) {
      const childDepth = subtreeDepths.pop() as number;
      subtreeDepths.pop();
      if (childDepth === 0) {
        invalidField(location, entry, label, "value does not encode one binary taproot tree");
      }
      subtreeDepths.push(childDepth - 1);
    }
  }
  if (subtreeDepths.length !== 1 || subtreeDepths[0] !== 0) {
    invalidField(location, entry, label, "value does not encode one binary taproot tree");
  }
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

function validateVersionEntry(entries: InternalEntry[]): void {
  const location: PsbtMapLocation = { kind: "global" };
  for (const entry of entries.filter((candidate) => candidate.keyType === 0xfb)) {
    assertNoKeyData(entry, location, "PSBT_GLOBAL_VERSION");
    assertValueLength(entry, location, "PSBT_GLOBAL_VERSION", 4);
  }
}

function validateGlobalMap(entries: InternalEntry[], version: number): void {
  const location: PsbtMapLocation = { kind: "global" };
  for (const entry of entries) {
    if (version === 0 && entry.keyType >= 0x02 && entry.keyType <= 0x06) {
      forbiddenField(location, entry, "BIP370 global field", version);
    }
    if (version === 2 && entry.keyType === 0x00) {
      forbiddenField(location, entry, "PSBT_GLOBAL_UNSIGNED_TX", version);
    }

    switch (entry.keyType) {
      case 0x00:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_UNSIGNED_TX");
        break;
      case 0x01: {
        assertSerializedExtendedPublicKey(entry, location, "PSBT_GLOBAL_XPUB");
        assertDerivationValue(entry, location, "PSBT_GLOBAL_XPUB");
        const depth = entry.keyData[4] as number;
        if ((entry.value.byteLength - 4) / 4 !== depth) {
          invalidField(location, entry, "PSBT_GLOBAL_XPUB", "derivation depth does not match");
        }
        break;
      }
      case 0x02:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_TX_VERSION");
        assertValueLength(entry, location, "PSBT_GLOBAL_TX_VERSION", 4);
        break;
      case 0x03:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_FALLBACK_LOCKTIME");
        assertValueLength(entry, location, "PSBT_GLOBAL_FALLBACK_LOCKTIME", 4);
        break;
      case 0x04:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_INPUT_COUNT");
        assertCompactSizeValue(entry, location, "PSBT_GLOBAL_INPUT_COUNT");
        break;
      case 0x05:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_OUTPUT_COUNT");
        assertCompactSizeValue(entry, location, "PSBT_GLOBAL_OUTPUT_COUNT");
        break;
      case 0x06:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_TX_MODIFIABLE");
        assertValueLength(entry, location, "PSBT_GLOBAL_TX_MODIFIABLE", 1);
        break;
      case 0xfb:
        assertNoKeyData(entry, location, "PSBT_GLOBAL_VERSION");
        assertValueLength(entry, location, "PSBT_GLOBAL_VERSION", 4);
        break;
      case 0xfc:
        assertProprietaryKey(entry, location, "PSBT_GLOBAL_PROPRIETARY");
        break;
    }
  }

  if (version === 0) {
    requireField(entries, location, 0x00, "PSBT_GLOBAL_UNSIGNED_TX");
  } else {
    requireField(entries, location, 0xfb, "PSBT_GLOBAL_VERSION");
    requireField(entries, location, 0x02, "PSBT_GLOBAL_TX_VERSION");
    requireField(entries, location, 0x04, "PSBT_GLOBAL_INPUT_COUNT");
    requireField(entries, location, 0x05, "PSBT_GLOBAL_OUTPUT_COUNT");
  }
}

function validateInputMap(map: InternalMap, version: number): void {
  const { location, entries } = map;
  for (const entry of entries) {
    if (version === 0 && entry.keyType >= 0x0e && entry.keyType <= 0x12) {
      forbiddenField(location, entry, "BIP370 input field", version);
    }

    switch (entry.keyType) {
      case 0x00:
        assertNoKeyData(entry, location, "PSBT_IN_NON_WITNESS_UTXO");
        assertNonEmptyValue(entry, location, "PSBT_IN_NON_WITNESS_UTXO");
        break;
      case 0x01:
        assertNoKeyData(entry, location, "PSBT_IN_WITNESS_UTXO");
        assertTxOut(entry, location, "PSBT_IN_WITNESS_UTXO");
        break;
      case 0x02:
        assertSerializedPubkey(entry, location, "PSBT_IN_PARTIAL_SIG");
        assertNonEmptyValue(entry, location, "PSBT_IN_PARTIAL_SIG");
        break;
      case 0x03:
        assertNoKeyData(entry, location, "PSBT_IN_SIGHASH_TYPE");
        assertValueLength(entry, location, "PSBT_IN_SIGHASH_TYPE", 4);
        break;
      case 0x04:
        assertNoKeyData(entry, location, "PSBT_IN_REDEEM_SCRIPT");
        break;
      case 0x05:
        assertNoKeyData(entry, location, "PSBT_IN_WITNESS_SCRIPT");
        break;
      case 0x06:
        assertSerializedPubkey(entry, location, "PSBT_IN_BIP32_DERIVATION");
        assertDerivationValue(entry, location, "PSBT_IN_BIP32_DERIVATION");
        break;
      case 0x07:
        assertNoKeyData(entry, location, "PSBT_IN_FINAL_SCRIPTSIG");
        break;
      case 0x08:
        assertNoKeyData(entry, location, "PSBT_IN_FINAL_SCRIPTWITNESS");
        assertScriptWitness(entry, location, "PSBT_IN_FINAL_SCRIPTWITNESS");
        break;
      case 0x0a:
        assertKeyDataLength(entry, location, "PSBT_IN_RIPEMD160", 20);
        break;
      case 0x0b:
        assertKeyDataLength(entry, location, "PSBT_IN_SHA256", 32);
        break;
      case 0x0c:
        assertKeyDataLength(entry, location, "PSBT_IN_HASH160", 20);
        break;
      case 0x0d:
        assertKeyDataLength(entry, location, "PSBT_IN_HASH256", 32);
        break;
      case 0x0e:
        assertNoKeyData(entry, location, "PSBT_IN_PREVIOUS_TXID");
        assertValueLength(entry, location, "PSBT_IN_PREVIOUS_TXID", 32);
        break;
      case 0x0f:
        assertNoKeyData(entry, location, "PSBT_IN_OUTPUT_INDEX");
        assertValueLength(entry, location, "PSBT_IN_OUTPUT_INDEX", 4);
        break;
      case 0x10:
        assertNoKeyData(entry, location, "PSBT_IN_SEQUENCE");
        assertValueLength(entry, location, "PSBT_IN_SEQUENCE", 4);
        break;
      case 0x11:
        assertNoKeyData(entry, location, "PSBT_IN_REQUIRED_TIME_LOCKTIME");
        assertValueLength(entry, location, "PSBT_IN_REQUIRED_TIME_LOCKTIME", 4);
        if (entry.value.readUInt32LE(0) < 500_000_000) {
          invalidField(
            location,
            entry,
            "PSBT_IN_REQUIRED_TIME_LOCKTIME",
            "value is below the timestamp threshold",
          );
        }
        break;
      case 0x12: {
        assertNoKeyData(entry, location, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME");
        assertValueLength(entry, location, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME", 4);
        const locktime = entry.value.readUInt32LE(0);
        if (locktime === 0 || locktime >= 500_000_000) {
          invalidField(
            location,
            entry,
            "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
            "value is outside the block-height range",
          );
        }
        break;
      }
      case 0x13:
        assertNoKeyData(entry, location, "PSBT_IN_TAP_KEY_SIG");
        assertTaprootSignature(entry, location, "PSBT_IN_TAP_KEY_SIG");
        break;
      case 0x14:
        assertKeyDataLength(entry, location, "PSBT_IN_TAP_SCRIPT_SIG", 64);
        assertTaprootSignature(entry, location, "PSBT_IN_TAP_SCRIPT_SIG");
        break;
      case 0x15: {
        assertTaprootControlBlock(entry, location, "PSBT_IN_TAP_LEAF_SCRIPT");
        const leafVersion = entry.value[entry.value.byteLength - 1] as number;
        assertTaprootLeafVersion(entry, location, "PSBT_IN_TAP_LEAF_SCRIPT", leafVersion);
        if (((entry.keyData[0] as number) & 0xfe) !== leafVersion) {
          invalidField(
            location,
            entry,
            "PSBT_IN_TAP_LEAF_SCRIPT",
            "leaf version does not match the control block",
          );
        }
        break;
      }
      case 0x16:
        assertTaprootDerivation(entry, location, "PSBT_IN_TAP_BIP32_DERIVATION");
        break;
      case 0x17:
        assertNoKeyData(entry, location, "PSBT_IN_TAP_INTERNAL_KEY");
        assertValueLength(entry, location, "PSBT_IN_TAP_INTERNAL_KEY", 32);
        assertXOnlyPublicKey(entry.value, entry, location, "PSBT_IN_TAP_INTERNAL_KEY");
        break;
      case 0x18:
        assertNoKeyData(entry, location, "PSBT_IN_TAP_MERKLE_ROOT");
        assertValueLength(entry, location, "PSBT_IN_TAP_MERKLE_ROOT", 32);
        break;
      case 0xfc:
        assertProprietaryKey(entry, location, "PSBT_IN_PROPRIETARY");
        break;
    }
  }

  if (version === 2) {
    requireField(entries, location, 0x0e, "PSBT_IN_PREVIOUS_TXID");
    requireField(entries, location, 0x0f, "PSBT_IN_OUTPUT_INDEX");
  }
}

function validateOutputMap(map: InternalMap, version: number): void {
  const { location, entries } = map;
  for (const entry of entries) {
    if (version === 0 && (entry.keyType === 0x03 || entry.keyType === 0x04)) {
      forbiddenField(location, entry, "BIP370 output field", version);
    }

    switch (entry.keyType) {
      case 0x00:
        assertNoKeyData(entry, location, "PSBT_OUT_REDEEM_SCRIPT");
        break;
      case 0x01:
        assertNoKeyData(entry, location, "PSBT_OUT_WITNESS_SCRIPT");
        break;
      case 0x02:
        assertSerializedPubkey(entry, location, "PSBT_OUT_BIP32_DERIVATION");
        assertDerivationValue(entry, location, "PSBT_OUT_BIP32_DERIVATION");
        break;
      case 0x03:
        assertNoKeyData(entry, location, "PSBT_OUT_AMOUNT");
        assertValueLength(entry, location, "PSBT_OUT_AMOUNT", 8);
        break;
      case 0x04:
        assertNoKeyData(entry, location, "PSBT_OUT_SCRIPT");
        break;
      case 0x05:
        assertNoKeyData(entry, location, "PSBT_OUT_TAP_INTERNAL_KEY");
        assertValueLength(entry, location, "PSBT_OUT_TAP_INTERNAL_KEY", 32);
        assertXOnlyPublicKey(entry.value, entry, location, "PSBT_OUT_TAP_INTERNAL_KEY");
        break;
      case 0x06:
        assertTaprootTree(entry, location, "PSBT_OUT_TAP_TREE");
        break;
      case 0x07:
        assertTaprootDerivation(entry, location, "PSBT_OUT_TAP_BIP32_DERIVATION");
        break;
      case 0xfc:
        assertProprietaryKey(entry, location, "PSBT_OUT_PROPRIETARY");
        break;
    }
  }

  if (version === 2) {
    requireField(entries, location, 0x03, "PSBT_OUT_AMOUNT");
    requireField(entries, location, 0x04, "PSBT_OUT_SCRIPT");
  }
}

function validateMaps(maps: InternalMap[], version: number): void {
  for (const map of maps) {
    if (map.location.kind === "input") {
      validateInputMap(map, version);
    } else if (map.location.kind === "output") {
      validateOutputMap(map, version);
    }
  }
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
  const value = version.readUInt32LE(0);
  if (value !== 0 && value !== 2) {
    fieldError(
      "INVALID_FIELD",
      { kind: "global" },
      0xfb,
      `PSBT_GLOBAL_VERSION specifies an unsupported version`,
    );
  }
  return value;
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
    validateVersionEntry(globalMap.entries);
    const psbtVersion = determineVersion(globalMap.entries);
    validateGlobalMap(globalMap.entries, psbtVersion);
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
    validateMaps(maps, psbtVersion);

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

export function requireUniquePsbtEntryValue(
  encoded: string,
  location: PsbtMapLocation,
  keyType: number,
): Buffer {
  const map = parsePsbtDocument(encoded).maps.find(
    (candidate) =>
      candidate.location.kind === location.kind &&
      (candidate.location.kind === "global" ||
        (location.kind !== "global" && candidate.location.index === location.index)),
  );
  const entries = map?.entries.filter(
    (entry) => entry.keyType === keyType && entry.keyData.byteLength === 0,
  );
  if (entries?.length !== 1 || !entries[0]) {
    throw new PsbtDocumentError(
      `PSBT must contain exactly one key type ${keyType} at the selected map`,
      { location, keyType },
    );
  }
  return Buffer.from(entries[0].value);
}
