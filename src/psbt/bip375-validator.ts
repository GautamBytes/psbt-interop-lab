import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { readCompactSize } from "./compact-size.js";
import {
  type PsbtDocument,
  type PsbtDocumentEntry,
  PsbtDocumentError,
  type PsbtDocumentMap,
  parsePsbtDocument,
} from "./document.js";

const GLOBAL_SP_ECDH_SHARE = 0x07;
const GLOBAL_SP_DLEQ = 0x08;
const IN_NON_WITNESS_UTXO = 0x00;
const IN_WITNESS_UTXO = 0x01;
const IN_SIGHASH_TYPE = 0x03;
const IN_REDEEM_SCRIPT = 0x04;
const IN_BIP32_DERIVATION = 0x06;
const IN_PREVIOUS_TXID = 0x0e;
const IN_OUTPUT_INDEX = 0x0f;
const IN_TAP_INTERNAL_KEY = 0x17;
const IN_SP_ECDH_SHARE = 0x1d;
const IN_SP_DLEQ = 0x1e;
const OUT_SCRIPT = 0x04;
const OUT_SP_V0_INFO = 0x09;
const NUMS_H = Buffer.from(
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
  "hex",
);
const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

type SecpPoint = ReturnType<typeof secp256k1.Point.fromBytes>;

export type Bip375ValidationStage =
  | "psbt structure"
  | "ecdh coverage"
  | "input eligibility"
  | "output scripts";

export type Bip375FailureClass =
  | "silent_payment.invalid_dleq"
  | "silent_payment.missing_dleq"
  | "silent_payment.incomplete_coverage"
  | "silent_payment.sighash_not_allowed"
  | "silent_payment.output_script_mismatch"
  | "silent_payment.output_order_mismatch"
  | "silent_payment.invalid_psbt";

export type Bip375ValidationResult =
  | { readonly valid: true }
  | {
      readonly valid: false;
      readonly stage: Bip375ValidationStage;
      readonly message: string;
      readonly failureClass: Bip375FailureClass;
    };

export type ClassifiedBip375ValidationResult =
  | { readonly valid: true }
  | (Extract<Bip375ValidationResult, { valid: false }> & {
      readonly class: Bip375FailureClass;
    });

class Bip375ValidationError extends Error {
  override readonly name = "Bip375ValidationError";

  constructor(
    readonly stage: Bip375ValidationStage,
    message: string,
    readonly failureClass: Bip375FailureClass = "silent_payment.invalid_psbt",
  ) {
    super(message);
  }
}

function fail(
  stage: Bip375ValidationStage,
  message: string,
  failureClass: Bip375FailureClass = "silent_payment.invalid_psbt",
): never {
  throw new Bip375ValidationError(stage, message, failureClass);
}

function mapAt(document: PsbtDocument, kind: "global"): PsbtDocumentMap;
function mapAt(document: PsbtDocument, kind: "input" | "output", index: number): PsbtDocumentMap;
function mapAt(
  document: PsbtDocument,
  kind: "global" | "input" | "output",
  index?: number,
): PsbtDocumentMap {
  const map = document.maps.find(({ location }) =>
    kind === "global"
      ? location.kind === "global"
      : location.kind === kind && location.index === index,
  );
  if (!map) {
    fail("psbt structure", `Missing ${kind}${index === undefined ? "" : ` ${index}`} map`);
  }
  return map;
}

function entriesOfType(map: PsbtDocumentMap, keyType: number): readonly PsbtDocumentEntry[] {
  return map.entries.filter((entry) => entry.keyType === keyType);
}

function singleton(map: PsbtDocumentMap, keyType: number): PsbtDocumentEntry | undefined {
  return map.entries.find((entry) => entry.keyType === keyType && entry.keyData.byteLength === 0);
}

function keyed(
  map: PsbtDocumentMap,
  keyType: number,
  keyData: Uint8Array,
): PsbtDocumentEntry | undefined {
  return map.entries.find((entry) => entry.keyType === keyType && entry.keyData.equals(keyData));
}

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function taggedHash(tag: string, message: Uint8Array): Buffer {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  return sha256(Buffer.concat([tagHash, tagHash, Buffer.from(message)]));
}

function scalar(bytes: Uint8Array, label: string): bigint {
  const value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  if (value === 0n || value >= CURVE_ORDER) {
    fail("output scripts", `${label} is outside the secp256k1 scalar range`);
  }
  return value;
}

function point(bytes: Uint8Array, stage: Bip375ValidationStage, label: string): SecpPoint {
  try {
    return secp256k1.Point.fromBytes(bytes);
  } catch {
    fail(stage, `${label} is not a valid secp256k1 point`);
  }
}

function compressed(pointValue: SecpPoint): Buffer {
  return Buffer.from(pointValue.toBytes(true));
}

function multiplyPublic(pointValue: SecpPoint, value: bigint): SecpPoint {
  return pointValue.multiplyUnsafe(value % CURVE_ORDER);
}

function sumPoints(points: readonly SecpPoint[]): SecpPoint | undefined {
  if (points.length === 0) {
    return undefined;
  }
  return points.slice(1).reduce((sum, next) => sum.add(next), points[0] as SecpPoint);
}

function readVarBytes(
  buffer: Buffer,
  offset: number,
  label: string,
): {
  readonly bytes: Buffer;
  readonly nextOffset: number;
} {
  const length = readCompactSize(buffer, offset);
  const end = length.nextOffset + length.value;
  if (end > buffer.byteLength) {
    fail("psbt structure", `${label} exceeds its containing transaction`);
  }
  return { bytes: buffer.subarray(length.nextOffset, end), nextOffset: end };
}

function witnessScript(value: Buffer): Buffer {
  if (value.byteLength < 9) {
    fail("psbt structure", "PSBT_IN_WITNESS_UTXO is truncated");
  }
  const script = readVarBytes(value, 8, "PSBT_IN_WITNESS_UTXO script");
  if (script.nextOffset !== value.byteLength) {
    fail("psbt structure", "PSBT_IN_WITNESS_UTXO contains trailing data");
  }
  return script.bytes;
}

function previousTransactionOutputScript(transaction: Buffer, outputIndex: number): Buffer {
  if (transaction.byteLength < 10) {
    fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO is truncated");
  }
  let offset = 4;
  let inputCount = readCompactSize(transaction, offset);
  offset = inputCount.nextOffset;
  let hasWitness = false;
  if (inputCount.value === 0) {
    if (offset >= transaction.byteLength || transaction[offset] === 0) {
      fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO has an invalid witness marker");
    }
    hasWitness = true;
    offset += 1;
    inputCount = readCompactSize(transaction, offset);
    offset = inputCount.nextOffset;
  }
  for (let index = 0; index < inputCount.value; index += 1) {
    if (offset + 36 > transaction.byteLength) {
      fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO input is truncated");
    }
    offset += 36;
    const script = readVarBytes(transaction, offset, "previous transaction scriptSig");
    offset = script.nextOffset + 4;
    if (offset > transaction.byteLength) {
      fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO sequence is truncated");
    }
  }
  const outputCount = readCompactSize(transaction, offset);
  offset = outputCount.nextOffset;
  let selected: Buffer | undefined;
  for (let index = 0; index < outputCount.value; index += 1) {
    if (offset + 8 > transaction.byteLength) {
      fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO output is truncated");
    }
    offset += 8;
    const script = readVarBytes(transaction, offset, "previous transaction output script");
    offset = script.nextOffset;
    if (index === outputIndex) {
      selected = Buffer.from(script.bytes);
    }
  }
  if (hasWitness) {
    for (let inputIndex = 0; inputIndex < inputCount.value; inputIndex += 1) {
      const itemCount = readCompactSize(transaction, offset);
      offset = itemCount.nextOffset;
      for (let itemIndex = 0; itemIndex < itemCount.value; itemIndex += 1) {
        offset = readVarBytes(transaction, offset, "previous transaction witness item").nextOffset;
      }
    }
  }
  if (offset + 4 !== transaction.byteLength) {
    fail("psbt structure", "PSBT_IN_NON_WITNESS_UTXO has invalid trailing data");
  }
  if (!selected) {
    fail("psbt structure", `Previous transaction has no output ${outputIndex}`);
  }
  return selected;
}

function inputScript(map: PsbtDocumentMap, stage: Bip375ValidationStage): Buffer {
  const witnessUtxo = singleton(map, IN_WITNESS_UTXO);
  if (witnessUtxo) {
    return witnessScript(witnessUtxo.value);
  }
  const nonWitnessUtxo = singleton(map, IN_NON_WITNESS_UTXO);
  const outputIndex = singleton(map, IN_OUTPUT_INDEX);
  if (nonWitnessUtxo && outputIndex) {
    return previousTransactionOutputScript(nonWitnessUtxo.value, outputIndex.value.readUInt32LE(0));
  }
  fail(stage, "Input is missing the UTXO data needed to determine eligibility");
}

function isP2pkh(script: Buffer): boolean {
  return (
    script.byteLength === 25 &&
    script[0] === 0x76 &&
    script[1] === 0xa9 &&
    script[2] === 0x14 &&
    script[23] === 0x88 &&
    script[24] === 0xac
  );
}

function isP2wpkh(script: Buffer): boolean {
  return script.byteLength === 22 && script[0] === 0x00 && script[1] === 0x14;
}

function isP2tr(script: Buffer): boolean {
  return script.byteLength === 34 && script[0] === 0x51 && script[1] === 0x20;
}

function isP2sh(script: Buffer): boolean {
  return (
    script.byteLength === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87
  );
}

function eligibleInput(map: PsbtDocumentMap, stage: Bip375ValidationStage): boolean {
  const script = inputScript(map, stage);
  if (isP2tr(script)) {
    return !singleton(map, IN_TAP_INTERNAL_KEY)?.value.equals(NUMS_H);
  }
  if (isP2sh(script)) {
    const redeemScript = singleton(map, IN_REDEEM_SCRIPT);
    return redeemScript !== undefined && isP2wpkh(redeemScript.value);
  }
  return isP2pkh(script) || isP2wpkh(script);
}

function inputPublicKey(map: PsbtDocumentMap, stage: Bip375ValidationStage): SecpPoint | undefined {
  if (!eligibleInput(map, stage)) {
    return undefined;
  }
  // Match the upstream vector validator: its fixture scripts are not ownership commitments.
  const derivation = entriesOfType(map, IN_BIP32_DERIVATION)[0];
  if (derivation?.keyData.byteLength === 33) {
    return point(derivation.keyData, stage, "PSBT_IN_BIP32_DERIVATION public key");
  }
  const script = inputScript(map, stage);
  if (isP2tr(script)) {
    return point(Buffer.concat([Buffer.from([0x02]), script.subarray(2)]), stage, "P2TR input key");
  }
  return undefined;
}

function eligibleInputKeys(
  inputMaps: readonly PsbtDocumentMap[],
  stage: Bip375ValidationStage,
): readonly SecpPoint[] {
  return inputMaps.flatMap((map, index) => {
    if (!eligibleInput(map, stage)) {
      return [];
    }
    const key = inputPublicKey(map, stage);
    if (!key) {
      fail(stage, `Eligible input ${index} has no recoverable public key`);
    }
    return [key];
  });
}

function verifyDleq(
  inputKey: SecpPoint,
  scanKeyBytes: Buffer,
  ecdhShareBytes: Buffer,
  proof: Buffer,
): boolean {
  const scanKey = point(scanKeyBytes, "ecdh coverage", "Silent Payment scan key");
  const ecdhShare = point(ecdhShareBytes, "ecdh coverage", "Silent Payment ECDH share");
  const e = BigInt(`0x${proof.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${proof.subarray(32).toString("hex")}`);
  if (s >= CURVE_ORDER) {
    return false;
  }
  const r1 = multiplyPublic(secp256k1.Point.BASE, s).subtract(multiplyPublic(inputKey, e));
  const r2 = multiplyPublic(scanKey, s).subtract(multiplyPublic(ecdhShare, e));
  if (r1.is0() || r2.is0()) {
    return false;
  }
  const challenge = taggedHash(
    "BIP0374/challenge",
    Buffer.concat([
      compressed(inputKey),
      compressed(scanKey),
      compressed(ecdhShare),
      compressed(secp256k1.Point.BASE),
      compressed(r1),
      compressed(r2),
    ]),
  );
  return e === BigInt(`0x${challenge.toString("hex")}`);
}

function scanKeys(document: PsbtDocument): readonly Buffer[] {
  const keys = new Map<string, Buffer>();
  for (let index = 0; index < document.outputCount; index += 1) {
    const info = singleton(mapAt(document, "output", index), OUT_SP_V0_INFO);
    if (info) {
      const scanKey = Buffer.from(info.value.subarray(0, 33));
      keys.set(scanKey.toString("hex"), scanKey);
    }
  }
  return [...keys.values()];
}

function hasComputedOutput(document: PsbtDocument, scanKey: Buffer): boolean {
  for (let index = 0; index < document.outputCount; index += 1) {
    const map = mapAt(document, "output", index);
    const info = singleton(map, OUT_SP_V0_INFO);
    if (info?.value.subarray(0, 33).equals(scanKey) && singleton(map, OUT_SCRIPT)) {
      return true;
    }
  }
  return false;
}

function validateEcdhCoverage(document: PsbtDocument): void {
  const globalMap = mapAt(document, "global");
  const inputMaps = Array.from({ length: document.inputCount }, (_, index) =>
    mapAt(document, "input", index),
  );
  for (const scanKey of scanKeys(document)) {
    const globalShare = keyed(globalMap, GLOBAL_SP_ECDH_SHARE, scanKey);
    const anyInputShare = inputMaps.some((map) => keyed(map, IN_SP_ECDH_SHARE, scanKey));
    const computed = hasComputedOutput(document, scanKey);
    if (computed && !globalShare && !anyInputShare) {
      fail(
        "ecdh coverage",
        "Computed Silent Payment output has no ECDH share for its scan key",
        "silent_payment.incomplete_coverage",
      );
    }
    if (globalShare) {
      const proof = keyed(globalMap, GLOBAL_SP_DLEQ, scanKey);
      if (!proof) {
        fail(
          "ecdh coverage",
          "Global ECDH share is missing its DLEQ proof",
          "silent_payment.missing_dleq",
        );
      }
      const inputKey = sumPoints(eligibleInputKeys(inputMaps, "ecdh coverage"));
      if (!inputKey) {
        fail("ecdh coverage", "Global ECDH share has no eligible input public keys");
      }
      if (!verifyDleq(inputKey, scanKey, globalShare.value, proof.value)) {
        fail(
          "ecdh coverage",
          "Global BIP374 DLEQ proof verification failed",
          "silent_payment.invalid_dleq",
        );
      }
    } else if (computed) {
      for (const [index, map] of inputMaps.entries()) {
        if (!eligibleInput(map, "ecdh coverage")) {
          continue;
        }
        const share = keyed(map, IN_SP_ECDH_SHARE, scanKey);
        if (!share) {
          fail(
            "ecdh coverage",
            `Eligible input ${index} is missing an ECDH share`,
            "silent_payment.incomplete_coverage",
          );
        }
        const proof = keyed(map, IN_SP_DLEQ, scanKey);
        if (!proof) {
          fail(
            "ecdh coverage",
            `Input ${index} ECDH share is missing its DLEQ proof`,
            "silent_payment.missing_dleq",
          );
        }
        const inputKey = inputPublicKey(map, "ecdh coverage");
        if (!inputKey) {
          fail("ecdh coverage", `Input ${index} is missing its public key for DLEQ verification`);
        }
        if (!verifyDleq(inputKey, scanKey, share.value, proof.value)) {
          fail(
            "ecdh coverage",
            `Input ${index} BIP374 DLEQ proof verification failed`,
            "silent_payment.invalid_dleq",
          );
        }
      }
    }
  }
}

function validateInputEligibility(document: PsbtDocument): void {
  if (scanKeys(document).length === 0) {
    return;
  }
  for (let index = 0; index < document.inputCount; index += 1) {
    const map = mapAt(document, "input", index);
    const script = inputScript(map, "input eligibility");
    const firstOpcode = script[0];
    const programLength = script[1];
    if (
      firstOpcode !== undefined &&
      firstOpcode > 0x51 &&
      firstOpcode <= 0x60 &&
      programLength !== undefined &&
      programLength >= 2 &&
      programLength <= 40 &&
      script.byteLength === programLength + 2
    ) {
      fail("input eligibility", `Input ${index} uses SegWit version greater than 1`);
    }
    const sighash = singleton(map, IN_SIGHASH_TYPE);
    if (sighash && sighash.value.readUInt32LE(0) !== 1) {
      fail(
        "input eligibility",
        `Input ${index} uses a non-SIGHASH_ALL signature`,
        "silent_payment.sighash_not_allowed",
      );
    }
  }
}

function collectEcdhAndInputKey(
  document: PsbtDocument,
  scanKey: Buffer,
): { readonly ecdhShare: SecpPoint; readonly inputKey: SecpPoint } | undefined {
  const globalShare = keyed(mapAt(document, "global"), GLOBAL_SP_ECDH_SHARE, scanKey);
  const inputMaps = Array.from({ length: document.inputCount }, (_, index) =>
    mapAt(document, "input", index),
  );
  if (globalShare) {
    const inputKey = sumPoints(eligibleInputKeys(inputMaps, "output scripts"));
    return inputKey
      ? {
          ecdhShare: point(globalShare.value, "output scripts", "Global ECDH share"),
          inputKey,
        }
      : undefined;
  }

  const contributions: { readonly share: SecpPoint; readonly key: SecpPoint }[] = [];
  for (const map of inputMaps) {
    const share = keyed(map, IN_SP_ECDH_SHARE, scanKey);
    if (!share || !eligibleInput(map, "output scripts")) {
      continue;
    }
    const key = inputPublicKey(map, "output scripts");
    if (!key) {
      fail("output scripts", "Eligible input with an ECDH share has no recoverable public key");
    }
    contributions.push({
      share: point(share.value, "output scripts", "Input ECDH share"),
      key,
    });
  }
  const ecdhShare = sumPoints(contributions.map(({ share }) => share));
  const inputKey = sumPoints(contributions.map(({ key }) => key));
  return ecdhShare && inputKey ? { ecdhShare, inputKey } : undefined;
}

function outpoints(document: PsbtDocument): readonly Buffer[] {
  return Array.from({ length: document.inputCount }, (_, index) => {
    const map = mapAt(document, "input", index);
    const txid = singleton(map, IN_PREVIOUS_TXID);
    const outputIndex = singleton(map, IN_OUTPUT_INDEX);
    if (!txid || !outputIndex) {
      fail("psbt structure", `Input ${index} is missing its outpoint`);
    }
    return Buffer.concat([txid.value, outputIndex.value]);
  });
}

function deriveOutputScript(
  transactionOutpoints: readonly Buffer[],
  inputKey: SecpPoint,
  ecdhShare: SecpPoint,
  spendKeyBytes: Buffer,
  k: number,
): Buffer {
  const lowestOutpoint = [...transactionOutpoints].sort(Buffer.compare)[0];
  if (!lowestOutpoint) {
    fail("output scripts", "Cannot derive a Silent Payment output without transaction inputs");
  }
  const inputHash = scalar(
    taggedHash("BIP0352/Inputs", Buffer.concat([lowestOutpoint, compressed(inputKey)])),
    "BIP352 input hash",
  );
  const sharedSecret = multiplyPublic(ecdhShare, inputHash);
  const kBytes = Buffer.alloc(4);
  kBytes.writeUInt32BE(k);
  const tweak = scalar(
    taggedHash("BIP0352/SharedSecret", Buffer.concat([compressed(sharedSecret), kBytes])),
    "BIP352 output tweak",
  );
  const spendKey = point(spendKeyBytes, "output scripts", "Silent Payment spend key");
  const outputKey = spendKey.add(multiplyPublic(secp256k1.Point.BASE, tweak));
  const xOnlyKey = Buffer.from(outputKey.toBytes(true)).subarray(1);
  return Buffer.concat([Buffer.from([0x51, 0x20]), xOnlyKey]);
}

function validateOutputScripts(document: PsbtDocument): void {
  const outputMaps = document.maps.filter(({ location }) => location.kind === "output");
  const outputOrder = new Map<number, number>();
  const byScanKey = new Map<string, number[]>();
  for (const [index, map] of outputMaps.entries()) {
    const info = singleton(map, OUT_SP_V0_INFO);
    if (!info) continue;
    const scanKey = Buffer.from(info.value.subarray(0, 33)).toString("hex");
    const group = byScanKey.get(scanKey) ?? [];
    group.push(index);
    byScanKey.set(scanKey, group);
  }
  for (const group of byScanKey.values()) {
    group.forEach((index, k) => {
      outputOrder.set(index, k);
    });
  }

  const transactionOutpoints = outpoints(document);
  const nextK = new Map<string, number>();
  for (let index = 0; index < document.outputCount; index += 1) {
    const map = mapAt(document, "output", index);
    const info = singleton(map, OUT_SP_V0_INFO);
    if (!info) {
      continue;
    }
    const scanKey = Buffer.from(info.value.subarray(0, 33));
    const spendKey = Buffer.from(info.value.subarray(33));
    const key = scanKey.toString("hex");
    const k = outputOrder.get(index) ?? nextK.get(key) ?? 0;
    const collected = collectEcdhAndInputKey(document, scanKey);
    const actualScript = singleton(map, OUT_SCRIPT);
    if (collected) {
      const expectedScript = deriveOutputScript(
        transactionOutpoints,
        collected.inputKey,
        collected.ecdhShare,
        spendKey,
        k,
      );
      if (actualScript && !actualScript.value.equals(expectedScript)) {
        const groupSize = byScanKey.get(key)?.length ?? 1;
        const matchesAnotherK = Array.from({ length: groupSize }, (_, candidateK) => candidateK)
          .filter((candidateK) => candidateK !== k)
          .some((candidateK) =>
            actualScript.value.equals(
              deriveOutputScript(
                transactionOutpoints,
                collected.inputKey,
                collected.ecdhShare,
                spendKey,
                candidateK,
              ),
            ),
          );
        fail(
          "output scripts",
          `Output ${index} does not match its BIP352 derivation`,
          matchesAnotherK
            ? "silent_payment.output_order_mismatch"
            : "silent_payment.output_script_mismatch",
        );
      }
      nextK.set(key, k + 1);
    } else if (actualScript) {
      fail(
        "output scripts",
        `Output ${index} lacks the ECDH share or input keys needed to derive it`,
        "silent_payment.incomplete_coverage",
      );
    }
  }
}

function parserFailureStage(error: PsbtDocumentError): Bip375ValidationStage {
  if (
    error.code === "MISSING_REQUIRED_FIELD" &&
    error.keyType !== undefined &&
    [GLOBAL_SP_ECDH_SHARE, GLOBAL_SP_DLEQ, IN_SP_ECDH_SHARE, IN_SP_DLEQ].includes(error.keyType)
  ) {
    return "ecdh coverage";
  }
  return "psbt structure";
}

export function validateBip375ReferencePsbt(encoded: string): Bip375ValidationResult {
  try {
    const document = parsePsbtDocument(encoded);
    if (document.psbtVersion !== 2) {
      fail("psbt structure", "BIP375 fields require PSBTv2");
    }
    runValidationStage("ecdh coverage", () => validateEcdhCoverage(document));
    runValidationStage("input eligibility", () => validateInputEligibility(document));
    runValidationStage("output scripts", () => validateOutputScripts(document));
    return { valid: true };
  } catch (error) {
    if (error instanceof Bip375ValidationError) {
      return {
        valid: false,
        stage: error.stage,
        message: error.message,
        failureClass: error.failureClass,
      };
    }
    if (error instanceof PsbtDocumentError) {
      return {
        valid: false,
        stage: parserFailureStage(error),
        message: error.message,
        failureClass: "silent_payment.invalid_psbt",
      };
    }
    return {
      valid: false,
      stage: "psbt structure",
      message: error instanceof Error ? error.message : "Unknown BIP375 validation failure",
      failureClass: "silent_payment.invalid_psbt",
    };
  }
}

export function classifyBip375ReferencePsbt(encoded: string): ClassifiedBip375ValidationResult {
  const result = validateBip375ReferencePsbt(encoded);
  if (result.valid) return result;
  return { ...result, class: result.failureClass };
}

function runValidationStage(stage: Bip375ValidationStage, validate: () => void): void {
  try {
    validate();
  } catch (error) {
    if (error instanceof Bip375ValidationError || error instanceof PsbtDocumentError) {
      throw error;
    }
    fail(stage, error instanceof Error ? error.message : `Unknown ${stage} validation failure`);
  }
}
