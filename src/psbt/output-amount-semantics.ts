import { readCompactSize } from "./compact-size.js";
import type { PsbtDocument } from "./document.js";

export const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const RULE_ID = "lab.transaction-output.money-range" as const;

export type OutputAmountSemanticCode =
  | "OUTPUT_AMOUNT_NEGATIVE"
  | "OUTPUT_AMOUNT_ABOVE_MAX_MONEY"
  | "OUTPUT_TOTAL_ABOVE_MAX_MONEY";

export interface OutputAmountSemanticFinding {
  readonly ruleId: typeof RULE_ID;
  readonly code: OutputAmountSemanticCode;
  readonly outputIndex?: number;
}

export interface OutputAmountSemanticAssessment {
  readonly status: "valid" | "invalid" | "not-evaluated";
  readonly findings: readonly OutputAmountSemanticFinding[];
  readonly outputsModifiable?: boolean;
}

interface IndexedAmount {
  readonly outputIndex: number;
  readonly value: bigint;
}

function requireBytes(buffer: Buffer, offset: number, count: number, label: string): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + count > buffer.length) {
    throw new Error(`Parsed PSBT invariant failed while reading ${label}`);
  }
}

function v0Amounts(document: PsbtDocument): readonly IndexedAmount[] {
  const globalMap = document.maps.find(({ location }) => location.kind === "global");
  const transaction = globalMap?.entries.find(
    ({ keyType, keyData }) => keyType === 0x00 && keyData.length === 0,
  )?.value;
  if (!transaction) throw new Error("Parsed PSBTv0 is missing its unsigned transaction");

  requireBytes(transaction, 0, 4, "transaction version");
  let offset = 4;
  const inputs = readCompactSize(transaction, offset);
  offset = inputs.nextOffset;
  for (let index = 0; index < inputs.value; index += 1) {
    requireBytes(transaction, offset, 36, "transaction input outpoint");
    offset += 36;
    const scriptLength = readCompactSize(transaction, offset);
    offset = scriptLength.nextOffset;
    requireBytes(transaction, offset, scriptLength.value, "transaction input script");
    offset += scriptLength.value;
    requireBytes(transaction, offset, 4, "transaction input sequence");
    offset += 4;
  }

  const outputs = readCompactSize(transaction, offset);
  offset = outputs.nextOffset;
  const amounts: IndexedAmount[] = [];
  for (let outputIndex = 0; outputIndex < outputs.value; outputIndex += 1) {
    requireBytes(transaction, offset, 8, "transaction output amount");
    amounts.push({ outputIndex, value: transaction.readBigInt64LE(offset) });
    offset += 8;
    const scriptLength = readCompactSize(transaction, offset);
    offset = scriptLength.nextOffset;
    requireBytes(transaction, offset, scriptLength.value, "transaction output script");
    offset += scriptLength.value;
  }
  requireBytes(transaction, offset, 4, "transaction locktime");
  offset += 4;
  if (offset !== transaction.length) {
    throw new Error("Parsed PSBTv0 unsigned transaction contains trailing data");
  }
  return amounts;
}

function v2Amounts(document: PsbtDocument): readonly IndexedAmount[] {
  return document.maps
    .filter(({ location }) => location.kind === "output")
    .map((map) => {
      if (map.location.kind !== "output") throw new Error("Unreachable non-output map");
      const entry = map.entries.find(
        ({ keyType, keyData }) => keyType === 0x03 && keyData.length === 0,
      );
      if (entry?.value.length !== 8) {
        throw new Error("Parsed PSBTv2 output is missing its eight-byte amount");
      }
      return { outputIndex: map.location.index, value: entry.value.readBigInt64LE(0) };
    })
    .sort((left, right) => left.outputIndex - right.outputIndex);
}

function outputsModifiable(document: PsbtDocument): boolean {
  if (document.psbtVersion !== 2) return false;
  const globalMap = document.maps.find(({ location }) => location.kind === "global");
  const value = globalMap?.entries.find(
    ({ keyType, keyData }) => keyType === 0x06 && keyData.length === 0,
  )?.value;
  return value !== undefined && ((value[0] as number) & 0x02) !== 0;
}

export function assessOutputAmountSemantics(
  document: PsbtDocument,
): OutputAmountSemanticAssessment {
  const amounts = document.psbtVersion === 0 ? v0Amounts(document) : v2Amounts(document);
  const findings: OutputAmountSemanticFinding[] = [];
  let total = 0n;
  for (const { outputIndex, value } of amounts) {
    if (value < 0n) {
      findings.push({ ruleId: RULE_ID, code: "OUTPUT_AMOUNT_NEGATIVE", outputIndex });
    } else if (value > MAX_MONEY_SATS) {
      findings.push({
        ruleId: RULE_ID,
        code: "OUTPUT_AMOUNT_ABOVE_MAX_MONEY",
        outputIndex,
      });
    } else {
      total += value;
    }
  }
  if (findings.length === 0 && total > MAX_MONEY_SATS) {
    findings.push({ ruleId: RULE_ID, code: "OUTPUT_TOTAL_ABOVE_MAX_MONEY" });
  }
  return {
    status: findings.length === 0 ? "valid" : "invalid",
    findings,
    outputsModifiable: outputsModifiable(document),
  };
}
