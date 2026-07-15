import {
  diffPsbtDocuments,
  extractTransactionIdentity,
  type PsbtChangedEntry,
  type PsbtEntrySummary,
} from "./diff.js";
import type { PsbtDocument, PsbtMapLocation } from "./document.js";

export type PsbtTransitionPolicy = "roundtrip" | "sign" | "combine" | "finalize";

export type PsbtTransitionFailureCode =
  | "TRANSACTION_IDENTITY_CHANGED"
  | "TX_MODIFIABLE_INVALID_CHANGE"
  | "ENTRY_ADDED"
  | "ENTRY_REMOVED"
  | "ENTRY_CHANGED";

export interface PsbtValueFingerprint {
  readonly valueSha256: string;
  readonly valueBytes: number;
}

export interface PsbtTransitionFailure {
  readonly code: PsbtTransitionFailureCode;
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly completeKeySha256: string;
  readonly keyBytes: number;
  readonly before?: PsbtValueFingerprint;
  readonly after?: PsbtValueFingerprint;
}

export interface PsbtTransitionResult {
  readonly ok: boolean;
  readonly policy: PsbtTransitionPolicy;
  readonly exactBytesEqual: boolean;
  readonly failures: readonly PsbtTransitionFailure[];
}

const SIGNATURE_INPUT_TYPES = new Set([0x02, 0x13, 0x14]);
const FINAL_INPUT_TYPES = new Set([0x07, 0x08]);
const FINALIZE_REMOVABLE_INPUT_TYPES = new Set([
  0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
]);

function addedFailure(
  entry: PsbtEntrySummary,
  code: PsbtTransitionFailureCode = "ENTRY_ADDED",
): PsbtTransitionFailure {
  return {
    code,
    location: entry.location,
    keyType: entry.keyType,
    completeKeySha256: entry.completeKeySha256,
    keyBytes: entry.keyBytes,
    after: { valueSha256: entry.valueSha256, valueBytes: entry.valueBytes },
  };
}

function removedFailure(
  entry: PsbtEntrySummary,
  code: PsbtTransitionFailureCode = "ENTRY_REMOVED",
): PsbtTransitionFailure {
  return {
    code,
    location: entry.location,
    keyType: entry.keyType,
    completeKeySha256: entry.completeKeySha256,
    keyBytes: entry.keyBytes,
    before: { valueSha256: entry.valueSha256, valueBytes: entry.valueBytes },
  };
}

function changedFailure(
  entry: PsbtChangedEntry,
  code: PsbtTransitionFailureCode = "ENTRY_CHANGED",
): PsbtTransitionFailure {
  return {
    code,
    location: entry.location,
    keyType: entry.keyType,
    completeKeySha256: entry.completeKeySha256,
    keyBytes: entry.keyBytes,
    before: entry.before,
    after: entry.after,
  };
}

function isIdentityEntry(version: number, location: PsbtMapLocation, keyType: number): boolean {
  if (version === 0) {
    return location.kind === "global" && keyType === 0x00;
  }
  if (version !== 2) {
    return false;
  }
  if (location.kind === "global") {
    return keyType >= 0x02 && keyType <= 0x05;
  }
  if (location.kind === "input") {
    return keyType >= 0x0e && keyType <= 0x12;
  }
  return keyType === 0x03 || keyType === 0x04;
}

function isChangedIdentityEntry(
  before: PsbtDocument,
  after: PsbtDocument,
  location: PsbtMapLocation,
  keyType: number,
  identityChanged: boolean,
): boolean {
  if (!identityChanged) {
    return false;
  }
  if (before.psbtVersion !== after.psbtVersion && location.kind === "global" && keyType === 0xfb) {
    return true;
  }
  return (
    isIdentityEntry(before.psbtVersion, location, keyType) ||
    isIdentityEntry(after.psbtVersion, location, keyType)
  );
}

function isInputType(location: PsbtMapLocation, keyType: number, types: Set<number>): boolean {
  return location.kind === "input" && types.has(keyType);
}

function findGlobalValue(document: PsbtDocument, keyType: number): Buffer | undefined {
  return document.maps
    .find((map) => map.location.kind === "global")
    ?.entries.find((entry) => entry.keyType === keyType && entry.completeKey.byteLength === 1)
    ?.value;
}

function isValidTxModifiableChange(before: PsbtDocument, after: PsbtDocument): boolean {
  const beforeValue = findGlobalValue(before, 0x06);
  const afterValue = findGlobalValue(after, 0x06);
  if (beforeValue?.byteLength !== 1 || afterValue?.byteLength !== 1) {
    return false;
  }
  const beforeFlags = beforeValue[0] as number;
  const afterFlags = afterValue[0] as number;
  const unknownBitsUnchanged = (beforeFlags & 0xf8) === (afterFlags & 0xf8);
  const modifiableBitsOnlyClear = (afterFlags & 0x03 & ~(beforeFlags & 0x03)) === 0;
  const sighashSingleOnlySets = (beforeFlags & 0x04 & ~(afterFlags & 0x04)) === 0;
  return unknownBitsUnchanged && modifiableBitsOnlyClear && sighashSingleOnlySets;
}

function roundtripFailures(
  added: readonly PsbtEntrySummary[],
  removed: readonly PsbtEntrySummary[],
  changed: readonly PsbtChangedEntry[],
): PsbtTransitionFailure[] {
  return [
    ...added.map((entry) => addedFailure(entry)),
    ...removed.map((entry) => removedFailure(entry)),
    ...changed.map((entry) => changedFailure(entry)),
  ];
}

function signFailures(
  before: PsbtDocument,
  after: PsbtDocument,
  added: readonly PsbtEntrySummary[],
  removed: readonly PsbtEntrySummary[],
  changed: readonly PsbtChangedEntry[],
  identityChanged: boolean,
): PsbtTransitionFailure[] {
  const failures: PsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, SIGNATURE_INPUT_TYPES)) {
      failures.push(addedFailure(entry));
    }
  }
  for (const entry of removed) {
    const code = isChangedIdentityEntry(
      before,
      after,
      entry.location,
      entry.keyType,
      identityChanged,
    )
      ? "TRANSACTION_IDENTITY_CHANGED"
      : "ENTRY_REMOVED";
    failures.push(removedFailure(entry, code));
  }
  for (const entry of changed) {
    if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(changedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (entry.location.kind === "global" && entry.keyType === 0x06) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(changedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else {
      failures.push(changedFailure(entry));
    }
  }
  return failures;
}

function combineFailures(
  before: PsbtDocument,
  after: PsbtDocument,
  added: readonly PsbtEntrySummary[],
  removed: readonly PsbtEntrySummary[],
  changed: readonly PsbtChangedEntry[],
  identityChanged: boolean,
): PsbtTransitionFailure[] {
  const failures: PsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    }
  }
  for (const entry of removed) {
    const code = isChangedIdentityEntry(
      before,
      after,
      entry.location,
      entry.keyType,
      identityChanged,
    )
      ? "TRANSACTION_IDENTITY_CHANGED"
      : "ENTRY_REMOVED";
    failures.push(removedFailure(entry, code));
  }
  for (const entry of changed) {
    const code = isChangedIdentityEntry(
      before,
      after,
      entry.location,
      entry.keyType,
      identityChanged,
    )
      ? "TRANSACTION_IDENTITY_CHANGED"
      : "ENTRY_CHANGED";
    failures.push(changedFailure(entry, code));
  }
  return failures;
}

function finalizeFailures(
  before: PsbtDocument,
  after: PsbtDocument,
  added: readonly PsbtEntrySummary[],
  removed: readonly PsbtEntrySummary[],
  changed: readonly PsbtChangedEntry[],
  identityChanged: boolean,
): PsbtTransitionFailure[] {
  const failures: PsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, FINAL_INPUT_TYPES)) {
      failures.push(addedFailure(entry));
    }
  }
  for (const entry of removed) {
    if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(removedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, FINALIZE_REMOVABLE_INPUT_TYPES)) {
      failures.push(removedFailure(entry));
    }
  }
  for (const entry of changed) {
    const code = isChangedIdentityEntry(
      before,
      after,
      entry.location,
      entry.keyType,
      identityChanged,
    )
      ? "TRANSACTION_IDENTITY_CHANGED"
      : "ENTRY_CHANGED";
    failures.push(changedFailure(entry, code));
  }
  return failures;
}

export function assertPsbtTransition(
  policy: PsbtTransitionPolicy,
  before: PsbtDocument,
  after: PsbtDocument,
): PsbtTransitionResult {
  const diff = diffPsbtDocuments(before, after);
  const identityChanged =
    extractTransactionIdentity(before).sha256 !== extractTransactionIdentity(after).sha256;
  let failures: PsbtTransitionFailure[];

  switch (policy) {
    case "roundtrip":
      failures = roundtripFailures(diff.added, diff.removed, diff.changed);
      break;
    case "sign":
      failures = signFailures(
        before,
        after,
        diff.added,
        diff.removed,
        diff.changed,
        identityChanged,
      );
      break;
    case "combine":
      failures = combineFailures(
        before,
        after,
        diff.added,
        diff.removed,
        diff.changed,
        identityChanged,
      );
      break;
    case "finalize":
      failures = finalizeFailures(
        before,
        after,
        diff.added,
        diff.removed,
        diff.changed,
        identityChanged,
      );
      break;
  }

  return {
    ok: failures.length === 0,
    policy,
    exactBytesEqual: diff.exactBytesEqual,
    failures,
  };
}
