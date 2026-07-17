import {
  diffPsbtDocuments,
  extractTransactionIdentity,
  type PsbtChangedEntry,
  type PsbtEntrySummary,
} from "./diff.js";
import type { PsbtDocument, PsbtMapLocation } from "./document.js";
import { describePsbtField, type PsbtFieldMetadata } from "./fields.js";

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

export type PsbtSafeGuidanceCode =
  | "TRANSACTION_INTENT_CHANGED"
  | "RESTORE_TX_MODIFIABLE_FLAGS"
  | "RESTORE_EXTENSION_METADATA"
  | "RESTORE_AND_RESIGN"
  | "RESTORE_REMOVED_FIELD"
  | "REJECT_CHANGED_FIELD"
  | "REVIEW_UNEXPECTED_FIELD";

export interface PsbtSafeGuidance {
  readonly code: PsbtSafeGuidanceCode;
  readonly severity: "stop" | "review";
  readonly summary: string;
  readonly nextSteps: readonly string[];
}

export interface PsbtTransitionFailure {
  readonly code: PsbtTransitionFailureCode;
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly completeKeySha256: string;
  readonly keyBytes: number;
  readonly field?: PsbtFieldMetadata;
  readonly guidance?: PsbtSafeGuidance;
  readonly before?: PsbtValueFingerprint;
  readonly after?: PsbtValueFingerprint;
}

type BarePsbtTransitionFailure = Omit<PsbtTransitionFailure, "field" | "guidance">;

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
): BarePsbtTransitionFailure {
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
): BarePsbtTransitionFailure {
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
): BarePsbtTransitionFailure {
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
  if (
    before.psbtVersion !== 2 ||
    after.psbtVersion !== 2 ||
    (beforeValue !== undefined && beforeValue.byteLength !== 1) ||
    (afterValue !== undefined && afterValue.byteLength !== 1)
  ) {
    return false;
  }
  const beforeFlags = beforeValue?.[0] ?? 0;
  const afterFlags = afterValue?.[0] ?? 0;
  const unknownBitsUnchanged = (beforeFlags & 0xf8) === (afterFlags & 0xf8);
  const modifiableBitsOnlyClear = (afterFlags & 0x03 & ~(beforeFlags & 0x03)) === 0;
  const sighashSingleOnlySets = (beforeFlags & 0x04 & ~(afterFlags & 0x04)) === 0;
  return unknownBitsUnchanged && modifiableBitsOnlyClear && sighashSingleOnlySets;
}

function isTxModifiableEntry(entry: PsbtEntrySummary | PsbtChangedEntry): boolean {
  return entry.location.kind === "global" && entry.keyType === 0x06 && entry.keyBytes === 1;
}

function roundtripFailures(
  before: PsbtDocument,
  after: PsbtDocument,
  added: readonly PsbtEntrySummary[],
  removed: readonly PsbtEntrySummary[],
  changed: readonly PsbtChangedEntry[],
): BarePsbtTransitionFailure[] {
  const beforeModifiable = findGlobalValue(before, 0x06);
  const afterModifiable = findGlobalValue(after, 0x06);
  const omittedZeroNormalization =
    before.psbtVersion === 2 &&
    after.psbtVersion === 2 &&
    ((beforeModifiable === undefined &&
      afterModifiable?.byteLength === 1 &&
      afterModifiable[0] === 0) ||
      (beforeModifiable?.byteLength === 1 &&
        beforeModifiable[0] === 0 &&
        afterModifiable === undefined));
  const isNormalizedModifiableEntry = (entry: PsbtEntrySummary): boolean =>
    omittedZeroNormalization &&
    entry.location.kind === "global" &&
    entry.keyType === 0x06 &&
    entry.keyBytes === 1;

  return [
    ...added
      .filter((entry) => !isNormalizedModifiableEntry(entry))
      .map((entry) => addedFailure(entry)),
    ...removed
      .filter((entry) => !isNormalizedModifiableEntry(entry))
      .map((entry) => removedFailure(entry)),
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
): BarePsbtTransitionFailure[] {
  const failures: BarePsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(addedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, SIGNATURE_INPUT_TYPES)) {
      failures.push(addedFailure(entry));
    }
  }
  for (const entry of removed) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(removedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
      continue;
    }
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
): BarePsbtTransitionFailure[] {
  const failures: BarePsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(addedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    }
  }
  for (const entry of removed) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(removedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
      continue;
    }
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
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(changedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else {
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
): BarePsbtTransitionFailure[] {
  const failures: BarePsbtTransitionFailure[] = [];
  for (const entry of added) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(addedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(addedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, FINAL_INPUT_TYPES)) {
      failures.push(addedFailure(entry));
    }
  }
  for (const entry of removed) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(removedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else if (isChangedIdentityEntry(before, after, entry.location, entry.keyType, identityChanged)) {
      failures.push(removedFailure(entry, "TRANSACTION_IDENTITY_CHANGED"));
    } else if (!isInputType(entry.location, entry.keyType, FINALIZE_REMOVABLE_INPUT_TYPES)) {
      failures.push(removedFailure(entry));
    }
  }
  for (const entry of changed) {
    if (isTxModifiableEntry(entry)) {
      if (!isValidTxModifiableChange(before, after)) {
        failures.push(changedFailure(entry, "TX_MODIFIABLE_INVALID_CHANGE"));
      }
    } else {
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
  }
  return failures;
}

function safeGuidance(
  policy: PsbtTransitionPolicy,
  failure: BarePsbtTransitionFailure,
  field: PsbtFieldMetadata,
): PsbtSafeGuidance {
  if (failure.code === "TRANSACTION_IDENTITY_CHANGED") {
    return {
      code: "TRANSACTION_INTENT_CHANGED",
      severity: "stop",
      summary: `The transaction being authorized changed during the ${policy} transition.`,
      nextSteps: [
        "Do not sign or broadcast the changed PSBT.",
        "Return to the previous checkpoint and verify recipients, amounts, inputs, sequences, and locktime.",
        "Recreate the PSBT from the original transaction intent before retrying the handoff.",
      ],
    };
  }
  if (failure.code === "TX_MODIFIABLE_INVALID_CHANGE") {
    return {
      code: "RESTORE_TX_MODIFIABLE_FLAGS",
      severity: "stop",
      summary: `Transaction modifiable flags changed in a direction BIP370 does not permit during the ${policy} transition.`,
      nextSteps: [
        "Do not continue with the changed PSBT.",
        "Restore the flags from the previous checkpoint and report the non-monotonic change.",
      ],
    };
  }
  if (
    failure.code === "ENTRY_REMOVED" &&
    (field.kind === "unknown" || field.kind === "proprietary")
  ) {
    return {
      code: "RESTORE_EXTENSION_METADATA",
      severity: "stop",
      summary: `An extension field was removed during the ${policy} transition.`,
      nextSteps: [
        "Return to the previous checkpoint.",
        "Use an implementation that preserves unknown and proprietary fields.",
        "Report the removed field to the implementation maintainer before retrying.",
      ],
    };
  }
  if (
    failure.code === "ENTRY_REMOVED" &&
    ["PSBT_IN_PARTIAL_SIG", "PSBT_IN_TAP_KEY_SIG", "PSBT_IN_TAP_SCRIPT_SIG"].includes(field.symbol)
  ) {
    return {
      code: "RESTORE_AND_RESIGN",
      severity: "stop",
      summary: `A signature was removed during the ${policy} transition.`,
      nextSteps: [
        "Return to the previous checkpoint and do not treat the changed PSBT as fully signed.",
        "Correct the lossy handoff before asking the signer to sign again.",
      ],
    };
  }
  if (failure.code === "ENTRY_REMOVED") {
    return {
      code: "RESTORE_REMOVED_FIELD",
      severity: "stop",
      summary: `${field.displayName} was removed during the ${policy} transition.`,
      nextSteps: [
        "Return to the previous checkpoint.",
        "Restore the missing field at its source instead of reconstructing it from incomplete data.",
      ],
    };
  }
  if (failure.code === "ENTRY_CHANGED") {
    return {
      code: "REJECT_CHANGED_FIELD",
      severity: "stop",
      summary: `${field.displayName} changed during the ${policy} transition.`,
      nextSteps: [
        "Reject the changed PSBT and return to the previous checkpoint.",
        "Compare the field fingerprints and report which implementation changed the value.",
      ],
    };
  }
  return {
    code: "REVIEW_UNEXPECTED_FIELD",
    severity: "review",
    summary: `${field.displayName} was added unexpectedly during the ${policy} transition.`,
    nextSteps: [
      "Review why the field was added before accepting the PSBT.",
      "Continue only when the field is expected for this transition and transaction intent.",
    ],
  };
}

function enrichFailure(
  policy: PsbtTransitionPolicy,
  failure: BarePsbtTransitionFailure,
): PsbtTransitionFailure {
  const field = describePsbtField(failure.location.kind, failure.keyType);
  return { ...failure, field, guidance: safeGuidance(policy, failure, field) };
}

export function assertPsbtTransition(
  policy: PsbtTransitionPolicy,
  before: PsbtDocument,
  after: PsbtDocument,
): PsbtTransitionResult {
  const diff = diffPsbtDocuments(before, after);
  const identityChanged =
    extractTransactionIdentity(before).sha256 !== extractTransactionIdentity(after).sha256;
  let failures: BarePsbtTransitionFailure[];

  switch (policy) {
    case "roundtrip":
      failures = roundtripFailures(before, after, diff.added, diff.removed, diff.changed);
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
    failures: failures.map((failure) => enrichFailure(policy, failure)),
  };
}
