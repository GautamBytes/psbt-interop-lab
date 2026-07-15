import { createHash } from "node:crypto";
import type {
  PsbtDocument,
  PsbtDocumentEntry,
  PsbtDocumentMap,
  PsbtMapLocation,
} from "./document.js";

export interface PsbtEntrySummary {
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly completeKeySha256: string;
  readonly keyBytes: number;
  readonly valueSha256: string;
  readonly valueBytes: number;
}

export interface PsbtChangedEntry {
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly completeKeySha256: string;
  readonly keyBytes: number;
  readonly before: {
    readonly valueSha256: string;
    readonly valueBytes: number;
  };
  readonly after: {
    readonly valueSha256: string;
    readonly valueBytes: number;
  };
}

export interface PsbtSemanticDiff {
  readonly exactBytesEqual: boolean;
  readonly added: readonly PsbtEntrySummary[];
  readonly removed: readonly PsbtEntrySummary[];
  readonly changed: readonly PsbtChangedEntry[];
}

export interface TransactionIdentityField {
  readonly name: string;
  readonly location: PsbtMapLocation;
  readonly keyType: number;
  readonly valueSha256: string;
  readonly valueBytes: number;
}

export interface TransactionIdentity {
  readonly psbtVersion: number;
  readonly sha256: string;
  readonly fields: readonly TransactionIdentityField[];
}

interface LocatedEntry {
  id: string;
  location: PsbtMapLocation;
  entry: PsbtDocumentEntry;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function cloneLocation(location: PsbtMapLocation): PsbtMapLocation {
  return location.kind === "global" ? { kind: "global" } : { ...location };
}

function locationId(location: PsbtMapLocation): string {
  if (location.kind === "global") {
    return "0:global";
  }
  const kindOrder = location.kind === "input" ? 1 : 2;
  return `${kindOrder}:${location.index.toString().padStart(16, "0")}`;
}

function locatedEntries(document: PsbtDocument): LocatedEntry[] {
  return document.maps.flatMap((map) =>
    map.entries.map((entry) => ({
      id: `${locationId(map.location)}:${entry.completeKey.toString("hex")}`,
      location: map.location,
      entry,
    })),
  );
}

function summarize(item: LocatedEntry): PsbtEntrySummary {
  return {
    location: cloneLocation(item.location),
    keyType: item.entry.keyType,
    completeKeySha256: item.entry.completeKeySha256,
    keyBytes: item.entry.keyBytes,
    valueSha256: item.entry.valueSha256,
    valueBytes: item.entry.valueBytes,
  };
}

export function diffPsbtDocuments(before: PsbtDocument, after: PsbtDocument): PsbtSemanticDiff {
  const beforeEntries = locatedEntries(before);
  const afterEntries = locatedEntries(after);
  const beforeById = new Map(beforeEntries.map((item) => [item.id, item]));
  const afterById = new Map(afterEntries.map((item) => [item.id, item]));
  const added = afterEntries
    .filter((item) => !beforeById.has(item.id))
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(summarize);
  const removed = beforeEntries
    .filter((item) => !afterById.has(item.id))
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(summarize);
  const changed: PsbtChangedEntry[] = [];

  for (const beforeItem of beforeEntries) {
    const afterItem = afterById.get(beforeItem.id);
    if (!afterItem || beforeItem.entry.value.equals(afterItem.entry.value)) {
      continue;
    }
    changed.push({
      location: cloneLocation(beforeItem.location),
      keyType: beforeItem.entry.keyType,
      completeKeySha256: beforeItem.entry.completeKeySha256,
      keyBytes: beforeItem.entry.keyBytes,
      before: {
        valueSha256: beforeItem.entry.valueSha256,
        valueBytes: beforeItem.entry.valueBytes,
      },
      after: {
        valueSha256: afterItem.entry.valueSha256,
        valueBytes: afterItem.entry.valueBytes,
      },
    });
  }
  changed.sort((left, right) => {
    const leftId = `${locationId(left.location)}:${left.completeKeySha256}`;
    const rightId = `${locationId(right.location)}:${right.completeKeySha256}`;
    return leftId.localeCompare(rightId);
  });

  return {
    exactBytesEqual: before.bytes.equals(after.bytes),
    added,
    removed,
    changed,
  };
}

function singletonEntryId(location: PsbtMapLocation, keyType: number): string {
  return `${locationId(location)}:${keyType}`;
}

function indexSingletonEntries(
  maps: readonly PsbtDocumentMap[],
): ReadonlyMap<string, PsbtDocumentEntry> {
  const entries = new Map<string, PsbtDocumentEntry>();
  for (const map of maps) {
    for (const entry of map.entries) {
      if (entry.completeKey.byteLength === 1) {
        entries.set(singletonEntryId(map.location, entry.keyType), entry);
      }
    }
  }
  return entries;
}

function identityField(
  entries: ReadonlyMap<string, PsbtDocumentEntry>,
  name: string,
  location: PsbtMapLocation,
  keyType: number,
): TransactionIdentityField | undefined {
  const entry = entries.get(singletonEntryId(location, keyType));
  if (!entry) {
    return undefined;
  }
  return {
    name,
    location: cloneLocation(location),
    keyType,
    valueSha256: entry.valueSha256,
    valueBytes: entry.valueBytes,
  };
}

function appendField(
  fields: TransactionIdentityField[],
  field: TransactionIdentityField | undefined,
): void {
  if (field) {
    fields.push(field);
  }
}

export function extractTransactionIdentity(document: PsbtDocument): TransactionIdentity {
  const fields: TransactionIdentityField[] = [];
  const globalLocation: PsbtMapLocation = { kind: "global" };
  const entries = indexSingletonEntries(document.maps);

  if (document.psbtVersion === 0) {
    appendField(fields, identityField(entries, "unsignedTx", globalLocation, 0x00));
  } else {
    for (const [name, keyType] of [
      ["txVersion", 0x02],
      ["fallbackLocktime", 0x03],
      ["inputCount", 0x04],
      ["outputCount", 0x05],
    ] as const) {
      appendField(fields, identityField(entries, name, globalLocation, keyType));
    }
    for (let index = 0; index < document.inputCount; index += 1) {
      const location: PsbtMapLocation = { kind: "input", index };
      for (const [name, keyType] of [
        ["previousTxid", 0x0e],
        ["outputIndex", 0x0f],
        ["sequence", 0x10],
        ["requiredTimeLocktime", 0x11],
        ["requiredHeightLocktime", 0x12],
      ] as const) {
        appendField(fields, identityField(entries, `input[${index}].${name}`, location, keyType));
      }
    }
    for (let index = 0; index < document.outputCount; index += 1) {
      const location: PsbtMapLocation = { kind: "output", index };
      appendField(fields, identityField(entries, `output[${index}].amount`, location, 0x03));
      appendField(fields, identityField(entries, `output[${index}].script`, location, 0x04));
    }
  }

  const canonical = JSON.stringify({ psbtVersion: document.psbtVersion, fields });
  return {
    psbtVersion: document.psbtVersion,
    sha256: sha256(canonical),
    fields,
  };
}
