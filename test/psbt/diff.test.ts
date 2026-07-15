import { createHash } from "node:crypto";
import { describe, expect, test, vi } from "vitest";
import { diffPsbtDocuments, extractTransactionIdentity } from "../../src/psbt/diff.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";

const magic = Buffer.from("70736274ff", "hex");

function entry(keyType: number, value: Buffer, keyData: Buffer = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([
    Buffer.from([key.byteLength]),
    key,
    Buffer.from([value.byteLength]),
    value,
  ]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function compressedPubkey(fill = 0x02): Buffer {
  return Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, fill)]);
}

function unsignedTransaction(outputScript = Buffer.from("51", "hex")): Buffer {
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x11),
    Buffer.from("01000000", "hex"),
    Buffer.from([0]),
    Buffer.from("feffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([outputScript.byteLength]),
    outputScript,
    Buffer.from("00000000", "hex"),
  ]);
}

function psbtV0(globalEntries: Buffer[], inputEntries: Buffer[] = []): Buffer {
  return Buffer.concat([magic, map(...globalEntries), map(...inputEntries), map()]);
}

interface V2Options {
  modifiable?: number;
  sequence?: number;
  requiredTimeLocktime?: number;
  outputScript?: Buffer;
}

function psbtV2(options: V2Options = {}): Buffer {
  const globalEntries = [
    entry(0x02, Buffer.from("02000000", "hex")),
    entry(0x04, Buffer.from([1])),
    entry(0x05, Buffer.from([1])),
    entry(0xfb, Buffer.from("02000000", "hex")),
  ];
  if (options.modifiable !== undefined) {
    globalEntries.splice(3, 0, entry(0x06, Buffer.from([options.modifiable])));
  }
  const inputEntries = [
    entry(0x0e, Buffer.alloc(32, 0x22)),
    entry(0x0f, Buffer.from("03000000", "hex")),
  ];
  if (options.sequence !== undefined) {
    const sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(options.sequence);
    inputEntries.push(entry(0x10, sequence));
  }
  if (options.requiredTimeLocktime !== undefined) {
    const requiredTimeLocktime = Buffer.alloc(4);
    requiredTimeLocktime.writeUInt32LE(options.requiredTimeLocktime);
    inputEntries.push(entry(0x11, requiredTimeLocktime));
  }
  return Buffer.concat([
    magic,
    map(...globalEntries),
    map(...inputEntries),
    map(
      entry(0x03, Buffer.from("1027000000000000", "hex")),
      entry(0x04, options.outputScript ?? Buffer.from("51", "hex")),
    ),
  ]);
}

function document(psbt: Buffer) {
  return parsePsbtDocument(psbt.toString("base64"));
}

describe("diffPsbtDocuments", () => {
  test("ignores entry order while retaining exact-byte diagnostics", () => {
    const transactionEntry = entry(0x00, unsignedTransaction());
    const proprietaryEntry = entry(0xfc, Buffer.from("metadata"), Buffer.from("036c616201", "hex"));
    const before = document(psbtV0([transactionEntry, proprietaryEntry]));
    const after = document(psbtV0([proprietaryEntry, transactionEntry]));

    expect(diffPsbtDocuments(before, after)).toEqual({
      exactBytesEqual: false,
      added: [],
      removed: [],
      changed: [],
    });
  });

  test("reports additions, removals, and value changes by location and complete key", () => {
    const transactionEntry = entry(0x00, unsignedTransaction());
    const removedKeyData = Buffer.from("036c616201", "hex");
    const changedKeyData = compressedPubkey();
    const addedKeyData = Buffer.from("036c616202", "hex");
    const before = document(
      psbtV0(
        [transactionEntry, entry(0xfc, Buffer.from("keep?"), removedKeyData)],
        [entry(0x02, Buffer.from("old signature"), changedKeyData)],
      ),
    );
    const after = document(
      psbtV0(
        [transactionEntry, entry(0xfc, Buffer.from("added"), addedKeyData)],
        [entry(0x02, Buffer.from("new signature"), changedKeyData)],
      ),
    );

    const diff = diffPsbtDocuments(before, after);

    expect(diff.removed[0]).toMatchObject({
      location: { kind: "global" },
      keyType: 0xfc,
      completeKeySha256: createHash("sha256")
        .update(Buffer.concat([Buffer.from([0xfc]), removedKeyData]))
        .digest("hex"),
      valueBytes: 5,
    });
    expect(diff.added[0]).toMatchObject({
      location: { kind: "global" },
      keyType: 0xfc,
      valueBytes: 5,
    });
    expect(diff.changed[0]).toMatchObject({
      location: { kind: "input", index: 0 },
      keyType: 0x02,
      before: { valueBytes: 13 },
      after: { valueBytes: 13 },
    });
    expect(JSON.stringify(diff)).not.toContain("old signature");
    expect(JSON.stringify(diff)).not.toContain("new signature");
  });
});

describe("extractTransactionIdentity", () => {
  test("fingerprints the exact unsigned transaction for PSBTv0", () => {
    const transaction = unsignedTransaction();
    const identity = extractTransactionIdentity(document(psbtV0([entry(0x00, transaction)])));

    expect(identity.psbtVersion).toBe(0);
    expect(identity.fields).toEqual([
      {
        name: "unsignedTx",
        location: { kind: "global" },
        keyType: 0x00,
        valueSha256: createHash("sha256").update(transaction).digest("hex"),
        valueBytes: transaction.byteLength,
      },
    ]);
    expect(identity.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test("excludes v2 transaction-modifiable policy state from identity", () => {
    const modifiable = extractTransactionIdentity(document(psbtV2({ modifiable: 0x03 })));
    const locked = extractTransactionIdentity(document(psbtV2({ modifiable: 0x00 })));

    expect(modifiable).toEqual(locked);
    expect(modifiable.psbtVersion).toBe(2);
    expect(modifiable.fields.length).toBeGreaterThan(0);
    expect(modifiable.fields.some((field) => field.keyType === 0x06)).toBe(false);
  });

  test("preserves sequence and required locktime exactly as strict lab identity fields", () => {
    const first = extractTransactionIdentity(document(psbtV2({ sequence: 0xffff_fffe })));
    const second = extractTransactionIdentity(document(psbtV2({ sequence: 0xffff_fffd })));
    const firstLocktime = extractTransactionIdentity(
      document(psbtV2({ requiredTimeLocktime: 500_000_001 })),
    );
    const secondLocktime = extractTransactionIdentity(
      document(psbtV2({ requiredTimeLocktime: 500_000_002 })),
    );

    expect(first.sha256).not.toBe(second.sha256);
    expect(first.fields.find((field) => field.name === "input[0].sequence")).not.toEqual(
      second.fields.find((field) => field.name === "input[0].sequence"),
    );
    expect(firstLocktime.sha256).not.toBe(secondLocktime.sha256);
    expect(
      firstLocktime.fields.find((field) => field.name === "input[0].requiredTimeLocktime"),
    ).not.toEqual(
      secondLocktime.fields.find((field) => field.name === "input[0].requiredTimeLocktime"),
    );
  });

  test("reads one immutable map snapshot while extracting identity", () => {
    const parsed = document(psbtV2({ sequence: 0xffff_fffe, requiredTimeLocktime: 500_000_001 }));
    const maps = vi.spyOn(parsed, "maps", "get");

    extractTransactionIdentity(parsed);

    expect(maps).toHaveBeenCalledTimes(1);
  });
});
