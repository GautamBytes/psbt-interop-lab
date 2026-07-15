import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { PsbtDocumentError, parsePsbtDocument } from "../../src/psbt/document.js";

const magic = Buffer.from("70736274ff", "hex");

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
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

function unsignedTransaction(): Buffer {
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x11),
    Buffer.from("01000000", "hex"),
    Buffer.from([0]),
    Buffer.from("feffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
}

function psbtV0(globalEntries: Buffer[] = [], inputEntries: Buffer[] = []): Buffer {
  return Buffer.concat([
    magic,
    map(entry(0x00, unsignedTransaction()), ...globalEntries),
    map(...inputEntries),
    map(),
  ]);
}

function psbtV2(): Buffer {
  return Buffer.concat([
    magic,
    map(
      entry(0x02, Buffer.from("02000000", "hex")),
      entry(0x04, Buffer.from([1])),
      entry(0x05, Buffer.from([1])),
      entry(0xfb, Buffer.from("02000000", "hex")),
    ),
    map(entry(0x0e, Buffer.alloc(32, 0x22)), entry(0x0f, Buffer.from("03000000", "hex"))),
    map(entry(0x03, Buffer.from("1027000000000000", "hex")), entry(0x04, Buffer.from("51", "hex"))),
  ]);
}

describe("parsePsbtDocument", () => {
  test("preserves complete keys and values with deterministic fingerprints", () => {
    const proprietaryKeyData = Buffer.from("046c616201", "hex");
    const proprietaryValue = Buffer.from("private metadata");
    const psbt = psbtV0([entry(0xfc, proprietaryValue, proprietaryKeyData)]);

    const document = parsePsbtDocument(psbt.toString("base64"));
    const proprietary = document.maps[0]?.entries[1];

    expect(document).toMatchObject({
      psbtVersion: 0,
      byteLength: psbt.byteLength,
      inputCount: 1,
      outputCount: 1,
      mapCount: 3,
    });
    expect(document.sha256).toBe(createHash("sha256").update(psbt).digest("hex"));
    expect(document.maps.map((item) => item.location)).toEqual([
      { kind: "global" },
      { kind: "input", index: 0 },
      { kind: "output", index: 0 },
    ]);
    expect(proprietary).toMatchObject({
      keyType: 0xfc,
      keyData: proprietaryKeyData,
      completeKey: Buffer.concat([Buffer.from([0xfc]), proprietaryKeyData]),
      value: proprietaryValue,
      keyBytes: proprietaryKeyData.byteLength + 1,
      valueBytes: proprietaryValue.byteLength,
    });
    expect(proprietary?.completeKeySha256).toBe(
      createHash("sha256")
        .update(Buffer.concat([Buffer.from([0xfc]), proprietaryKeyData]))
        .digest("hex"),
    );
    expect(proprietary?.valueSha256).toBe(
      createHash("sha256").update(proprietaryValue).digest("hex"),
    );
  });

  test("returns byte snapshots that cannot mutate parser state", () => {
    const document = parsePsbtDocument(
      psbtV0([], [entry(0x02, Buffer.from("signature"), Buffer.from("pubkey"))]).toString("base64"),
    );
    const firstEntry = document.maps[1]?.entries[0];
    const originalValue = Buffer.from(firstEntry?.value ?? Buffer.alloc(0));
    const originalKey = Buffer.from(firstEntry?.completeKey ?? Buffer.alloc(0));
    const bytes = document.bytes;

    if (firstEntry) {
      firstEntry.value.fill(0);
      firstEntry.completeKey.fill(0);
      firstEntry.keyData.fill(0);
    }
    bytes.fill(0);

    expect(document.maps[1]?.entries[0]?.value).toEqual(originalValue);
    expect(document.maps[1]?.entries[0]?.completeKey).toEqual(originalKey);
    expect(document.bytes.subarray(0, magic.byteLength)).toEqual(magic);
  });

  test("supports BIP370 map framing", () => {
    const document = parsePsbtDocument(psbtV2().toString("base64"));

    expect(document).toMatchObject({
      psbtVersion: 2,
      inputCount: 1,
      outputCount: 1,
      mapCount: 3,
    });
    expect(document.maps[1]?.entries.map((item) => item.keyType)).toEqual([0x0e, 0x0f]);
    expect(document.maps[2]?.entries.map((item) => item.keyType)).toEqual([0x03, 0x04]);
  });

  test("rejects extra maps and preserves configured limits", () => {
    const valid = psbtV0();
    const extraMap = Buffer.concat([valid, map()]);

    expect(() => parsePsbtDocument(extraMap.toString("base64"))).toThrow(/trailing/i);
    expect(() => parsePsbtDocument(valid.toString("base64"), { maxValueBytes: 8 })).toThrow(
      /value.*limit/i,
    );
    expect(() => parsePsbtDocument("not base64")).toThrow(PsbtDocumentError);
  });
});
