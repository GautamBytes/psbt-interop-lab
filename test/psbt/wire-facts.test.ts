import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { CompactSizeError, readCompactSize } from "../../src/psbt/compact-size.js";
import { extractWireFacts, PsbtWireError } from "../../src/psbt/wire-facts.js";

const magic = Buffer.from("70736274ff", "hex");

function unsignedTransaction(): Buffer {
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32),
    Buffer.from("ffffffff", "hex"),
    Buffer.from([0]),
    Buffer.from("ffffffff", "hex"),
    Buffer.from([1]),
    Buffer.alloc(8),
    Buffer.from([0]),
    Buffer.alloc(4),
  ]);
}

function validPsbt(): Buffer {
  const transaction = unsignedTransaction();
  return Buffer.concat([
    magic,
    Buffer.from([1, 0, transaction.byteLength]),
    transaction,
    Buffer.from([0]),
    Buffer.from([0]),
    Buffer.from([0]),
  ]);
}

describe("readCompactSize", () => {
  test.each([
    [Buffer.from([252]), 252, 1],
    [Buffer.from("fdfd00", "hex"), 253, 3],
    [Buffer.from("fe00000100", "hex"), 65_536, 5],
  ])("reads a minimally encoded integer", (buffer, value, nextOffset) => {
    expect(readCompactSize(buffer, 0)).toEqual({ value, nextOffset });
  });

  test("rejects a non-minimal encoding", () => {
    expect(() => readCompactSize(Buffer.from("fd0100", "hex"), 0)).toThrow(/non-minimal/i);
  });

  test("rejects truncated input", () => {
    expect(() => readCompactSize(Buffer.from([0xfd, 1]), 0)).toThrow(CompactSizeError);
  });
});

describe("extractWireFacts", () => {
  test("extracts bounded structural facts from a PSBTv0", () => {
    const psbt = validPsbt();
    const facts = extractWireFacts(psbt.toString("base64"));

    expect(facts).toMatchObject({
      format: "psbt",
      psbtVersion: 0,
      byteLength: psbt.byteLength,
      inputCount: 1,
      outputCount: 1,
      mapCount: 3,
    });
    expect(facts.sha256).toBe(createHash("sha256").update(psbt).digest("hex"));
    expect(facts.maps.map((map) => map.kind)).toEqual(["global", "input", "output"]);
    expect(facts.maps[0]?.entries[0]).toEqual({
      keyType: 0,
      keyDataBytes: 0,
      valueBytes: unsignedTransaction().byteLength,
    });
  });

  test("rejects invalid magic bytes", () => {
    const invalid = Buffer.from(validPsbt());
    invalid[0] = 0;

    expect(() => extractWireFacts(invalid.toString("base64"))).toThrow(/magic/i);
  });

  test("rejects duplicate complete keys within one map", () => {
    const transaction = unsignedTransaction();
    const invalid = Buffer.concat([
      magic,
      Buffer.from([1, 0, transaction.byteLength]),
      transaction,
      Buffer.from([1, 0, transaction.byteLength]),
      transaction,
      Buffer.from([0, 0, 0]),
    ]);

    expect(() => extractWireFacts(invalid.toString("base64"))).toThrow(/duplicate/i);
  });

  test("decodes a multi-byte CompactSize key type", () => {
    const transaction = unsignedTransaction();
    const psbt = Buffer.concat([
      magic,
      Buffer.from([1, 0, transaction.byteLength]),
      transaction,
      Buffer.from("03fdfd000101", "hex"),
      Buffer.from([0, 0, 0]),
    ]);

    const facts = extractWireFacts(psbt.toString("base64"));

    expect(facts.maps[0]?.entries[1]).toEqual({
      keyType: 253,
      keyDataBytes: 0,
      valueBytes: 1,
    });
  });

  test("rejects a non-minimal CompactSize key type", () => {
    const transaction = unsignedTransaction();
    const invalid = Buffer.concat([
      magic,
      Buffer.from([1, 0, transaction.byteLength]),
      transaction,
      Buffer.from("03fd01000101", "hex"),
      Buffer.from([0, 0, 0]),
    ]);

    expect(() => extractWireFacts(invalid.toString("base64"))).toThrow(/key type.*non-minimal/i);
  });

  test("rejects a map without a terminator", () => {
    const truncated = validPsbt().subarray(0, -1);

    expect(() => extractWireFacts(truncated.toString("base64"))).toThrow(/terminator|truncated/i);
  });

  test("rejects bytes after the expected maps", () => {
    const invalid = Buffer.concat([validPsbt(), Buffer.from([0])]);

    expect(() => extractWireFacts(invalid.toString("base64"))).toThrow(/trailing/i);
  });

  test("enforces PSBT and value size limits", () => {
    const encoded = validPsbt().toString("base64");

    expect(() => extractWireFacts(encoded, { maxPsbtBytes: 8 })).toThrow(/size limit/i);
    expect(() => extractWireFacts(encoded, { maxValueBytes: 8 })).toThrow(/value.*limit/i);
  });

  test("rejects oversized canonical base64 before decoding", () => {
    const oversized = Buffer.alloc(9).toString("base64");

    expect(() => extractWireFacts(oversized, { maxPsbtBytes: 8 })).toThrow(/size limit/i);
  });

  test("rejects oversized encoded input before validating base64 syntax", () => {
    expect(() => extractWireFacts("!".repeat(13), { maxPsbtBytes: 8 })).toThrow(/size limit/i);
  });

  test("rejects malformed base64", () => {
    expect(() => extractWireFacts("not base64!!!")).toThrow(PsbtWireError);
  });
});
