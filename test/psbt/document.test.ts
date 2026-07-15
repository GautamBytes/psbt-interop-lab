import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  PsbtDocumentError,
  type PsbtDocumentErrorCode,
  type PsbtMapLocation,
  parsePsbtDocument,
} from "../../src/psbt/document.js";

const magic = Buffer.from("70736274ff", "hex");

// Published BIP370 vectors: https://bips.dev/370/
const bip370ValidRequiredFields =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";
const bip370InvalidV0WithVersion2 =
  "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==";

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
  return framedPsbt(validV2Global(), validV2Input(), validV2Output());
}

function framedPsbt(
  globalEntries: Buffer[],
  inputEntries: Buffer[],
  outputEntries: Buffer[],
): Buffer {
  return Buffer.concat([magic, map(...globalEntries), map(...inputEntries), map(...outputEntries)]);
}

function validV2Global(): Buffer[] {
  return [
    entry(0x02, Buffer.from("02000000", "hex")),
    entry(0x04, Buffer.from([1])),
    entry(0x05, Buffer.from([1])),
    entry(0xfb, Buffer.from("02000000", "hex")),
  ];
}

function validV2Input(): Buffer[] {
  return [entry(0x0e, Buffer.alloc(32, 0x22)), entry(0x0f, Buffer.from("03000000", "hex"))];
}

function validV2Output(): Buffer[] {
  return [
    entry(0x03, Buffer.from("1027000000000000", "hex")),
    entry(0x04, Buffer.from("51", "hex")),
  ];
}

function replaceEntry(entries: Buffer[], index: number, replacement: Buffer): Buffer[] {
  const replaced = [...entries];
  replaced[index] = replacement;
  return replaced;
}

function expectDocumentError(
  psbt: Buffer,
  code: PsbtDocumentErrorCode,
  location: PsbtMapLocation,
  keyType: number,
): void {
  let caught: unknown;
  try {
    parsePsbtDocument(psbt.toString("base64"));
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(PsbtDocumentError);
  expect(caught).toMatchObject({ code, location, keyType });
  expect(caught).not.toHaveProperty("value");
  expect(caught).not.toHaveProperty("completeKey");
}

describe("parsePsbtDocument", () => {
  test("accepts the official BIP370 required-fields-only PSBTv2 vector", () => {
    const document = parsePsbtDocument(bip370ValidRequiredFields);

    expect(document).toMatchObject({ psbtVersion: 2, inputCount: 1, outputCount: 2 });
  });

  test("rejects the official BIP370 PSBTv0-with-version-2 vector", () => {
    expectDocumentError(
      Buffer.from(bip370InvalidV0WithVersion2, "base64"),
      "FORBIDDEN_FIELD",
      { kind: "global" },
      0x00,
    );
  });

  test("preserves complete keys and values with deterministic fingerprints", () => {
    const proprietaryKeyData = Buffer.from("036c616201", "hex");
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
      psbtV0([], [entry(0x02, Buffer.from("signature"), compressedPubkey())]).toString("base64"),
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

  test.each([
    ["transaction version", 0x02],
    ["input count", 0x04],
    ["output count", 0x05],
  ] as const)("requires the PSBTv2 global %s field", (_name, missingType) => {
    const psbt = framedPsbt(
      validV2Global().filter((item) => item[1] !== missingType),
      validV2Input(),
      validV2Output(),
    );

    expectDocumentError(psbt, "MISSING_REQUIRED_FIELD", { kind: "global" }, missingType);
  });

  test.each([
    ["previous txid", 0x0e],
    ["output index", 0x0f],
  ] as const)("requires every PSBTv2 input %s field", (_name, missingType) => {
    const psbt = framedPsbt(
      validV2Global(),
      validV2Input().filter((item) => item[1] !== missingType),
      validV2Output(),
    );

    expectDocumentError(psbt, "MISSING_REQUIRED_FIELD", { kind: "input", index: 0 }, missingType);
  });

  test.each([
    ["amount", 0x03],
    ["script", 0x04],
  ] as const)("requires every PSBTv2 output %s field", (_name, missingType) => {
    const psbt = framedPsbt(
      validV2Global(),
      validV2Input(),
      validV2Output().filter((item) => item[1] !== missingType),
    );

    expectDocumentError(psbt, "MISSING_REQUIRED_FIELD", { kind: "output", index: 0 }, missingType);
  });

  test("rejects PSBTv2-only fields in PSBTv0 maps", () => {
    expectDocumentError(
      psbtV0([entry(0x02, Buffer.alloc(4))]),
      "FORBIDDEN_FIELD",
      { kind: "global" },
      0x02,
    );
    expectDocumentError(
      psbtV0([], [entry(0x0e, Buffer.alloc(32))]),
      "FORBIDDEN_FIELD",
      { kind: "input", index: 0 },
      0x0e,
    );
    const transaction = entry(0x00, unsignedTransaction());
    expectDocumentError(
      Buffer.concat([magic, map(transaction), map(), map(entry(0x03, Buffer.alloc(8)))]),
      "FORBIDDEN_FIELD",
      { kind: "output", index: 0 },
      0x03,
    );
  });

  test("rejects PSBT_GLOBAL_TX_MODIFIABLE in PSBTv0", () => {
    expectDocumentError(
      psbtV0([entry(0x06, Buffer.from([0]))]),
      "FORBIDDEN_FIELD",
      { kind: "global" },
      0x06,
    );
  });

  test("rejects PSBT_GLOBAL_UNSIGNED_TX in PSBTv2", () => {
    expectDocumentError(
      framedPsbt(
        [entry(0x00, unsignedTransaction()), ...validV2Global()],
        validV2Input(),
        validV2Output(),
      ),
      "FORBIDDEN_FIELD",
      { kind: "global" },
      0x00,
    );
  });

  test.each([
    {
      name: "global version",
      psbt: () =>
        framedPsbt(
          replaceEntry(validV2Global(), 3, entry(0xfb, Buffer.alloc(3))),
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0xfb,
    },
    {
      name: "transaction version",
      psbt: () =>
        framedPsbt(
          replaceEntry(validV2Global(), 0, entry(0x02, Buffer.alloc(3))),
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0x02,
    },
    {
      name: "fallback locktime",
      psbt: () =>
        framedPsbt(
          [...validV2Global(), entry(0x03, Buffer.alloc(3))],
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0x03,
    },
    {
      name: "transaction modifiable",
      psbt: () =>
        framedPsbt(
          [...validV2Global(), entry(0x06, Buffer.alloc(2))],
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0x06,
    },
    {
      name: "previous txid",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          replaceEntry(validV2Input(), 0, entry(0x0e, Buffer.alloc(31))),
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x0e,
    },
    {
      name: "output index",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          replaceEntry(validV2Input(), 1, entry(0x0f, Buffer.alloc(3))),
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x0f,
    },
    {
      name: "sequence",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          [...validV2Input(), entry(0x10, Buffer.alloc(3))],
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x10,
    },
    {
      name: "required time locktime",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          [...validV2Input(), entry(0x11, Buffer.alloc(3))],
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x11,
    },
    {
      name: "required height locktime",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          [...validV2Input(), entry(0x12, Buffer.alloc(3))],
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x12,
    },
    {
      name: "output amount",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          validV2Input(),
          replaceEntry(validV2Output(), 0, entry(0x03, Buffer.alloc(7))),
        ),
      location: { kind: "output", index: 0 } as const,
      keyType: 0x03,
    },
  ])("rejects a wrong-width $name field", ({ psbt, location, keyType }) => {
    expectDocumentError(psbt(), "INVALID_FIELD", location, keyType);
  });

  test.each([
    {
      name: "global version",
      psbt: () =>
        framedPsbt(
          replaceEntry(validV2Global(), 3, entry(0xfb, Buffer.alloc(4), Buffer.from([1]))),
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0xfb,
    },
    {
      name: "transaction version",
      psbt: () =>
        framedPsbt(
          replaceEntry(validV2Global(), 0, entry(0x02, Buffer.alloc(4), Buffer.from([1]))),
          validV2Input(),
          validV2Output(),
        ),
      location: { kind: "global" } as const,
      keyType: 0x02,
    },
    {
      name: "previous txid",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          replaceEntry(validV2Input(), 0, entry(0x0e, Buffer.alloc(32), Buffer.from([1]))),
          validV2Output(),
        ),
      location: { kind: "input", index: 0 } as const,
      keyType: 0x0e,
    },
    {
      name: "output amount",
      psbt: () =>
        framedPsbt(
          validV2Global(),
          validV2Input(),
          replaceEntry(validV2Output(), 0, entry(0x03, Buffer.alloc(8), Buffer.from([1]))),
        ),
      location: { kind: "output", index: 0 } as const,
      keyType: 0x03,
    },
  ])("rejects key data on singleton $name fields", ({ psbt, location, keyType }) => {
    expectDocumentError(psbt(), "INVALID_FIELD", location, keyType);
  });

  test("validates BIP370 locktime ranges", () => {
    const belowTimestamp = Buffer.alloc(4);
    belowTimestamp.writeUInt32LE(499_999_999);
    const zeroHeight = Buffer.alloc(4);

    expectDocumentError(
      framedPsbt(
        validV2Global(),
        [...validV2Input(), entry(0x11, belowTimestamp)],
        validV2Output(),
      ),
      "INVALID_FIELD",
      { kind: "input", index: 0 },
      0x11,
    );
    expectDocumentError(
      framedPsbt(validV2Global(), [...validV2Input(), entry(0x12, zeroHeight)], validV2Output()),
      "INVALID_FIELD",
      { kind: "input", index: 0 },
      0x12,
    );
  });

  test.each([
    ["partial signature pubkey", entry(0x02, Buffer.from([1]), Buffer.alloc(32)), 0x02],
    ["sighash width", entry(0x03, Buffer.alloc(3)), 0x03],
    ["tap key signature width", entry(0x13, Buffer.alloc(63)), 0x13],
    ["tap script signature key", entry(0x14, Buffer.alloc(64), Buffer.alloc(63)), 0x14],
    ["tap internal key width", entry(0x17, Buffer.alloc(33)), 0x17],
  ] as const)("rejects malformed BIP174/BIP371 %s fields", (_name, malformed, keyType) => {
    expectDocumentError(
      psbtV0([], [malformed]),
      "INVALID_FIELD",
      { kind: "input", index: 0 },
      keyType,
    );
  });
});
