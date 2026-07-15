import { describe, expect, test } from "vitest";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { assertPsbtTransition } from "../../src/psbt/invariants.js";

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

interface V0Options {
  transaction?: Buffer;
  global?: Buffer[];
  input?: Buffer[];
  output?: Buffer[];
  transactionFirst?: boolean;
}

function psbtV0(options: V0Options = {}): Buffer {
  const transaction = entry(0x00, options.transaction ?? unsignedTransaction());
  const extras = options.global ?? [];
  const globalEntries =
    options.transactionFirst === false ? [...extras, transaction] : [transaction, ...extras];
  return Buffer.concat([
    magic,
    map(...globalEntries),
    map(...(options.input ?? [])),
    map(...(options.output ?? [])),
  ]);
}

function psbtV2(modifiable?: number, outputScript = Buffer.from("51", "hex")): Buffer {
  const globalEntries = [
    entry(0x02, Buffer.from("02000000", "hex")),
    entry(0x04, Buffer.from([1])),
    entry(0x05, Buffer.from([1])),
    entry(0xfb, Buffer.from("02000000", "hex")),
  ];
  if (modifiable !== undefined) {
    globalEntries.splice(3, 0, entry(0x06, Buffer.from([modifiable])));
  }
  return Buffer.concat([
    magic,
    map(...globalEntries),
    map(
      entry(0x0e, Buffer.alloc(32, 0x22)),
      entry(0x0f, Buffer.from("03000000", "hex")),
      entry(0x10, Buffer.from("feffffff", "hex")),
    ),
    map(entry(0x03, Buffer.from("1027000000000000", "hex")), entry(0x04, outputScript)),
  ]);
}

function document(psbt: Buffer) {
  return parsePsbtDocument(psbt.toString("base64"));
}

describe("roundtrip policy", () => {
  test("accepts reordered entries without exact-byte equality", () => {
    const proprietary = entry(0xfc, Buffer.from("metadata"), Buffer.from("046c616201", "hex"));
    const before = document(psbtV0({ global: [proprietary] }));
    const after = document(psbtV0({ global: [proprietary], transactionFirst: false }));

    expect(assertPsbtTransition("roundtrip", before, after)).toEqual({
      ok: true,
      policy: "roundtrip",
      exactBytesEqual: false,
      failures: [],
    });
  });

  test("rejects dropped proprietary metadata with a stable sanitized failure", () => {
    const proprietary = entry(
      0xfc,
      Buffer.from("secret metadata"),
      Buffer.from("046c616201", "hex"),
    );
    const result = assertPsbtTransition(
      "roundtrip",
      document(psbtV0({ global: [proprietary] })),
      document(psbtV0()),
    );

    expect(result.ok).toBe(false);
    expect(result.failures[0]).toMatchObject({
      code: "ENTRY_REMOVED",
      location: { kind: "global" },
      keyType: 0xfc,
      before: { valueBytes: 15 },
    });
    expect(JSON.stringify(result)).not.toContain("secret metadata");
    expect(result.failures[0]).not.toHaveProperty("value");
    expect(result.failures[0]).not.toHaveProperty("completeKey");
  });

  test("rejects changed output metadata", () => {
    const keyData = Buffer.from("pubkey");
    const result = assertPsbtTransition(
      "roundtrip",
      document(psbtV0({ output: [entry(0x02, Buffer.from("old path"), keyData)] })),
      document(psbtV0({ output: [entry(0x02, Buffer.from("new path"), keyData)] })),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_CHANGED",
        location: { kind: "output", index: 0 },
        keyType: 0x02,
      }),
    );
  });
});

describe("sign policy", () => {
  test.each([0x02, 0x13, 0x14])("allows input signature type 0x%s to be added", (keyType) => {
    const keyData = keyType === 0x13 ? Buffer.alloc(0) : Buffer.from("signing key");
    const result = assertPsbtTransition(
      "sign",
      document(psbtV0()),
      document(psbtV0({ input: [entry(keyType, Buffer.from("signature"), keyData)] })),
    );

    expect(result).toMatchObject({ ok: true, exactBytesEqual: false, failures: [] });
  });

  test("rejects removal of an existing signature", () => {
    const signature = entry(0x02, Buffer.from("signature"), Buffer.from("pubkey"));
    const result = assertPsbtTransition(
      "sign",
      document(psbtV0({ input: [signature] })),
      document(psbtV0()),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_REMOVED",
        location: { kind: "input", index: 0 },
        keyType: 0x02,
      }),
    );
  });

  test("rejects non-signature additions", () => {
    const result = assertPsbtTransition(
      "sign",
      document(psbtV0()),
      document(psbtV0({ input: [entry(0x06, Buffer.from("derivation"), Buffer.from("pubkey"))] })),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_ADDED", keyType: 0x06 }),
    );
  });

  test("rejects changed transaction identity with a dedicated code", () => {
    const result = assertPsbtTransition(
      "sign",
      document(psbtV0()),
      document(psbtV0({ transaction: unsignedTransaction(Buffer.from("52", "hex")) })),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "TRANSACTION_IDENTITY_CHANGED",
        location: { kind: "global" },
        keyType: 0x00,
      }),
    );
  });

  test("allows only monotonic BIP370 transaction-modifiable changes", () => {
    const allowed = assertPsbtTransition("sign", document(psbtV2(0x03)), document(psbtV2(0x04)));
    const reversed = assertPsbtTransition("sign", document(psbtV2(0x04)), document(psbtV2(0x03)));
    const unknownBitChanged = assertPsbtTransition(
      "sign",
      document(psbtV2(0x08)),
      document(psbtV2(0x00)),
    );

    expect(allowed).toMatchObject({ ok: true, exactBytesEqual: false, failures: [] });
    expect(reversed.failures).toContainEqual(
      expect.objectContaining({ code: "TX_MODIFIABLE_INVALID_CHANGE", keyType: 0x06 }),
    );
    expect(unknownBitChanged.failures).toContainEqual(
      expect.objectContaining({ code: "TX_MODIFIABLE_INVALID_CHANGE", keyType: 0x06 }),
    );
  });

  test("rejects adding or removing transaction-modifiable policy state", () => {
    const added = assertPsbtTransition("sign", document(psbtV2()), document(psbtV2(0x00)));
    const removed = assertPsbtTransition("sign", document(psbtV2(0x00)), document(psbtV2()));

    expect(added.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_ADDED", keyType: 0x06 }),
    );
    expect(removed.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0x06 }),
    );
  });
});

describe("combine policy", () => {
  test("allows additions but rejects removal or mutation of existing entries", () => {
    const existing = entry(0xfc, Buffer.from("original"), Buffer.from("046c616201", "hex"));
    const added = entry(0x50, Buffer.from("new metadata"), Buffer.from("key"));

    expect(
      assertPsbtTransition(
        "combine",
        document(psbtV0({ input: [existing] })),
        document(psbtV0({ input: [existing, added] })),
      ).ok,
    ).toBe(true);
    expect(
      assertPsbtTransition(
        "combine",
        document(psbtV0({ input: [existing] })),
        document(psbtV0({ input: [] })),
      ).failures,
    ).toContainEqual(expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0xfc }));
    expect(
      assertPsbtTransition(
        "combine",
        document(psbtV0({ input: [existing] })),
        document(
          psbtV0({
            input: [entry(0xfc, Buffer.from("mutated"), Buffer.from("046c616201", "hex"))],
          }),
        ),
      ).failures,
    ).toContainEqual(expect.objectContaining({ code: "ENTRY_CHANGED", keyType: 0xfc }));
  });

  test("rejects transaction identity changes", () => {
    const result = assertPsbtTransition(
      "combine",
      document(psbtV2(0x03)),
      document(psbtV2(0x03, Buffer.from("52", "hex"))),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "TRANSACTION_IDENTITY_CHANGED",
        location: { kind: "output", index: 0 },
        keyType: 0x04,
      }),
    );
  });
});

describe("finalize policy", () => {
  test("allows final fields to replace temporary BIP174 and BIP371 signing fields", () => {
    const proprietary = entry(0xfc, Buffer.from("retain"), Buffer.from("046c616201", "hex"));
    const before = document(
      psbtV0({
        input: [
          proprietary,
          entry(0x02, Buffer.from("partial"), Buffer.from("pubkey")),
          entry(0x04, Buffer.from("redeem script")),
          entry(0x13, Buffer.from("tap signature")),
          entry(0x15, Buffer.from("tap leaf"), Buffer.from("control block")),
        ],
      }),
    );
    const after = document(
      psbtV0({ input: [proprietary, entry(0x07, Buffer.from("final scriptSig"))] }),
    );

    expect(assertPsbtTransition("finalize", before, after)).toMatchObject({
      ok: true,
      exactBytesEqual: false,
      failures: [],
    });
  });

  test("rejects removal of unknown input fields and changes to global or output metadata", () => {
    const unknown = entry(0x50, Buffer.from("retain"), Buffer.from("key"));
    const removed = assertPsbtTransition(
      "finalize",
      document(psbtV0({ input: [unknown] })),
      document(psbtV0()),
    );
    const changedGlobal = assertPsbtTransition(
      "finalize",
      document(psbtV0({ global: [entry(0xfc, Buffer.from("old"), Buffer.from("key"))] })),
      document(psbtV0({ global: [entry(0xfc, Buffer.from("new"), Buffer.from("key"))] })),
    );
    const changedOutput = assertPsbtTransition(
      "finalize",
      document(psbtV0({ output: [entry(0x02, Buffer.from("old"), Buffer.from("pubkey"))] })),
      document(psbtV0({ output: [entry(0x02, Buffer.from("new"), Buffer.from("pubkey"))] })),
    );

    expect(removed.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0x50 }),
    );
    expect(changedGlobal.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_CHANGED",
        location: { kind: "global" },
        keyType: 0xfc,
      }),
    );
    expect(changedOutput.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_CHANGED",
        location: { kind: "output", index: 0 },
        keyType: 0x02,
      }),
    );
  });

  test("rejects transaction identity changes", () => {
    const result = assertPsbtTransition(
      "finalize",
      document(psbtV2(0x03)),
      document(psbtV2(0x03, Buffer.from("52", "hex"))),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({ code: "TRANSACTION_IDENTITY_CHANGED", keyType: 0x04 }),
    );
  });
});
