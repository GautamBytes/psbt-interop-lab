import { describe, expect, test } from "vitest";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { assertPsbtTransition } from "../../src/psbt/invariants.js";

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

const proprietaryKeyData = Buffer.from("036c616201", "hex");
const taprootInternalKey = Buffer.from(
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);

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
    const proprietary = entry(0xfc, Buffer.from("metadata"), proprietaryKeyData);
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
    const proprietary = entry(0xfc, Buffer.from("secret metadata"), proprietaryKeyData);
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
      field: {
        symbol: "PSBT_GLOBAL_PROPRIETARY",
        displayName: "Proprietary global field",
        bip: "BIP174",
        kind: "proprietary",
      },
      guidance: {
        code: "RESTORE_EXTENSION_METADATA",
        severity: "stop",
      },
      before: { valueBytes: 15 },
    });
    expect(JSON.stringify(result)).not.toContain("secret metadata");
    expect(result.failures[0]).not.toHaveProperty("value");
    expect(result.failures[0]).not.toHaveProperty("completeKey");
  });

  test("rejects changed output metadata", () => {
    const keyData = compressedPubkey();
    const result = assertPsbtTransition(
      "roundtrip",
      document(psbtV0({ output: [entry(0x02, Buffer.alloc(4, 0x01), keyData)] })),
      document(psbtV0({ output: [entry(0x02, Buffer.alloc(4, 0x02), keyData)] })),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_CHANGED",
        location: { kind: "output", index: 0 },
        keyType: 0x02,
      }),
    );
  });

  test("accepts only the BIP370 omitted-to-zero transaction-modifiable normalization", () => {
    const addedDefault = assertPsbtTransition(
      "roundtrip",
      document(psbtV2()),
      document(psbtV2(0x00)),
    );
    const removedDefault = assertPsbtTransition(
      "roundtrip",
      document(psbtV2(0x00)),
      document(psbtV2()),
    );
    const addedPermission = assertPsbtTransition(
      "roundtrip",
      document(psbtV2()),
      document(psbtV2(0x01)),
    );
    const removedPermission = assertPsbtTransition(
      "roundtrip",
      document(psbtV2(0x01)),
      document(psbtV2()),
    );

    expect(addedDefault).toMatchObject({ ok: true, exactBytesEqual: false, failures: [] });
    expect(removedDefault).toMatchObject({ ok: true, exactBytesEqual: false, failures: [] });
    expect(addedPermission.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_ADDED", keyType: 0x06 }),
    );
    expect(removedPermission.failures).toContainEqual(
      expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0x06 }),
    );
  });
});

describe("sign policy", () => {
  test.each([0x02, 0x13, 0x14])("allows input signature type 0x%s to be added", (keyType) => {
    const keyData =
      keyType === 0x02
        ? compressedPubkey()
        : keyType === 0x14
          ? Buffer.alloc(64, 0x03)
          : Buffer.alloc(0);
    const signature = keyType === 0x02 ? Buffer.from("signature") : Buffer.alloc(64, 0x04);
    const result = assertPsbtTransition(
      "sign",
      document(psbtV0()),
      document(psbtV0({ input: [entry(keyType, signature, keyData)] })),
    );

    expect(result).toMatchObject({ ok: true, exactBytesEqual: false, failures: [] });
  });

  test("rejects removal of an existing signature", () => {
    const signature = entry(0x02, Buffer.from("signature"), compressedPubkey());
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
      document(psbtV0({ input: [entry(0x06, Buffer.alloc(4), compressedPubkey())] })),
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
        field: expect.objectContaining({
          symbol: "PSBT_GLOBAL_UNSIGNED_TX",
          displayName: "Unsigned transaction",
          bip: "BIP174",
        }),
        guidance: {
          code: "TRANSACTION_INTENT_CHANGED",
          severity: "stop",
          summary: "The transaction being authorized changed during the sign transition.",
          nextSteps: [
            "Do not sign or broadcast the changed PSBT.",
            "Return to the previous checkpoint and verify recipients, amounts, inputs, sequences, and locktime.",
            "Recreate the PSBT from the original transaction intent before retrying the handoff.",
          ],
        },
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

  test("allows omitted-zero normalization and monotonic removal of modifiable permissions", () => {
    const added = assertPsbtTransition("sign", document(psbtV2()), document(psbtV2(0x00)));
    const tightened = assertPsbtTransition("sign", document(psbtV2(0x03)), document(psbtV2()));
    const invalidAdded = assertPsbtTransition("sign", document(psbtV2()), document(psbtV2(0x01)));
    const invalidRemoval = assertPsbtTransition("sign", document(psbtV2(0x04)), document(psbtV2()));

    expect(added).toMatchObject({ ok: true, failures: [] });
    expect(tightened).toMatchObject({ ok: true, failures: [] });
    expect(invalidAdded.failures).toContainEqual(
      expect.objectContaining({ code: "TX_MODIFIABLE_INVALID_CHANGE", keyType: 0x06 }),
    );
    expect(invalidRemoval.failures).toContainEqual(
      expect.objectContaining({ code: "TX_MODIFIABLE_INVALID_CHANGE", keyType: 0x06 }),
    );
  });
});

describe("combine policy", () => {
  test("allows additions but rejects removal or mutation of existing entries", () => {
    const existing = entry(0xfc, Buffer.from("original"), proprietaryKeyData);
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
            input: [entry(0xfc, Buffer.from("mutated"), proprietaryKeyData)],
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
  test("allows an omitted transaction-modifiable zero to be serialized explicitly", () => {
    expect(
      assertPsbtTransition("finalize", document(psbtV2()), document(psbtV2(0x00))),
    ).toMatchObject({ ok: true, failures: [] });
  });

  test("allows final fields to replace temporary BIP174 and BIP371 signing fields", () => {
    const proprietary = entry(0xfc, Buffer.from("retain"), proprietaryKeyData);
    const before = document(
      psbtV0({
        input: [
          proprietary,
          entry(0x02, Buffer.from("partial"), compressedPubkey()),
          entry(0x04, Buffer.from("redeem script")),
          entry(0x13, Buffer.alloc(64, 0x05)),
          entry(
            0x15,
            Buffer.from([0x51, 0xc0]),
            Buffer.concat([Buffer.from([0xc0]), taprootInternalKey]),
          ),
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

  test("allows Taproot output derivation cleanup after every input has final script data", () => {
    const outputDerivation = entry(
      0x07,
      Buffer.from("0000000000", "hex"),
      taprootInternalKey,
    );
    const result = assertPsbtTransition(
      "finalize",
      document(psbtV0({ output: [outputDerivation] })),
      document(psbtV0({ input: [entry(0x08, Buffer.from("0100", "hex"))] })),
    );

    expect(result).toMatchObject({ ok: true, failures: [] });
  });

  test("rejects Taproot output derivation cleanup before final script data exists", () => {
    const outputDerivation = entry(
      0x07,
      Buffer.from("0000000000", "hex"),
      taprootInternalKey,
    );
    const result = assertPsbtTransition(
      "finalize",
      document(psbtV0({ output: [outputDerivation] })),
      document(psbtV0()),
    );

    expect(result.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_REMOVED",
        location: { kind: "output", index: 0 },
        keyType: 0x07,
      }),
    );
  });

  test.each(["roundtrip", "sign"] as const)(
    "rejects Taproot output derivation cleanup during %s",
    (policy) => {
      const outputDerivation = entry(
        0x07,
        Buffer.from("0000000000", "hex"),
        taprootInternalKey,
      );
      const result = assertPsbtTransition(
        policy,
        document(psbtV0({ output: [outputDerivation] })),
        document(psbtV0({ input: [entry(0x08, Buffer.from("0100", "hex"))] })),
      );

      expect(result.failures).toContainEqual(
        expect.objectContaining({
          code: "ENTRY_REMOVED",
          location: { kind: "output", index: 0 },
          keyType: 0x07,
        }),
      );
    },
  );

  test("rejects removal of unknown input fields and changes to global or output metadata", () => {
    const unknown = entry(0x50, Buffer.from("retain"), Buffer.from("key"));
    const removed = assertPsbtTransition(
      "finalize",
      document(psbtV0({ input: [unknown] })),
      document(psbtV0()),
    );
    const changedGlobal = assertPsbtTransition(
      "finalize",
      document(psbtV0({ global: [entry(0xfc, Buffer.from("old"), proprietaryKeyData)] })),
      document(psbtV0({ global: [entry(0xfc, Buffer.from("new"), proprietaryKeyData)] })),
    );
    const changedOutput = assertPsbtTransition(
      "finalize",
      document(psbtV0({ output: [entry(0x02, Buffer.alloc(4, 0x01), compressedPubkey())] })),
      document(psbtV0({ output: [entry(0x02, Buffer.alloc(4, 0x02), compressedPubkey())] })),
    );

    expect(removed.failures).toContainEqual(
      expect.objectContaining({
        code: "ENTRY_REMOVED",
        keyType: 0x50,
        field: {
          scope: "input",
          keyType: 0x50,
          keyTypeHex: "0x50",
          symbol: "PSBT_IN_UNKNOWN",
          displayName: "Unknown input field",
          kind: "unknown",
        },
        guidance: expect.objectContaining({
          code: "RESTORE_EXTENSION_METADATA",
          severity: "stop",
        }),
      }),
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
