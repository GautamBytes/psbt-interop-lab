import { describe, expect, test } from "vitest";
import { PsbtDocumentError, parsePsbtDocument } from "../../src/psbt/document.js";
import {
  applyPsbtMutations,
  generateBoundedMutations,
  type PsbtMutationRecipe,
  serializePsbtDocument,
} from "../../src/psbt/mutation.js";

// Published BIP370 required-fields-only PSBTv2 vector.
const PSBT =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";

describe("PSBT mutation recipes", () => {
  test("serializes a parsed document without changing its bytes", () => {
    const document = parsePsbtDocument(PSBT);

    expect(serializePsbtDocument(document).toString("base64")).toBe(PSBT);
  });

  test("replaces, inserts, and deletes map entries without mutating the source", () => {
    const recipes: PsbtMutationRecipe[] = [
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 0x04,
        valueHex: "51",
      },
      {
        kind: "set-entry",
        location: { kind: "global" },
        keyType: 0xfc,
        keyDataHex: "036c616201",
        valueHex: "64656c657465",
      },
      {
        kind: "set-entry",
        location: { kind: "global" },
        keyType: 0xfc,
        keyDataHex: "036c616202",
        valueHex: "70726f6265",
      },
      {
        kind: "delete-entry",
        location: { kind: "global" },
        keyType: 0xfc,
        keyDataHex: "036c616201",
      },
    ];

    const mutated = applyPsbtMutations(PSBT, recipes);
    const document = parsePsbtDocument(mutated);

    expect(
      parsePsbtDocument(PSBT).maps[2]?.entries.find((entry) => entry.keyType === 0x04)?.value,
    ).not.toEqual(Buffer.from("51", "hex"));
    expect(document.maps[2]?.entries.find((entry) => entry.keyType === 0x04)?.value).toEqual(
      Buffer.from("51", "hex"),
    );
    expect(
      document.maps[0]?.entries.find((entry) =>
        entry.keyData.equals(Buffer.from("036c616202", "hex")),
      )?.value,
    ).toEqual(Buffer.from("probe"));
    expect(
      document.maps[0]?.entries.some((entry) =>
        entry.keyData.equals(Buffer.from("036c616201", "hex")),
      ),
    ).toBe(false);
  });

  test("can deliberately create a duplicate key for parser probes", () => {
    const mutated = applyPsbtMutations(PSBT, [
      {
        kind: "duplicate-entry",
        location: { kind: "global" },
        keyType: 0xfb,
      },
    ]);

    expect(() => parsePsbtDocument(mutated)).toThrow(PsbtDocumentError);
  });

  test("generates bounded deterministic cases from a seed", () => {
    const first = generateBoundedMutations(PSBT, 42, 16);
    const second = generateBoundedMutations(PSBT, 42, 16);
    const different = generateBoundedMutations(PSBT, 43, 16);

    expect(first).toEqual(second);
    expect(first).toHaveLength(16);
    expect(first.map((item) => item.mutatedPsbt)).not.toEqual(
      different.map((item) => item.mutatedPsbt),
    );
    expect(() => generateBoundedMutations(PSBT, 42, 0)).toThrow(/between 1 and 512/);
    expect(() => generateBoundedMutations(PSBT, 42, 513)).toThrow(/between 1 and 512/);
  });
});
