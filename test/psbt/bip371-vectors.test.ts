import { describe, expect, test } from "vitest";
import {
  BIP371_CORPUS_SHA256,
  BIP371_INVALID_VECTORS,
  BIP371_SOURCE_SHA256,
  BIP371_VALID_VECTORS,
} from "../../src/psbt/bip371-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";

describe("official BIP371 vectors", () => {
  test("ships the complete upstream corpus", () => {
    expect(BIP371_VALID_VECTORS).toHaveLength(6);
    expect(BIP371_INVALID_VECTORS).toHaveLength(11);
    expect(BIP371_SOURCE_SHA256).toBe(
      "f7bde92b1de04c0286c678930dd11fdafbfaa7e72767038e44e12fd4d4b31091",
    );
    expect(BIP371_CORPUS_SHA256).toBe(
      "6afe6b443edc7eeab2d424b743d048fc9493bd4728910bc199ca9837433a57a0",
    );
    expect([...BIP371_VALID_VECTORS, ...BIP371_INVALID_VECTORS].map(({ id }) => id)).toEqual([
      "valid-01",
      "valid-02",
      "valid-03",
      "valid-04",
      "valid-05",
      "valid-06",
      "invalid-01",
      "invalid-02",
      "invalid-03",
      "invalid-04",
      "invalid-05",
      "invalid-06",
      "invalid-07",
      "invalid-08",
      "invalid-09",
      "invalid-10",
      "invalid-11",
    ]);
  });

  test.each(BIP371_VALID_VECTORS)("accepts valid vector $id", ({ base64 }) => {
    expect(Buffer.from(base64, "base64").subarray(0, 5).toString("hex")).toBe("70736274ff");
    expect(parsePsbtDocument(base64)).toMatchObject({ psbtVersion: 0 });
  });

  test.each(BIP371_INVALID_VECTORS)("rejects invalid vector $id", ({ base64 }) => {
    expect(() => parsePsbtDocument(base64)).toThrow();
  });
});
