import { describe, expect, test } from "vitest";
import { BIP370_INVALID_VECTORS, BIP370_VALID_VECTORS } from "../../src/psbt/bip370-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";

describe("official BIP370 vectors", () => {
  test("ships the complete official parse corpus", () => {
    expect(BIP370_VALID_VECTORS).toHaveLength(14);
    expect(BIP370_INVALID_VECTORS).toHaveLength(21);
  });

  test.each(BIP370_VALID_VECTORS)("accepts valid vector $id", ({ base64 }) => {
    expect(parsePsbtDocument(base64)).toMatchObject({ psbtVersion: 2 });
  });

  test.each(BIP370_INVALID_VECTORS)("rejects invalid vector $id", ({ base64 }) => {
    expect(() => parsePsbtDocument(base64.trim())).toThrow();
  });
});
