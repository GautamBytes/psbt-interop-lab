import { describe, expect, test } from "vitest";
import { validateBip375ReferencePsbt } from "../../src/psbt/bip375-validator.js";
import {
  BIP375_CORPUS_SHA256,
  BIP375_INVALID_VECTORS,
  BIP375_SOURCE_SHA256,
  BIP375_VALID_VECTORS,
  BIP375_VECTOR_VERSION,
} from "../../src/psbt/bip375-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";

function bip32Derivation(encoded: string, inputIndex: number) {
  const input = parsePsbtDocument(encoded).maps.find(
    ({ location }) => location.kind === "input" && location.index === inputIndex,
  );
  const derivation = input?.entries.find(({ keyType }) => keyType === 0x06);
  if (!derivation) throw new Error(`Vector input ${inputIndex} has no BIP32 derivation`);
  return derivation;
}

describe("official BIP375 vectors", () => {
  test("ships the complete pinned upstream corpus", () => {
    expect(BIP375_VECTOR_VERSION).toBe("1.1");
    expect(BIP375_VALID_VECTORS).toHaveLength(19);
    expect(BIP375_INVALID_VECTORS).toHaveLength(22);
    expect(BIP375_SOURCE_SHA256).toBe(
      "879b8c6177f8af710ad881c743cb268b5b1d9ee2d32438df6c4109532743cd15",
    );
    expect(BIP375_CORPUS_SHA256).toBe(
      "8eb14ccf424f8a105c3c68deb196072eee3e44e57c31e6ee863c2412683e8901",
    );
    expect([...BIP375_VALID_VECTORS, ...BIP375_INVALID_VECTORS].map(({ id }) => id)).toEqual([
      ...Array.from({ length: 19 }, (_, index) => `valid-${String(index + 1).padStart(2, "0")}`),
      ...Array.from({ length: 22 }, (_, index) => `invalid-${String(index + 1).padStart(2, "0")}`),
    ]);
  });

  test.each(BIP375_VALID_VECTORS)("accepts valid vector $id: $title", ({ base64 }) => {
    expect(validateBip375ReferencePsbt(base64)).toEqual({ valid: true });
  });

  test.each(BIP375_INVALID_VECTORS)(
    "rejects invalid vector $id at $expectedStage",
    ({ base64, expectedStage }) => {
      const result = validateBip375ReferencePsbt(base64);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.stage).toBe(expectedStage);
        expect(result.message.length).toBeGreaterThan(0);
      }
    },
  );

  test("rejects a global share when an eligible input has no recoverable public key", () => {
    const vector = BIP375_VALID_VECTORS[1];
    if (!vector) throw new Error("Missing valid BIP375 global-share vector");
    const derivation = bip32Derivation(vector.base64, 1);
    const incomplete = applyPsbtMutations(vector.base64, [
      {
        kind: "delete-entry",
        location: { kind: "input", index: 1 },
        keyType: 0x06,
        keyDataHex: derivation.keyData.toString("hex"),
      },
    ]);

    expect(validateBip375ReferencePsbt(incomplete)).toMatchObject({
      valid: false,
      stage: "ecdh coverage",
      message: "Eligible input 1 has no recoverable public key",
    });
  });

  test("does not classify a non-witness script beginning with OP_2 as SegWit v2", () => {
    const vector = BIP375_VALID_VECTORS[15];
    if (!vector) throw new Error("Missing valid in-progress BIP375 vector");
    const nonWitnessProgram = applyPsbtMutations(vector.base64, [
      {
        kind: "replace-value",
        location: { kind: "input", index: 0 },
        keyType: 0x01,
        valueHex: `000000000000000003520100`,
      },
    ]);

    expect(validateBip375ReferencePsbt(nonWitnessProgram)).toEqual({ valid: true });
  });
});
