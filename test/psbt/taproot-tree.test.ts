import { describe, expect, test } from "vitest";
import { taprootTreeMerkleRoot } from "../../src/psbt/taproot-tree.js";

const leafOne = Buffer.from("01c00151", "hex");
const leafTwo = Buffer.from("01c00152", "hex");

describe("Taproot tree commitments", () => {
  test("treats swapped sibling leaves as the same BIP341 commitment", () => {
    const forward = Buffer.concat([leafOne, leafTwo]);
    const reversed = Buffer.concat([leafTwo, leafOne]);

    expect(forward.equals(reversed)).toBe(false);
    expect(taprootTreeMerkleRoot(forward)).toBe(taprootTreeMerkleRoot(reversed));
  });

  test("distinguishes a changed leaf script", () => {
    const original = Buffer.concat([leafOne, leafTwo]);
    const changed = Buffer.concat([leafOne, Buffer.from("01c00153", "hex")]);

    expect(taprootTreeMerkleRoot(original)).not.toBe(taprootTreeMerkleRoot(changed));
  });

  test.each([
    Buffer.alloc(0),
    Buffer.from("01c00251", "hex"),
    Buffer.from("00c0015100c00152", "hex"),
  ])("rejects malformed serialized trees", (tree) => {
    expect(() => taprootTreeMerkleRoot(tree)).toThrow();
  });
});
