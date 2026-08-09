import { describe, expect, test } from "vitest";
import {
  type Bip375FailureClass,
  classifyBip375ReferencePsbt,
} from "../../src/psbt/bip375-validator.js";
import { BIP375_INVALID_VECTORS, BIP375_VALID_VECTORS } from "../../src/psbt/bip375-vectors.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";

const expected = new Map<string, Bip375FailureClass>([
  ["invalid-11", "silent_payment.invalid_dleq"],
  ["invalid-16", "silent_payment.incomplete_coverage"],
  ["invalid-18", "silent_payment.sighash_not_allowed"],
  ["invalid-20", "silent_payment.output_script_mismatch"],
  ["invalid-21", "silent_payment.output_order_mismatch"],
]);

describe("BIP375 failure classification", () => {
  test("maps official advanced-workflow canaries to stable developer-facing classes", () => {
    for (const [id, failureClass] of expected) {
      const vector = BIP375_INVALID_VECTORS.find((candidate) => candidate.id === id);
      if (!vector) throw new Error(`Missing official vector ${id}`);
      expect(classifyBip375ReferencePsbt(vector.base64), id).toMatchObject({
        valid: false,
        class: failureClass,
      });
    }
  });

  test("does not mistake an arbitrary script corruption for a k-ordering failure", () => {
    const vector = BIP375_VALID_VECTORS.find(({ id }) => id === "valid-09");
    if (!vector) throw new Error("Missing official vector valid-09");
    const corrupted = applyPsbtMutations(vector.base64, [
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 0x04,
        valueHex: `5120${"00".repeat(32)}`,
      },
    ]);

    expect(classifyBip375ReferencePsbt(corrupted)).toMatchObject({
      valid: false,
      class: "silent_payment.output_script_mismatch",
    });
  });
});
