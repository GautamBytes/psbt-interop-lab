import { describe, expect, test } from "vitest";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../../src/psbt/mutation.js";
import {
  verifyMultiSender,
  verifyMultiWitnesses,
} from "../../src/scenarios/bip375-multi-verify.js";
import fixture from "../fixtures/bip375-multi-sender.json" with { type: "json" };

describe("funded multi-input independent evidence", () => {
  for (const variant of fixture.variants) {
    test(`${variant.mode} / reverse=${variant.reverse} verifies derivation, intent and both witnesses`, () => {
      expect(
        verifyMultiSender(fixture.template, variant.output.psbt, variant.mode, variant.reverse),
      ).toBe(true);
      expect(verifyMultiWitnesses(variant.output.psbt, variant.output.finalizedPsbt)).toBe(true);
    });
    test(`${variant.mode} / reverse=${variant.reverse} rejects missing or corrupt shares and proofs`, () => {
      const doc = parsePsbtDocument(variant.output.psbt);
      const maps = doc.maps.filter(
        ({ location }) => location.kind === (variant.mode === "global" ? "global" : "input"),
      );
      for (const map of maps)
        for (const entry of map.entries.filter(({ keyType }) =>
          (variant.mode === "global" ? [7, 8] : [29, 30]).includes(keyType),
        )) {
          for (const kind of ["delete-entry", "replace-value"] as const) {
            const changed = applyPsbtMutations(variant.output.psbt, [
              {
                location: map.location,
                keyType: entry.keyType,
                keyDataHex: entry.keyData.toString("hex"),
                ...(kind === "replace-value"
                  ? { kind, valueHex: "00".repeat(entry.value.length) }
                  : { kind }),
              },
            ]);
            expect(
              verifyMultiSender(fixture.template, changed, variant.mode, variant.reverse),
            ).toBe(false);
          }
        }
    });
    test(`${variant.mode} / reverse=${variant.reverse} rejects changed intent or the wrong permutation`, () => {
      expect(
        verifyMultiSender(fixture.template, variant.output.psbt, variant.mode, !variant.reverse),
      ).toBe(false);
      const changes: PsbtMutationRecipe[] = [
        {
          kind: "replace-value",
          location: { kind: "output", index: 1 },
          keyType: 4,
          valueHex: `0014${"00".repeat(20)}`,
        },
        {
          kind: "replace-value",
          location: { kind: "output", index: 1 },
          keyType: 3,
          valueHex: "0100000000000000",
        },
        {
          kind: "replace-value",
          location: { kind: "output", index: 0 },
          keyType: 3,
          valueHex: "0100000000000000",
        },
        {
          kind: "replace-value",
          location: { kind: "output", index: 0 },
          keyType: 9,
          valueHex: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".repeat(2),
        },
        {
          kind: "replace-value",
          location: { kind: "input", index: 1 },
          keyType: 15,
          valueHex: "01000000",
        },
      ];
      for (const mutation of changes)
        expect(
          verifyMultiSender(
            fixture.template,
            applyPsbtMutations(variant.output.psbt, [mutation]),
            variant.mode,
            variant.reverse,
          ),
        ).toBe(false);
      const signed = parsePsbtDocument(variant.output.psbt);
      for (const map of signed.maps.filter(({ location }) => location.kind === "input")) {
        const sig = map.entries.find(({ keyType }) => keyType === 2);
        if (!sig) throw new Error("Fixture lacks input signature");
        const changed = applyPsbtMutations(variant.output.psbt, [
          {
            kind: "delete-entry",
            location: map.location,
            keyType: 2,
            keyDataHex: sig.keyData.toString("hex"),
          },
        ]);
        expect(verifyMultiSender(fixture.template, changed, variant.mode, variant.reverse)).toBe(
          false,
        );
        expect(verifyMultiWitnesses(changed, variant.output.finalizedPsbt)).toBe(false);
        const value = Buffer.from(sig.value);
        value[10] = (value[10] ?? 0) ^ 1;
        const mismatched = applyPsbtMutations(variant.output.psbt, [
          {
            kind: "replace-value",
            location: map.location,
            keyType: 2,
            keyDataHex: sig.keyData.toString("hex"),
            valueHex: value.toString("hex"),
          },
        ]);
        expect(verifyMultiWitnesses(mismatched, variant.output.finalizedPsbt)).toBe(false);
      }
    });
  }
});
