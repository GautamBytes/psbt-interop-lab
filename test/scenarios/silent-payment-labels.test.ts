import { secp256k1 } from "@noble/curves/secp256k1.js";
import { expect, test } from "vitest";
import fixture from "../../adapters/rust-psbt-v2/tests/fixtures/labels.json" with { type: "json" };
import { FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { verifyMultiSender } from "../../src/scenarios/bip375-multi-verify.js";
import {
  createReceiverPsbt,
  discoverReceiverOutputs,
  labeledSpendKey,
  receiverLabelTweak,
} from "../../src/scenarios/silent-payment-receiver.js";

for (const v of fixture.variants) {
  test(`label 1 discovery, combined tweak and sender intent: shuffled=${v.shuffle}`, () => {
    const found = discoverReceiverOutputs(v.output.finalizedPsbt, 2n, undefined, 1);
    expect(found.map((o) => o.index)).toEqual(v.shuffle ? [1, 2] : [0, 1]);
    expect(createReceiverPsbt(v.output.transactionId, found)).toBe(v.child);
    for (const label of [undefined, 0, 2])
      expect(discoverReceiverOutputs(v.output.finalizedPsbt, 2n, undefined, label)).toEqual([]);
    const spend = labeledSpendKey(2n, FIXTURE_PUBLIC_KEYS.scalar1, 1);
    const raw = discoverReceiverOutputs(v.output.finalizedPsbt, 2n, spend);
    const order = secp256k1.Point.Fn.ORDER;
    expect(found.map((o) => o.tweakHex)).toEqual(
      raw.map((o) =>
        ((BigInt(`0x${o.tweakHex}`) + receiverLabelTweak(2n, 1)) % order)
          .toString(16)
          .padStart(64, "0"),
      ),
    );
    expect(
      verifyMultiSender(fixture.template, v.output.psbt, "per-input", false, v.shuffle, true),
    ).toBe(true);
    expect(verifyMultiSender(fixture.template, v.output.psbt, "per-input", false, v.shuffle)).toBe(
      false,
    );
    const changed = applyPsbtMutations(v.output.psbt, [
      {
        kind: "replace-value",
        location: { kind: "output", index: v.shuffle ? 1 : 0 },
        keyType: 9,
        valueHex: FIXTURE_PUBLIC_KEYS.scalar2 + labeledSpendKey(2n, FIXTURE_PUBLIC_KEYS.scalar1, 2),
      },
    ]);
    expect(verifyMultiSender(fixture.template, changed, "per-input", false, v.shuffle, true)).toBe(
      false,
    );
  });
  test(`discovery needs no sender recipient or share metadata: shuffled=${v.shuffle}`, () => {
    const doc = parsePsbtDocument(v.output.finalizedPsbt);
    const stripped = applyPsbtMutations(
      v.output.finalizedPsbt,
      doc.maps.flatMap((m) =>
        m.entries
          .filter(
            (e) =>
              (m.location.kind === "input" && [29, 30].includes(e.keyType)) ||
              (m.location.kind === "output" && [9, 10].includes(e.keyType)),
          )
          .map((e) => ({
            kind: "delete-entry" as const,
            location: m.location,
            keyType: e.keyType,
            keyDataHex: e.keyData.toString("hex"),
          })),
      ),
    );
    expect(discoverReceiverOutputs(stripped, 2n, undefined, 1)).toEqual(
      discoverReceiverOutputs(v.output.finalizedPsbt, 2n, undefined, 1),
    );
  });
}

test("rejects invalid label indexes and scan scalars", () => {
  for (const label of [-1, 1.5, 2 ** 32, NaN])
    expect(() => receiverLabelTweak(2n, label)).toThrow();
  for (const scan of [0n, -1n, secp256k1.Point.Fn.ORDER])
    expect(() => receiverLabelTweak(scan, 1)).toThrow();
});
