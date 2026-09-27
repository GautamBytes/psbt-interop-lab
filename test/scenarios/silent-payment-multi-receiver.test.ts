import { expect, test } from "vitest";
import fixture from "../../adapters/rust-psbt-v2/tests/fixtures/multi-receiver.json" with {
  type: "json",
};
import { FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { verifyMultiSender } from "../../src/scenarios/bip375-multi-verify.js";
import {
  createReceiverPsbt,
  discoverReceiverOutputs,
} from "../../src/scenarios/silent-payment-receiver.js";

for (const variant of fixture.variants) {
  test(`two receivers discover only their own outputs: shuffled=${variant.shuffle}`, () => {
    const alice = discoverReceiverOutputs(variant.output.finalizedPsbt);
    const bob = discoverReceiverOutputs(
      variant.output.finalizedPsbt,
      3n,
      FIXTURE_PUBLIC_KEYS.scalar2,
    );
    expect(alice.map((o) => o.index)).toEqual(variant.shuffle ? [1, 3] : [0, 2]);
    expect(bob.map((o) => o.index)).toEqual([variant.shuffle ? 2 : 1]);
    expect(alice.reduce((n, o) => n + o.amountSats, 0n)).toBe(96_000n);
    expect(bob[0]?.amountSats).toBe(48_000n);
    expect(new Set([...alice, ...bob].map((o) => o.scriptHex)).size).toBe(3);
    expect(
      discoverReceiverOutputs(variant.output.finalizedPsbt, 3n, FIXTURE_PUBLIC_KEYS.scalar1),
    ).toEqual([]);
    expect(
      discoverReceiverOutputs(variant.output.finalizedPsbt, 2n, FIXTURE_PUBLIC_KEYS.scalar2),
    ).toEqual([]);
    const child = parsePsbtDocument(createReceiverPsbt(variant.output.transactionId, bob, 1));
    expect(child.inputCount).toBe(1);
    expect(
      child.maps
        .find((m) => m.location.kind === "input")
        ?.entries.find((e) => e.keyType === 0x1f)
        ?.keyData.toString("hex"),
    ).toBe(FIXTURE_PUBLIC_KEYS.scalar2);
    expect(
      child.maps
        .find((m) => m.location.kind === "output")
        ?.entries.find((e) => e.keyType === 3)
        ?.value.readBigUInt64LE(),
    ).toBe(38_000n);
  });
}

for (const variant of fixture.variants) {
  test(`verifies both recipient identities and their ECDH proofs: shuffled=${variant.shuffle}`, () => {
    const verify = (psbt: string) =>
      verifyMultiSender(fixture.template, psbt, "per-input", false, variant.shuffle);
    expect(verify(variant.output.psbt)).toBe(true);
    expect(
      verifyMultiSender(
        fixture.template,
        variant.output.psbt,
        "per-input",
        false,
        !variant.shuffle,
      ),
    ).toBe(false);
    const bobIndex = variant.shuffle ? 2 : 1;
    expect(
      verify(
        applyPsbtMutations(variant.output.psbt, [
          {
            kind: "replace-value",
            location: { kind: "output", index: bobIndex },
            keyType: 9,
            valueHex: FIXTURE_PUBLIC_KEYS.scalar2 + FIXTURE_PUBLIC_KEYS.scalar1,
          },
        ]),
      ),
    ).toBe(false);
    expect(
      verify(
        applyPsbtMutations(variant.output.psbt, [
          {
            kind: "delete-entry",
            location: { kind: "input", index: 0 },
            keyType: 30,
            keyDataHex: FIXTURE_PUBLIC_KEYS.scalar3,
          },
        ]),
      ),
    ).toBe(false);
    expect(
      verify(
        applyPsbtMutations(variant.output.psbt, [
          {
            kind: "replace-value",
            location: { kind: "output", index: variant.shuffle ? 0 : 3 },
            keyType: 3,
            valueHex: "0100000000000000",
          },
        ]),
      ),
    ).toBe(false);
  });
}
