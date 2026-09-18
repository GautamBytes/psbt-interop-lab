import { expect, test } from "vitest";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import {
  createReceiverPsbt,
  discoverReceiverOutput,
} from "../../src/scenarios/silent-payment-receiver.js";
import fixture from "../fixtures/bip375-multi-sender.json" with { type: "json" };

const first = fixture.variants[0];
if (!first) throw new Error("Missing sender fixture");
for (const variant of fixture.variants) {
  test(`discovers the actual recipient from ${variant.mode}, reverse=${variant.reverse}`, () => {
    const found = discoverReceiverOutput(variant.output.finalizedPsbt);
    expect(found).toMatchObject({
      index: 0,
      amountSats: 94_000n,
      scriptHex: variant.output.outputScript,
    });
    expect(found?.tweakHex).toMatch(/^[0-9a-f]{64}$/);
  });
  test(`discovery ignores sender share, proof and recipient metadata: ${variant.mode}/${variant.reverse}`, () => {
    const parent = variant.output.finalizedPsbt;
    const stripped = applyPsbtMutations(
      parent,
      parsePsbtDocument(parent).maps.flatMap((map) =>
        map.entries
          .filter(
            (e) =>
              (map.location.kind === "global" && [7, 8].includes(e.keyType)) ||
              (map.location.kind === "input" && [29, 30].includes(e.keyType)) ||
              (map.location.kind === "output" && [9, 10].includes(e.keyType)),
          )
          .map((e) => ({
            kind: "delete-entry" as const,
            location: map.location,
            keyType: e.keyType,
            keyDataHex: e.keyData.toString("hex"),
          })),
      ),
    );
    expect(discoverReceiverOutput(stripped)).toEqual(discoverReceiverOutput(parent));
    expect(discoverReceiverOutput(parent, 3n)).toBeUndefined();
    expect(
      discoverReceiverOutput(
        parent,
        2n,
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      ),
    ).toBeUndefined();
    const unrelated = applyPsbtMutations(parent, [
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 4,
        valueHex: `5120${"11".repeat(32)}`,
      },
    ]);
    expect(discoverReceiverOutput(unrelated)).toBeUndefined();
  });
}
test("builds a BIP376 child spending the discovered outpoint and preserving its exact amount", () => {
  const variant = first;
  const found = discoverReceiverOutput(variant.output.finalizedPsbt);
  if (!found) throw new Error("Receiver output was not discovered");
  const child = parsePsbtDocument(createReceiverPsbt(variant.output.transactionId, found));
  expect(child.inputCount).toBe(1);
  expect(child.outputCount).toBe(1);
  const input = child.maps.find((m) => m.location.kind === "input");
  if (!input) throw new Error("Missing receiver input");
  expect(input.entries.find((e) => e.keyType === 14)?.value.toString("hex")).toBe(
    Buffer.from(variant.output.transactionId, "hex").reverse().toString("hex"),
  );
  expect(input.entries.find((e) => e.keyType === 0x20)?.value.toString("hex")).toBe(found.tweakHex);
  const output = child.maps.find((m) => m.location.kind === "output");
  if (!output) throw new Error("Missing receiver output");
  expect(output.entries.find((e) => e.keyType === 3)?.value.readBigUInt64LE()).toBe(84_000n);
});
test("refuses invalid scan keys and non-P2WPKH input evidence", () => {
  expect(() => discoverReceiverOutput(first.output.finalizedPsbt, 0n)).toThrow();
  const missing = applyPsbtMutations(first.output.finalizedPsbt, [
    { kind: "delete-entry", location: { kind: "input", index: 1 }, keyType: 8 },
  ]);
  expect(() => discoverReceiverOutput(missing)).toThrow();
});
