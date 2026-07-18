import { describe, expect, test } from "vitest";
import { distinctMultisigContributionEvidence } from "../../src/scenarios/psbtv2-interop.js";

const magic = Buffer.from("70736274ff", "hex");
const publicKeyOne = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
const publicKeyTwo = Buffer.from(
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "hex",
);

function entry(keyType: number, value: Uint8Array, keyData: Uint8Array = Buffer.alloc(0)): Buffer {
  const valueBytes = Buffer.from(value);
  const key = Buffer.concat([Buffer.from([keyType]), Buffer.from(keyData)]);
  return Buffer.concat([
    Buffer.from([key.length]),
    key,
    Buffer.from([valueBytes.length]),
    valueBytes,
  ]);
}

function map(entries: readonly Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(): Buffer {
  return Buffer.concat([
    Buffer.from("0200000001", "hex"),
    Buffer.alloc(32, 1),
    Buffer.from("0000000000fdffffff01", "hex"),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
}

function psbt(signatureKeys: readonly Uint8Array[]): string {
  const signatures = signatureKeys.map((key, index) =>
    entry(0x02, Buffer.alloc(71, index + 1), key),
  );
  return Buffer.concat([
    magic,
    map([entry(0x00, unsignedTransaction())]),
    map(signatures),
    map([]),
  ]).toString("base64");
}

describe("PSBTv2 multisig contribution evidence", () => {
  test("requires two distinct pubkey signatures and preserves both in the combined PSBT", () => {
    expect(
      distinctMultisigContributionEvidence(
        psbt([]),
        psbt([publicKeyOne]),
        psbt([publicKeyTwo]),
        psbt([publicKeyOne, publicKeyTwo]),
      ),
    ).toMatchObject({ passed: true });
  });

  test.each([
    ["same signing key", psbt([publicKeyOne]), psbt([publicKeyOne, publicKeyTwo])],
    ["missing combined signature", psbt([publicKeyTwo]), psbt([publicKeyOne])],
  ])("rejects %s", (_label, wallySigned, combined) => {
    expect(
      distinctMultisigContributionEvidence(psbt([]), psbt([publicKeyOne]), wallySigned, combined),
    ).toMatchObject({ passed: false });
  });
});
