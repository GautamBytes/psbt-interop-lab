import { describe, expect, test } from "vitest";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import {
  assessOutputAmountSemantics,
  MAX_MONEY_SATS,
} from "../../src/psbt/output-amount-semantics.js";

const MAGIC = Buffer.from("70736274ff", "hex");
const ISSUE_PSBT =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAgAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";

function amount(value: bigint): Buffer {
  const encoded = Buffer.alloc(8);
  encoded.writeBigInt64LE(value);
  return encoded;
}

function entry(keyType: number, value: Buffer): Buffer {
  const key = Buffer.from([keyType]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(values: readonly bigint[]): Buffer {
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x11),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("ffffffff", "hex"),
    Buffer.from([values.length]),
    ...values.flatMap((value) => [amount(value), Buffer.from([1, 0x51])]),
    Buffer.from("00000000", "hex"),
  ]);
}

function psbtV0(values: readonly bigint[]): string {
  return Buffer.concat([
    MAGIC,
    map(entry(0x00, unsignedTransaction(values))),
    map(),
    ...values.map(() => map()),
  ]).toString("base64");
}

function psbtV2(values: readonly bigint[], modifiable?: number): string {
  const global = [
    entry(0x02, Buffer.from("02000000", "hex")),
    entry(0x04, Buffer.from([1])),
    entry(0x05, Buffer.from([values.length])),
    ...(modifiable === undefined ? [] : [entry(0x06, Buffer.from([modifiable]))]),
    entry(0xfb, Buffer.from("02000000", "hex")),
  ];
  const input = map(
    entry(0x0e, Buffer.alloc(32, 0x22)),
    entry(0x0f, Buffer.from("00000000", "hex")),
  );
  const outputs = values.map((value) =>
    map(entry(0x03, amount(value)), entry(0x04, Buffer.from([0x51]))),
  );
  return Buffer.concat([MAGIC, map(...global), input, ...outputs]).toString("base64");
}

const versions = [
  ["PSBTv0", psbtV0],
  ["PSBTv2", psbtV2],
] as const;

describe.each(versions)("%s output amount semantics", (_name, build) => {
  test.each([0n, MAX_MONEY_SATS])("accepts boundary amount %s", (value) => {
    expect(assessOutputAmountSemantics(parsePsbtDocument(build([value])))).toMatchObject({
      status: "valid",
      findings: [],
    });
  });

  test("reports negative and above-MAX_MONEY outputs in index order", () => {
    expect(
      assessOutputAmountSemantics(parsePsbtDocument(build([-1n, MAX_MONEY_SATS + 1n]))),
    ).toMatchObject({
      status: "invalid",
      findings: [
        {
          ruleId: "lab.transaction-output.money-range",
          code: "OUTPUT_AMOUNT_NEGATIVE",
          outputIndex: 0,
        },
        {
          ruleId: "lab.transaction-output.money-range",
          code: "OUTPUT_AMOUNT_ABOVE_MAX_MONEY",
          outputIndex: 1,
        },
      ],
    });
  });

  test("reports an excessive aggregate only when every individual amount is valid", () => {
    expect(
      assessOutputAmountSemantics(parsePsbtDocument(build([MAX_MONEY_SATS, 1n]))),
    ).toMatchObject({
      status: "invalid",
      findings: [
        {
          ruleId: "lab.transaction-output.money-range",
          code: "OUTPUT_TOTAL_ABOVE_MAX_MONEY",
        },
      ],
    });
  });

  test("treats zero current outputs as amount-valid", () => {
    expect(assessOutputAmountSemantics(parsePsbtDocument(build([])))).toMatchObject({
      status: "valid",
      findings: [],
    });
  });
});

test("matches issue #38 without exposing its raw signed value", () => {
  const assessment = assessOutputAmountSemantics(parsePsbtDocument(ISSUE_PSBT));
  expect(assessment).toEqual({
    status: "invalid",
    outputsModifiable: false,
    findings: [
      {
        ruleId: "lab.transaction-output.money-range",
        code: "OUTPUT_AMOUNT_NEGATIVE",
        outputIndex: 0,
      },
    ],
  });
  expect(JSON.stringify(assessment)).not.toContain("9223372036054775808");
});

test.each([
  [undefined, false],
  [0, false],
  [2, true],
] as const)("reports PSBTv2 output modifiability %s as %s", (flags, expected) => {
  expect(
    assessOutputAmountSemantics(parsePsbtDocument(psbtV2([1n], flags))).outputsModifiable,
  ).toBe(expected);
});
