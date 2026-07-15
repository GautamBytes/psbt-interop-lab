import { parsePsbtDocument } from "./psbt/document.js";
import {
  assertPsbtTransition,
  type PsbtTransitionFailureCode,
  type PsbtTransitionPolicy,
} from "./psbt/invariants.js";

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");
const TEST_PUBLIC_KEY = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);

export interface DetectorCanaryResult {
  readonly id: string;
  readonly detected: boolean;
  readonly failureCode: PsbtTransitionFailureCode;
  readonly keyType: number;
}

const CANARY_EXPECTATIONS = [
  { id: "proprietary-field-drop", failureCode: "ENTRY_REMOVED", keyType: 0xfc },
  { id: "output-amount-change", failureCode: "TRANSACTION_IDENTITY_CHANGED", keyType: 0x00 },
  { id: "sequence-change", failureCode: "TRANSACTION_IDENTITY_CHANGED", keyType: 0x00 },
  { id: "signature-removal", failureCode: "ENTRY_REMOVED", keyType: 0x02 },
] as const satisfies readonly Omit<DetectorCanaryResult, "detected">[];

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  if (key.byteLength >= 0xfd || value.byteLength >= 0xfd) {
    throw new Error("Detector canary entries must use one-byte compact sizes");
  }
  return Buffer.concat([
    Buffer.from([key.byteLength]),
    key,
    Buffer.from([value.byteLength]),
    value,
  ]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(amountSats = 10_000, sequence = 0xffff_fffd): Buffer {
  const amount = Buffer.alloc(8);
  amount.writeBigUInt64LE(BigInt(amountSats));
  const encodedSequence = Buffer.alloc(4);
  encodedSequence.writeUInt32LE(sequence);
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x11),
    Buffer.from("01000000", "hex"),
    Buffer.from([0]),
    encodedSequence,
    Buffer.from([1]),
    amount,
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
}

function psbt(
  options: {
    readonly amountSats?: number;
    readonly sequence?: number;
    readonly global?: readonly Buffer[];
    readonly input?: readonly Buffer[];
  } = {},
): string {
  return Buffer.concat([
    PSBT_MAGIC,
    map(
      entry(0x00, unsignedTransaction(options.amountSats, options.sequence)),
      ...(options.global ?? []),
    ),
    map(...(options.input ?? [])),
    map(),
  ]).toString("base64");
}

function canary(
  id: string,
  policy: PsbtTransitionPolicy,
  before: string,
  after: string,
  failureCode: PsbtTransitionFailureCode,
  keyType: number,
): DetectorCanaryResult {
  const transition = assertPsbtTransition(
    policy,
    parsePsbtDocument(before),
    parsePsbtDocument(after),
  );
  return {
    id,
    detected: transition.failures.some(
      (failure) => failure.code === failureCode && failure.keyType === keyType,
    ),
    failureCode,
    keyType,
  };
}

export function runDetectorCanaries(): readonly DetectorCanaryResult[] {
  const proprietary = entry(
    0xfc,
    Buffer.from("must survive", "utf8"),
    Buffer.from("08707362742d6c616201", "hex"),
  );
  const signature = entry(
    0x02,
    Buffer.concat([
      Buffer.from("30440220", "hex"),
      Buffer.alloc(32, 0x01),
      Buffer.from("0220", "hex"),
      Buffer.alloc(32, 0x02),
      Buffer.from([0x01]),
    ]),
    TEST_PUBLIC_KEY,
  );
  return [
    canary(
      "proprietary-field-drop",
      "roundtrip",
      psbt({ global: [proprietary] }),
      psbt(),
      "ENTRY_REMOVED",
      0xfc,
    ),
    canary(
      "output-amount-change",
      "sign",
      psbt({ amountSats: 10_000 }),
      psbt({ amountSats: 9_999 }),
      "TRANSACTION_IDENTITY_CHANGED",
      0x00,
    ),
    canary(
      "sequence-change",
      "sign",
      psbt({ sequence: 0xffff_fffd }),
      psbt({ sequence: 0xffff_fffc }),
      "TRANSACTION_IDENTITY_CHANGED",
      0x00,
    ),
    canary(
      "signature-removal",
      "combine",
      psbt({ input: [signature] }),
      psbt(),
      "ENTRY_REMOVED",
      0x02,
    ),
  ];
}

export function detectorCanariesPassed(results: readonly DetectorCanaryResult[]): boolean {
  if (results.length !== CANARY_EXPECTATIONS.length) return false;
  const actual = new Map(results.map((result) => [result.id, result]));
  if (actual.size !== CANARY_EXPECTATIONS.length) return false;
  return CANARY_EXPECTATIONS.every((expected) => {
    const result = actual.get(expected.id);
    return (
      result?.detected === true &&
      result.failureCode === expected.failureCode &&
      result.keyType === expected.keyType
    );
  });
}
