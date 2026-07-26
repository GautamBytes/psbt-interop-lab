import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import {
  classifySighashCommitments,
  createSighashMatrixScenario,
  ECDSA_SIGHASH_CASES,
  TAPROOT_SIGHASH_CASES,
} from "../../src/scenarios/sighash-matrix.js";

const publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function basePsbt(taproot: boolean): string {
  const transaction = Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([2]),
    Buffer.alloc(32, 1),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fdffffff", "hex"),
    Buffer.alloc(32, 2),
    Buffer.from("01000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fcffffff", "hex"),
    Buffer.from([2]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("2027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
  const inputEntries = taproot
    ? [
        entry(
          0x01,
          Buffer.concat([Buffer.from("1027000000000000", "hex"), Buffer.from([1, 0x51])]),
        ),
        entry(0x17, Buffer.from(publicKey.slice(2), "hex")),
      ]
    : [
        entry(
          0x01,
          Buffer.concat([Buffer.from("1027000000000000", "hex"), Buffer.from([1, 0x51])]),
        ),
      ];
  return Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    map(entry(0x00, transaction)),
    map(...inputEntries),
    map(...inputEntries),
    map(),
    map(),
  ]).toString("base64");
}

function fixture(taproot: boolean): PsbtFixture {
  const initialPsbt = basePsbt(taproot);
  return {
    id: taproot ? "sighash-p2tr-keypath" : "sighash-p2wpkh",
    initialPsbt,
    outpoints: [],
    inputCount: 2,
    outputCount: 2,
    feeSats: 1_000,
    scriptTypes: [taproot ? "p2tr-keypath" : "p2wpkh"],
    inputDescriptors: [],
    outputDescriptor: "",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: extractWireFacts(initialPsbt).sha256,
    unsignedTxSha256: `sha256:${"b".repeat(64)}`,
  };
}

describe("sighash commitment model", () => {
  test("covers all ECDSA modes and Taproot DEFAULT", () => {
    expect(ECDSA_SIGHASH_CASES.map(({ value }) => value)).toEqual([
      0x01, 0x02, 0x03, 0x81, 0x82, 0x83,
    ]);
    expect(TAPROOT_SIGHASH_CASES.map(({ value }) => value)).toEqual([
      0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83,
    ]);
  });

  test("classifies committed inputs and outputs for mutation probes", () => {
    expect(classifySighashCommitments("ecdsa", 0x01, 0, 2, 2)).toEqual({
      committedInputOutpoints: [0, 1],
      permittedInputOutpoints: [],
      committedInputSequences: [0, 1],
      permittedInputSequences: [],
      committedOutputs: [0, 1],
      permittedOutputs: [],
    });
    expect(classifySighashCommitments("ecdsa", 0x82, 0, 2, 2)).toEqual({
      committedInputOutpoints: [0],
      permittedInputOutpoints: [1],
      committedInputSequences: [0],
      permittedInputSequences: [1],
      committedOutputs: [],
      permittedOutputs: [0, 1],
    });
    expect(classifySighashCommitments("ecdsa", 0x03, 0, 2, 2)).toEqual({
      committedInputOutpoints: [0, 1],
      permittedInputOutpoints: [],
      committedInputSequences: [0],
      permittedInputSequences: [1],
      committedOutputs: [0],
      permittedOutputs: [1],
    });
    expect(classifySighashCommitments("taproot", 0x03, 0, 2, 2)).toMatchObject({
      committedInputSequences: [0, 1],
      permittedInputSequences: [],
    });
    expect(classifySighashCommitments("taproot", 0x00, 0, 2, 2)).toEqual(
      classifySighashCommitments("taproot", 0x01, 0, 2, 2),
    );
  });
});

describe("sighash matrix scenario", () => {
  test.each([
    ["ecdsa", false, ECDSA_SIGHASH_CASES.length, 0x02],
    ["taproot", true, TAPROOT_SIGHASH_CASES.length, 0x13],
  ] as const)(
    "signs and Core-verifies every %s mode",
    async (_name, taproot, validModes, keyType) => {
      const selectedFixture = fixture(taproot);
      const requests: AdapterRequest[] = [];
      const implementation = {
        name: "rust-bitcoin",
        version: "0.1.0",
        sourceRevision: "bitcoin-crate-0.32.102",
        artifactDigest: `sha256:${"c".repeat(64)}`,
      };
      const adapter = {
        request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
          requests.push(request);
          const psbt = request.payload["psbt"];
          if (typeof psbt !== "string") throw new TypeError("missing PSBT");
          const sighash = request.payload["sighashType"];
          if (typeof sighash !== "number") throw new TypeError("missing sighash type");
          if (sighash === 0x80) {
            return {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status: "rejected",
              implementation,
              error: { class: "signing.invalid_sighash", message: "invalid default combination" },
            };
          }
          const value =
            keyType === 0x13
              ? Buffer.alloc(sighash === 0 ? 64 : 65, 1)
              : Buffer.concat([Buffer.from("3006020101020101", "hex"), Buffer.from([sighash])]);
          if (keyType === 0x13 && value.length === 65) value[64] = sighash as number;
          const signed = applyPsbtMutations(
            psbt,
            [0, 1].map((index) => ({
              kind: "set-entry" as const,
              location: { kind: "input" as const, index },
              keyType,
              ...(keyType === 0x02 ? { keyDataHex: publicKey } : {}),
              valueHex: value.toString("hex"),
            })),
          );
          return {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "ok",
            implementation,
            output: {
              psbt: signed,
              signedInputs: 2,
              mutationChecks: {
                signedInputSequenceValid: false,
                otherInputOutpointValid: (sighash & 0x80) !== 0,
                otherInputSequenceValid:
                  (sighash & 0x80) !== 0 || (!taproot && (sighash & 0x1f) !== 0x01),
                outputValueValid: [0, 1].map((outputIndex) => {
                  const base = sighash === 0 ? 0x01 : sighash & 0x1f;
                  return base === 0x02 || (base === 0x03 && outputIndex !== 0);
                }),
              },
            },
          };
        }),
      };
      const context = new ScenarioExecutionContext({
        rpc: {
          call: vi.fn(async (method: string) =>
            method === "finalizepsbt"
              ? { complete: true, hex: "02000000" }
              : [{ allowed: true, txid: "d".repeat(64) }],
          ),
        } as never,
        artifacts: {
          checkpoint: vi.fn(async () => ({ facts: {} })) as never,
        },
        adapters: new Map([["rust-bitcoin", adapter]]),
        adapterTimeoutMs: 1_000,
      });
      const scenario = createSighashMatrixScenario(selectedFixture, {
        adapter: "rust-bitcoin",
        family: taproot ? "taproot" : "ecdsa",
      });

      const result = await scenario.run(context);

      expect(result.assertions.every(({ passed }) => passed)).toBe(true);
      expect(requests).toHaveLength(validModes + (taproot ? 1 : 0));
      expect(requests.every(({ payload }) => payload["fixtureId"] === selectedFixture.id)).toBe(
        true,
      );
      expect(scenario.requirements[0]).toMatchObject({
        adapter: "rust-bitcoin",
        operations: ["sign"],
        features: ["fixture-commitment-sha256", "sighash-matrix-v1"],
      });
    },
  );
});
