import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { extractTransactionIdentity } from "../../src/psbt/diff.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import {
  type CombinerConflictFixtureSet,
  classifyCombinerConflict,
  combinerConflictCases,
  createCombinerConflictScenario,
} from "../../src/scenarios/combiner-conflicts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";

const publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function fixture(id: string, scriptType: PsbtFixture["scriptTypes"][number], entries: Buffer[]) {
  const transaction = Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 1),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fdffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
  const initialPsbt = Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    map(entry(0x00, transaction)),
    map(...entries),
    map(),
  ]).toString("base64");
  return {
    id,
    initialPsbt,
    outpoints: [],
    inputCount: 1,
    outputCount: 1,
    feeSats: 1_000,
    scriptTypes: [scriptType],
    inputDescriptors: [],
    outputDescriptor: "",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: extractWireFacts(initialPsbt).sha256,
    unsignedTxSha256: `sha256:${"b".repeat(64)}`,
  } satisfies PsbtFixture;
}

function fixtures(): CombinerConflictFixtureSet {
  const witnessUtxo = entry(
    0x01,
    Buffer.concat([Buffer.from("1027000000000000", "hex"), Buffer.from([1, 0x51])]),
  );
  return {
    p2wpkh: fixture("p2wpkh", "p2wpkh", [witnessUtxo]),
    nested: fixture("p2sh-p2wsh-2-of-3", "p2sh-p2wsh", [
      witnessUtxo,
      entry(0x04, Buffer.from("0020", "hex")),
      entry(0x05, Buffer.from("51ae", "hex")),
    ]),
    p2wsh: fixture("p2wsh-2-of-3", "p2wsh", [witnessUtxo, entry(0x05, Buffer.from("51ae", "hex"))]),
    taproot: fixture("p2tr-keypath", "p2tr-keypath", [
      witnessUtxo,
      entry(0x17, Buffer.from(publicKey.slice(2), "hex")),
    ]),
  };
}

const implementation = {
  name: "bitcoinjs-lib",
  version: "1.0.0",
  sourceRevision: "bitcoinjs-lib-7.0.1",
  artifactDigest: `sha256:${"c".repeat(64)}`,
};

function response(
  status: "rejected" | "crashed" | "timeout",
): Exclude<AdapterResponse, { status: "ok" }> {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: "request",
    status,
    implementation,
    error: { class: "psbt.combine_conflict", message: "conflicting key" },
  };
}

describe("combiner conflict classification", () => {
  test("normalizes rejection, crashes, timeouts, silent winners, and invalid merges", () => {
    const testCase = combinerConflictCases(fixtures())[0];
    if (!testCase) throw new Error("Missing combiner conflict case");

    expect(classifyCombinerConflict(response("rejected"), testCase.left, testCase.right)).toBe(
      "rejected-conflict",
    );
    expect(classifyCombinerConflict(response("crashed"), testCase.left, testCase.right)).toBe(
      "crashed",
    );
    expect(classifyCombinerConflict(response("timeout"), testCase.left, testCase.right)).toBe(
      "timeout",
    );
    expect(
      classifyCombinerConflict(
        {
          protocol: "psbt-lab.adapter/0.2",
          id: "request",
          status: "ok",
          implementation,
          output: { psbt: testCase.left },
        },
        testCase.left,
        testCase.right,
      ),
    ).toBe("left-selected");
    expect(
      classifyCombinerConflict(
        {
          protocol: "psbt-lab.adapter/0.2",
          id: "request",
          status: "ok",
          implementation,
          output: { psbt: "not-base64" },
        },
        testCase.left,
        testCase.right,
      ),
    ).toBe("merged-invalid");
  });

  test("builds paired conflicts for every requested map-field family", () => {
    const cases = combinerConflictCases(fixtures());

    expect(cases.map(({ id }) => id)).toEqual([
      "conflicting-witness-utxo",
      "conflicting-redeem-script",
      "conflicting-witness-script",
      "conflicting-sighash-type",
      "conflicting-derivation",
      "conflicting-partial-signature",
      "conflicting-taproot-signature",
    ]);
    for (const testCase of cases) {
      expect(testCase.left).not.toBe(testCase.right);
      expect(extractTransactionIdentity(parsePsbtDocument(testCase.left)).sha256).toBe(
        extractTransactionIdentity(parsePsbtDocument(testCase.right)).sha256,
      );
    }
  });

  test("requires explicit rejection instead of accepting a deterministic winner", async () => {
    const selected = fixtures();
    const requests: AdapterRequest[] = [];
    const context = new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: { checkpoint: vi.fn() } as never,
      adapters: new Map([
        [
          "bitcoinjs-lib",
          {
            request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
              requests.push(request);
              return { ...response("rejected"), id: request.id };
            }),
          },
        ],
      ]),
      adapterTimeoutMs: 1_000,
    });
    const scenario = createCombinerConflictScenario(selected, "bitcoinjs-lib");

    const result = await scenario.run(context);

    expect(result.assertions).toHaveLength(7);
    expect(result.assertions.every(({ passed }) => passed)).toBe(true);
    expect(requests).toHaveLength(7);
    expect(scenario.requirements[0]?.features).toContain("combiner-conflicts-v1");
  });
});
