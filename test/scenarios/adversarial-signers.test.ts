import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { extractTransactionIdentity } from "../../src/psbt/diff.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations, serializePsbtDocument } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import {
  type AdversarialFixtureSet,
  adversarialSignerCases,
  createAdversarialSignerScenario,
} from "../../src/scenarios/adversarial-signers.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";

const publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const xOnly = publicKey.slice(2);

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(): Buffer {
  return Buffer.concat([
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
}

function fixture(
  id: string,
  scriptType: PsbtFixture["scriptTypes"][number],
  inputEntries: readonly Buffer[],
): PsbtFixture {
  const initialPsbt = Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    map(entry(0x00, unsignedTransaction())),
    map(...inputEntries),
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
  };
}

function fixtureSet(): AdversarialFixtureSet {
  const witnessUtxo = entry(
    0x01,
    Buffer.concat([Buffer.from("1027000000000000", "hex"), Buffer.from([1, 0x51])]),
  );
  const previous = unsignedTransaction();
  return {
    p2wpkh: fixture("p2wpkh", "p2wpkh", [witnessUtxo]),
    p2pkh: fixture("p2pkh", "p2pkh", [entry(0x00, previous)]),
    nested: fixture("p2sh-p2wsh-2-of-3", "p2sh-p2wsh", [
      witnessUtxo,
      entry(0x04, Buffer.from("0020", "hex")),
      entry(0x05, Buffer.from("51ae", "hex")),
    ]),
    p2wsh: fixture("p2wsh-2-of-3", "p2wsh", [witnessUtxo, entry(0x05, Buffer.from("51ae", "hex"))]),
    taproot: fixture("p2tr-keypath", "p2tr-keypath", [
      witnessUtxo,
      entry(0x17, Buffer.from(xOnly, "hex")),
    ]),
  };
}

describe("adversarial signer cases", () => {
  test("covers all eight semantic mismatch classes without changing transaction identity", () => {
    const cases = adversarialSignerCases(fixtureSet());

    expect(cases.map(({ id }) => id)).toEqual([
      "wrong-witness-amount",
      "wrong-witness-script-pubkey",
      "wrong-non-witness-transaction",
      "redeem-script-mismatch",
      "witness-script-mismatch",
      "derivation-mismatch",
      "taproot-internal-key-mismatch",
      "taproot-merkle-root-mismatch",
    ]);
    for (const testCase of cases) {
      expect(testCase.mutatedPsbt).not.toBe(testCase.fixture.initialPsbt);
      expect(extractTransactionIdentity(parsePsbtDocument(testCase.mutatedPsbt)).sha256).toBe(
        extractTransactionIdentity(parsePsbtDocument(testCase.fixture.initialPsbt)).sha256,
      );
    }
  });

  test("requires stable clean rejection from the signer", async () => {
    const fixtures = fixtureSet();
    const implementation = {
      name: "rust-bitcoin",
      version: "0.1.0",
      sourceRevision: "bitcoin-crate-0.32.102",
      artifactDigest: `sha256:${"c".repeat(64)}`,
    };
    const requests: AdapterRequest[] = [];
    const adapter = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        requests.push(request);
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: {
            class: "policy.psbt_not_authorized",
            message: "fixture metadata mismatch",
          },
        };
      }),
    };
    const context = new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: { checkpoint: vi.fn() } as never,
      adapters: new Map([["rust-bitcoin", adapter]]),
      adapterTimeoutMs: 1_000,
    });
    const scenario = createAdversarialSignerScenario(fixtures, "rust-bitcoin");

    const result = await scenario.run(context);

    expect(result.assertions).toHaveLength(8);
    expect(result.assertions.every(({ passed }) => passed)).toBe(true);
    expect(requests).toHaveLength(8);
    expect(requests.map(({ payload }) => payload["fixtureId"])).toEqual(
      adversarialSignerCases(fixtures).map(({ fixture }) => fixture.id),
    );
    expect(scenario.requirements[0]?.features).toContain("adversarial-signer-inputs-v1");
  });

  test("does not treat a signature-bearing success as safe refusal", async () => {
    const fixtures = fixtureSet();
    const implementation = {
      name: "rust-bitcoin",
      version: "0.1.0",
      artifactDigest: `sha256:${"c".repeat(64)}`,
    };
    const context = new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: { checkpoint: vi.fn() } as never,
      adapters: new Map([
        [
          "rust-bitcoin",
          {
            request: vi.fn(
              async (request: AdapterRequest): Promise<AdapterResponse> => ({
                protocol: "psbt-lab.adapter/0.2",
                id: request.id,
                status: "ok",
                implementation,
                output: {
                  psbt: applyPsbtMutations(request.payload["psbt"] as string, [
                    {
                      kind: "set-entry",
                      location: { kind: "input", index: 0 },
                      keyType: 0xfc,
                      valueHex: "01",
                    },
                  ]),
                },
              }),
            ),
          },
        ],
      ]),
      adapterTimeoutMs: 1_000,
    });

    const result = await createAdversarialSignerScenario(fixtures, "rust-bitcoin").run(context);

    expect(result.assertions.some(({ passed }) => !passed)).toBe(true);
    expect(serializePsbtDocument(parsePsbtDocument(fixtures.p2wpkh.initialPsbt))).toBeInstanceOf(
      Buffer,
    );
  });
});
