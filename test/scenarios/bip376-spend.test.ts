import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture, RpcCaller } from "../../src/core/fixtures.js";
import type {
  AdapterRequest,
  AdapterResponse,
  JsonValue,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP370_VALID_VECTORS } from "../../src/psbt/bip370-vectors.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { bip376SpendPsbt, createBip376SpendScenario } from "../../src/scenarios/bip376.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const RUST = "rust-psbt-v2";
const WALLY = "libwally";
const OUTPUT_KEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

function implementation(name: string) {
  return {
    name,
    version: "test",
    sourceRevision: "test",
    artifactDigest: `sha256:${"a".repeat(64)}`,
  };
}

function ok(
  request: AdapterRequest,
  name: string,
  output: Record<string, JsonValue>,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation: implementation(name),
    output,
  };
}

function rejected(request: AdapterRequest, name: string, errorClass: string): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "rejected",
    implementation: implementation(name),
    error: { class: errorClass, message: "bounded rejection" },
  };
}

describe("BIP376 receiver spend workflow", () => {
  test("converts, signs, cleans, policy-checks, and rejects bounded canaries", async () => {
    const converted = BIP370_VALID_VECTORS[1]?.base64;
    if (!converted) throw new Error("Missing updated BIP370 vector");
    const inProgress = bip376SpendPsbt(converted);
    const signed = applyPsbtMutations(inProgress, [
      {
        kind: "set-entry",
        location: { kind: "input", index: 0 },
        keyType: 0x13,
        valueHex: "11".repeat(64),
      },
    ]);
    const finalized = applyPsbtMutations(signed, [
      {
        kind: "set-entry",
        location: { kind: "input", index: 0 },
        keyType: 0x08,
        valueHex: `0140${"11".repeat(64)}`,
      },
      { kind: "delete-entry", location: { kind: "input", index: 0 }, keyType: 0x01 },
      { kind: "delete-entry", location: { kind: "input", index: 0 }, keyType: 0x13 },
      {
        kind: "delete-entry",
        location: { kind: "input", index: 0 },
        keyType: 0x1f,
        keyDataHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      },
      { kind: "delete-entry", location: { kind: "input", index: 0 }, keyType: 0x20 },
    ]);
    const fixture = {
      id: "bip376-spend",
      initialPsbt: converted,
      inputCount: 1,
      outputCount: 1,
      psbtVersion: 0,
      unsignedTxSha256: `sha256:${"b".repeat(64)}`,
    } as PsbtFixture;
    const requests: AdapterRequest[] = [];
    const adapters = new Map([
      [
        WALLY,
        {
          request: vi.fn(async (request: AdapterRequest) => {
            requests.push(request);
            return ok(request, WALLY, {
              psbt: converted,
              psbtVersion: 2,
              unsignedTxSha256: fixture.unsignedTxSha256,
            });
          }),
        },
      ],
      [
        RUST,
        {
          request: vi.fn(async (request: AdapterRequest) => {
            requests.push(request);
            if (request.payload["network"] === "mainnet") {
              return rejected(request, RUST, "policy.network_not_allowed");
            }
            if (request.payload["psbt"] !== inProgress) {
              return rejected(request, RUST, "silent_payment.output_key_mismatch");
            }
            return ok(request, RUST, {
              psbt: signed,
              finalizedPsbt: finalized,
              finalized: true,
              signedInputs: 1,
              derivedOutputKey: OUTPUT_KEY,
              transaction: "00",
            });
          }),
        },
      ],
    ]);
    const rpc: RpcCaller = {
      call: async <T>(method: string): Promise<T> => {
        if (method === "testmempoolaccept") {
          return [{ allowed: true, txid: "1".repeat(64) }] as T;
        }
        throw new Error(`Unexpected RPC ${method}`);
      },
    };
    const context = new ScenarioExecutionContext({
      rpc,
      artifacts: {
        checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
          scenario,
          stage,
          psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
          factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
          facts: extractWireFacts(psbt),
        })),
      },
      adapters,
      adapterTimeoutMs: 1_000,
    });
    const negotiated = new Map<string, NegotiatedAdapter>([
      [
        WALLY,
        {
          implementation: implementation(WALLY),
          capabilities: {
            operations: ["hello", "convert"],
            roles: ["parser"],
            psbtVersions: [0, 2],
            scriptTypes: ["p2tr-keypath"],
            operationScriptTypes: { convert: ["p2tr-keypath"] },
            features: ["psbt-v0-v2-conversion", "unsigned-tx-sha256"],
          },
        },
      ],
      [
        RUST,
        {
          implementation: implementation(RUST),
          capabilities: {
            operations: ["hello", "silent-payment-spend"],
            roles: ["signer", "finalizer", "extractor"],
            psbtVersions: [2],
            scriptTypes: ["p2tr-keypath"],
            operationScriptTypes: { "silent-payment-spend": ["p2tr-keypath"] },
            features: ["bip376-spend-workflow", "fixture-commitment-sha256"],
          },
        },
      ],
    ]);

    const [result] = await runScenarioCatalog(
      [createBip376SpendScenario(fixture)],
      context,
      negotiated,
    );

    expect(result).toMatchObject({
      id: "bip376-spend-workflow-rust-psbt-v2",
      outcome: "passed",
      policyAccepted: true,
      transactionId: "1".repeat(64),
    });
    expect(result?.assertions.every(({ passed }) => passed)).toBe(true);
    expect(requests).toHaveLength(4);
  });
});
