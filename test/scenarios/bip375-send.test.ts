import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP375_VALID_VECTORS } from "../../src/psbt/bip375-vectors.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { bip375SenderFixture, createBip375SenderScenario } from "../../src/scenarios/bip375.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const implementation = {
  name: "rust-psbt-v2",
  version: "0.1.0",
  sourceRevision: "psbt-v2-0.3.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

describe("BIP375 sender workflow", () => {
  test("completes, validates, roundtrips, and exercises bounded rejection canaries", async () => {
    const requests: AdapterRequest[] = [];
    const completed = BIP375_VALID_VECTORS[0];
    if (!completed) throw new Error("Missing BIP375 sender vector");
    const supplementary = completed.supplementary as {
      outputs: readonly [{ script: string }];
    };
    const adapter = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        requests.push(request);
        if (request.operation === "roundtrip") {
          return {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "ok",
            implementation,
            output: { psbt: completed.base64, byteIdentical: true },
          };
        }
        if (
          request.operation === "silent-payment-send" &&
          request.payload["network"] === "regtest" &&
          request.payload["psbt"] === bip375SenderFixture().inProgressPsbt
        ) {
          return {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "ok",
            implementation,
            output: {
              psbt: completed.base64,
              finalizedPsbt: completed.base64,
              finalized: true,
              signedInputs: 1,
              silentPaymentOutputs: 1,
              outputScript: supplementary.outputs[0].script,
              transaction: "00",
              transactionId: "1".repeat(64),
              witnessTransactionId: "1".repeat(64),
            },
          };
        }
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: {
            class:
              request.payload["network"] === "mainnet"
                ? "policy.network_not_allowed"
                : "policy.fixture_commitment_mismatch",
            message: "bounded sender rejection",
          },
        };
      }),
    };
    const context = new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: {
        checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
          scenario,
          stage,
          psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
          factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
          facts: extractWireFacts(psbt),
        })),
      },
      adapters: new Map([[implementation.name, adapter]]),
      adapterTimeoutMs: 1_000,
    });
    const negotiated: NegotiatedAdapter = {
      implementation,
      capabilities: {
        operations: ["hello", "roundtrip", "silent-payment-send"],
        roles: ["parser", "updater", "signer", "finalizer", "extractor"],
        psbtVersions: [2],
        scriptTypes: ["p2pkh"],
        operationScriptTypes: {
          roundtrip: ["p2pkh"],
          "silent-payment-send": ["p2pkh"],
        },
        features: ["bip375-sender-workflow"],
      },
    };
    const [result] = await runScenarioCatalog(
      [createBip375SenderScenario(implementation.name)],
      context,
      new Map([[implementation.name, negotiated]]),
    );

    expect(result).toMatchObject({
      id: "bip375-sender-workflow-rust-psbt-v2",
      outcome: "passed",
      transactionId: "1".repeat(64),
    });
    expect(result?.assertions.map(({ name, passed }) => ({ name, passed }))).toEqual([
      { name: "bip375-sender-cryptography", passed: true },
      { name: "bip375-sender-transition", passed: true },
      { name: "bip375-sender-finalization", passed: true },
      { name: "bip375-sender-native-roundtrip", passed: true },
      { name: "bip375-sender-bounded-canaries", passed: true },
    ]);
    expect(requests).toHaveLength(4);
  });
});
