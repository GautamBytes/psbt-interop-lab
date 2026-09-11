import { expect, test, vi } from "vitest";
import type { PsbtFixture, RpcCaller } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import {
  createBip375MultiSenderScenario,
  multiSenderCanaries,
} from "../../src/scenarios/bip375-multi.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import fixture from "../fixtures/bip375-multi-sender.json" with { type: "json" };

async function run(
  options: {
    badCommitment?: boolean;
    missingParent?: boolean;
    wrongTxid?: boolean;
    wrongExtraction?: boolean;
  } = {},
) {
  const commitment = `sha256:${"a".repeat(64)}`;
  const prepared = {
    id: "bip375-multi",
    psbtVersion: 0,
    inputCount: 2,
    outputCount: 2,
    initialPsbt: fixture.template,
    unsignedTxSha256: commitment,
  } as PsbtFixture;
  const requests: AdapterRequest[] = [];
  const request = async (req: AdapterRequest): Promise<AdapterResponse> => {
    requests.push(req);
    const base = {
      protocol: req.protocol,
      id: req.id,
      implementation: { name: "test", version: "test", artifactDigest: commitment },
    };
    if (req.operation === "convert")
      return {
        ...base,
        status: "ok",
        output: {
          psbt: fixture.template,
          unsignedTxSha256: options.badCommitment ? "bad" : commitment,
        },
      };
    if (req.operation === "extract") {
      const variant = fixture.variants.find((v) => v.output.finalizedPsbt === req.payload["psbt"]);
      if (!variant) throw new Error("Unknown finalized fixture");
      return {
        ...base,
        status: "ok",
        output: { transaction: options.wrongExtraction ? "00" : variant.output.transaction },
      };
    }
    const canary = multiSenderCanaries(fixture.template).find(
      (c) => c.psbt === req.payload["psbt"],
    );
    if (canary || req.payload["network"] === "mainnet")
      return {
        ...base,
        status: "rejected",
        error: { class: canary?.errorClass ?? "policy.network_not_allowed", message: "rejected" },
      };
    const variant = fixture.variants.find(
      (v) => v.mode === req.payload["shareMode"] && v.reverse === req.payload["reverseInputs"],
    );
    if (!variant) throw new Error("Unknown sender variant");
    return { ...base, status: "ok", output: variant.output };
  };
  const rpc = {
    call: vi.fn(async (_method: string, params: { rawtxs: string[] }) => {
      const variant = fixture.variants.find((v) => v.output.transaction === params.rawtxs[0]);
      if (!variant) throw new Error("Unknown transaction fixture");
      return [
        {
          allowed: !options.missingParent,
          txid: options.wrongTxid ? "b".repeat(64) : variant.output.transactionId,
          ...(options.missingParent ? { "reject-reason": "missing-inputs" } : {}),
        },
      ];
    }),
  };
  const context = new ScenarioExecutionContext({
    rpc: rpc as RpcCaller,
    adapters: new Map([
      ["rust-psbt-v2", { request }],
      ["libwally", { request }],
    ]),
    adapterTimeoutMs: 1000,
    artifacts: {
      checkpoint: async (scenario, stage, psbt) => ({
        scenario,
        stage,
        psbtPath: `${stage}.psbt`,
        factsPath: `${stage}.json`,
        facts: extractWireFacts(psbt),
      }),
    },
  });
  return { result: await createBip375MultiSenderScenario(prepared).run(context), requests, rpc };
}
test("checks all four funded transactions with Core and never broadcasts", async () => {
  const { result, rpc } = await run();
  expect(result.assertions?.every((a) => a.passed)).toBe(true);
  expect(result.policyAccepted).toBe(true);
  expect(rpc.call).toHaveBeenCalledTimes(4);
  expect(rpc.call.mock.calls.every(([method]) => method === "testmempoolaccept")).toBe(true);
});
test.each([{ missingParent: true }, { wrongTxid: true }, { wrongExtraction: true }])(
  "fails on disconnected policy or extraction evidence: %j",
  async (options) => {
    const { result } = await run(options);
    expect(result.assertions?.some((a) => !a.passed)).toBe(true);
    if (options.missingParent || options.wrongTxid) expect(result.policyAccepted).toBe(false);
  },
);
test("does not sign if conversion changes the committed transaction", async () => {
  const { result, requests, rpc } = await run({ badCommitment: true });
  expect(result.policyAccepted).toBe(false);
  expect(requests.map((r) => r.operation)).toEqual(["convert"]);
  expect(rpc.call).not.toHaveBeenCalled();
});
