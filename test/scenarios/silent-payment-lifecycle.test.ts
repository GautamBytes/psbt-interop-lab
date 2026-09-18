import { expect, test, vi } from "vitest";
import receiver from "../../adapters/rust-psbt-v2/tests/fixtures/receiver.json" with {
  type: "json",
};
import type { PsbtFixture, RpcCaller } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { createSilentPaymentLifecycleScenario } from "../../src/scenarios/silent-payment-lifecycle.js";
import sender from "../fixtures/bip375-multi-sender.json" with { type: "json" };

const parentCandidate = sender.variants.find((v) => v.mode === "per-input" && !v.reverse)?.output;
if (!parentCandidate) throw new Error("Missing per-input parent fixture");
const parent = parentCandidate;
const commitment = `sha256:${"a".repeat(64)}`;
async function run(
  options: {
    badCommitment?: boolean;
    badParentId?: boolean;
    badExtraction?: boolean;
    badPackageId?: boolean;
    undecidedChild?: boolean;
    childAlone?: boolean;
    acceptCanary?: boolean;
  } = {},
) {
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
          psbt: sender.template,
          unsignedTxSha256: options.badCommitment ? "bad" : commitment,
        },
      };
    if (req.operation === "silent-payment-send") return { ...base, status: "ok", output: parent };
    if (req.operation === "extract")
      return {
        ...base,
        status: "ok",
        output: {
          transaction: options.badExtraction
            ? "00"
            : req.payload["psbt"] === parent.finalizedPsbt
              ? parent.transaction
              : receiver.output.transaction,
        },
      };
    if (req.payload["network"] === "mainnet")
      return {
        ...base,
        status: "rejected",
        error: { class: "policy.network_not_allowed", message: "canary" },
      };
    if (req.payload["psbt"] !== receiver.child && !options.acceptCanary)
      return {
        ...base,
        status: "rejected",
        error: { class: "silent_payment.receiver_link_invalid", message: "canary" },
      };
    return { ...base, status: "ok", output: receiver.output };
  };
  const call = vi.fn(async (_method: string, params: unknown) => {
    const { rawtxs } = params as { rawtxs: string[] };
    if (rawtxs.length === 2)
      return [
        { allowed: true, txid: parent.transactionId },
        {
          ...(options.undecidedChild ? {} : { allowed: true }),
          txid: options.badPackageId ? "f".repeat(64) : receiver.output.transactionId,
        },
      ];
    return rawtxs[0] === parent.transaction
      ? [{ allowed: true, txid: options.badParentId ? "f".repeat(64) : parent.transactionId }]
      : [
          {
            allowed: options.childAlone ?? false,
            txid: receiver.output.transactionId,
            "reject-reason": "missing-inputs",
          },
        ];
  });
  const context = new ScenarioExecutionContext({
    rpc: { call } as RpcCaller,
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
  const fixture = {
    id: "bip375-multi",
    psbtVersion: 0,
    inputCount: 2,
    outputCount: 2,
    initialPsbt: sender.template,
    unsignedTxSha256: commitment,
  } as PsbtFixture;
  return {
    result: await createSilentPaymentLifecycleScenario(fixture).run(context),
    requests,
    call,
    context,
  };
}
test("links independent discovery to the actual parent/child package and six checkpoints", async () => {
  const { result, call, context } = await run();
  expect(result.assertions?.filter((a) => !a.passed)).toEqual([]);
  expect(result.policyAccepted).toBe(true);
  expect(context.checkpoints).toHaveLength(6);
  expect(call.mock.calls.map(([method]) => method)).toEqual([
    "testmempoolaccept",
    "testmempoolaccept",
    "testmempoolaccept",
  ]);
  expect(call).toHaveBeenLastCalledWith("testmempoolaccept", {
    rawtxs: [parent.transaction, receiver.output.transaction],
  });
});
test.each([
  ["wrong package txid", { badPackageId: true }, "package-policy"],
  ["undecided child", { undecidedChild: true }, "package-policy"],
  ["child accepted without parent", { childAlone: true }, "child-needs-parent"],
  ["accepted tamper canary", { acceptCanary: true }, "wrong-outpoint"],
] as const)("fails required evidence on %s", async (_label, options, name) => {
  const { result } = await run(options);
  expect(result.assertions).toContainEqual(
    expect.objectContaining({ name: `lifecycle-${name}`, passed: false }),
  );
});
test.each([{ badCommitment: true }, { badParentId: true }, { badExtraction: true }])(
  "stops before receiver signing when the parent is not bound: %j",
  async (options) => {
    const { result, requests } = await run(options);
    expect(result.policyAccepted).toBe(false);
    expect(requests.some((r) => r.operation === "silent-payment-spend")).toBe(false);
  },
);
