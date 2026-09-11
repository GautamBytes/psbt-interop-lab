import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture, RpcCaller } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import {
  createBip375FundedSenderScenario,
  fundedSenderCanaries,
  verifyFundedSender,
} from "../../src/scenarios/bip375-funded.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import fixture from "../fixtures/bip375-funded-sender.json" with { type: "json" };

describe("Core-funded BIP375 sender evidence", () => {
  test("independently verifies the derived destination and bounded field changes", () => {
    expect(verifyFundedSender(fixture.template, fixture.output.psbt)).toBe(true);
  });

  test.each([
    [
      "DLEQ",
      {
        kind: "replace-value",
        location: { kind: "input", index: 0 },
        keyType: 0x1e,
        keyDataHex: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        valueHex: "00".repeat(64),
      },
    ],
    [
      "input",
      {
        kind: "replace-value",
        location: { kind: "input", index: 0 },
        keyType: 0x0f,
        valueHex: "01000000",
      },
    ],
    [
      "recipient",
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 0x09,
        valueHex: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".repeat(2),
      },
    ],
    [
      "amount",
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 0x03,
        valueHex: "a75b010000000000",
      },
    ],
    [
      "script",
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 0x04,
        valueHex: `5120${"11".repeat(32)}`,
      },
    ],
    [
      "unlocked transaction",
      { kind: "replace-value", location: { kind: "global" }, keyType: 0x06, valueHex: "03" },
    ],
    [
      "missing signature",
      {
        kind: "delete-entry",
        location: { kind: "input", index: 0 },
        keyType: 0x02,
        keyDataHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      },
    ],
  ] satisfies [string, PsbtMutationRecipe][])("rejects altered %s", (_name, mutation) => {
    expect(
      verifyFundedSender(fixture.template, applyPsbtMutations(fixture.output.psbt, [mutation])),
    ).toBe(false);
  });

  test("constructs distinct signing-boundary canaries", () => {
    const canaries = fundedSenderCanaries(fixture.template);
    expect(canaries.map(({ name }) => name)).toEqual([
      "changed-input",
      "supplied-recipient",
      "supplied-dleq",
    ]);
    expect(new Set(canaries.map(({ psbt }) => psbt)).size).toBe(3);
    for (const canary of canaries) expect(canary.psbt).not.toBe(fixture.template);
  });
});

async function runFundedScenario(
  options: {
    allowed?: boolean;
    txid?: string;
    extracted?: string;
    commitment?: string;
    signed?: string;
  } = {},
) {
  const commitment = `sha256:${"b".repeat(64)}`;
  const prepared = {
    id: "p2wpkh",
    psbtVersion: 0,
    inputCount: 1,
    outputCount: 1,
    initialPsbt: fixture.template,
    unsignedTxSha256: commitment,
  } as PsbtFixture;
  const requests: AdapterRequest[] = [];
  const request = async (request: AdapterRequest): Promise<AdapterResponse> => {
    requests.push(request);
    const base = {
      protocol: request.protocol,
      id: request.id,
      implementation: { name: "test", version: "test", artifactDigest: `sha256:${"a".repeat(64)}` },
    };
    if (request.operation === "convert")
      return {
        ...base,
        status: "ok",
        output: { psbt: fixture.template, unsignedTxSha256: options.commitment ?? commitment },
      };
    if (request.operation === "extract")
      return {
        ...base,
        status: "ok",
        output: { transaction: options.extracted ?? fixture.output.transaction },
      };
    const canary = fundedSenderCanaries(fixture.template).find(
      ({ psbt }) => psbt === request.payload["psbt"],
    );
    const errorClass =
      request.payload["network"] === "mainnet" ? "policy.network_not_allowed" : canary?.errorClass;
    if (errorClass)
      return {
        ...base,
        status: "rejected",
        error: { class: errorClass, message: "expected canary rejection" },
      };
    return {
      ...base,
      status: "ok",
      output: { ...fixture.output, psbt: options.signed ?? fixture.output.psbt },
    };
  };
  const rpc = {
    call: vi.fn(async () => [
      {
        allowed: options.allowed ?? true,
        txid: options.txid ?? fixture.output.transactionId,
        ...(options.allowed === false ? { "reject-reason": "missing-inputs" } : {}),
      },
    ]),
  };
  const context = new ScenarioExecutionContext({
    rpc: rpc as RpcCaller,
    adapters: new Map([
      ["rust-psbt-v2", { request }],
      ["libwally", { request }],
    ]),
    artifacts: {
      checkpoint: async (scenario, stage, psbt) => ({
        scenario,
        stage,
        psbtPath: `${stage}.psbt`,
        factsPath: `${stage}.json`,
        facts: extractWireFacts(psbt),
      }),
    },
    adapterTimeoutMs: 1000,
  });
  return { result: await createBip375FundedSenderScenario(prepared).run(context), requests, rpc };
}

describe("Core-funded sender scenario", () => {
  test("links the signed PSBT, independent extraction, and Core policy result without broadcasting", async () => {
    const { result, rpc } = await runFundedScenario();
    expect(result.assertions?.every(({ passed }) => passed)).toBe(true);
    expect(result.policyAccepted).toBe(true);
    expect(rpc.call).toHaveBeenCalledExactlyOnceWith("testmempoolaccept", {
      rawtxs: [fixture.output.transaction],
    });
  });
  test.each([
    ["missing parent", { allowed: false }, "core-policy"],
    ["wrong Core txid", { txid: "c".repeat(64) }, "core-policy"],
    ["detached extracted transaction", { extracted: "00" }, "independent-extraction"],
  ])("fails on %s", async (_name, options, assertion) => {
    const { result } = await runFundedScenario(options);
    expect(result.assertions).toContainEqual(
      expect.objectContaining({ name: `bip375-funded-${assertion}`, passed: false }),
    );
  });
  test("stops before signing when conversion changes the funding commitment", async () => {
    const { result, requests, rpc } = await runFundedScenario({
      commitment: `sha256:${"c".repeat(64)}`,
    });
    expect(result.policyAccepted).toBe(false);
    expect(requests.map(({ operation }) => operation)).toEqual(["convert"]);
    expect(rpc.call).not.toHaveBeenCalled();
  });
  test("rejects a signed PSBT whose signature does not match the finalized witness", async () => {
    const signed = applyPsbtMutations(fixture.output.psbt, [
      {
        kind: "replace-value",
        location: { kind: "input", index: 0 },
        keyType: 0x02,
        keyDataHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        valueHex: "300602010102010101",
      },
    ]);
    const { result } = await runFundedScenario({ signed });
    expect(result.assertions).toContainEqual(
      expect.objectContaining({ name: "bip375-funded-signature-witness", passed: false }),
    );
  });
});
