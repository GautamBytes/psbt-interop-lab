import { expect, test } from "vitest";
import fixture from "../../adapters/rust-psbt-v2/tests/fixtures/multi-output.json" with {
  type: "json",
};
import type { PsbtFixture, RpcCaller } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { verifyMultiSender } from "../../src/scenarios/bip375-multi-verify.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { createSilentPaymentLifecycleScenario } from "../../src/scenarios/silent-payment-lifecycle.js";
import {
  createReceiverPsbt,
  discoverReceiverOutputs,
} from "../../src/scenarios/silent-payment-receiver.js";

for (const variant of fixture.variants) {
  test(`discovers both counters independently of output positions: shuffled=${variant.shuffle}`, () => {
    const found = discoverReceiverOutputs(variant.output.finalizedPsbt);
    expect(found.map((o) => o.index)).toEqual(variant.shuffle ? [1, 2] : [0, 1]);
    expect(new Set(found.map((o) => o.tweakHex)).size).toBe(2);
    expect(found.reduce((n, o) => n + o.amountSats, 0n)).toBe(128_000n);
    const child = parsePsbtDocument(createReceiverPsbt(variant.output.transactionId, found));
    expect(child.inputCount).toBe(2);
    expect(
      child.maps
        .find((m) => m.location.kind === "output")
        ?.entries.find((e) => e.keyType === 3)
        ?.value.readBigUInt64LE(),
    ).toBe(118_000n);
    const first = found[0];
    if (!first) throw new Error("Missing discovered output");
    expect(() => createReceiverPsbt(variant.output.transactionId, [first, first])).toThrow();
    expect(discoverReceiverOutputs(variant.output.finalizedPsbt, 3n)).toEqual([]);
  });
  test(`stops at a missing counter and rejects duplicate matches: shuffled=${variant.shuffle}`, () => {
    const found = discoverReceiverOutputs(variant.output.finalizedPsbt);
    const first = found[0],
      second = found[1];
    if (!first || !second) throw new Error("Missing recipient outputs");
    const replaceScript = (index: number, valueHex: string) =>
      applyPsbtMutations(variant.output.finalizedPsbt, [
        { kind: "replace-value", location: { kind: "output", index }, keyType: 4, valueHex },
      ]);
    const ordinary = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
    expect(discoverReceiverOutputs(replaceScript(first.index, ordinary))).toEqual([]);
    expect(discoverReceiverOutputs(replaceScript(second.index, ordinary))).toEqual([first]);
    expect(() => discoverReceiverOutputs(replaceScript(second.index, first.scriptHex))).toThrow(
      /Duplicate/,
    );
  });
  test(`discovery ignores recipient metadata and finds reversed k positions: shuffled=${variant.shuffle}`, () => {
    const doc = parsePsbtDocument(variant.output.finalizedPsbt);
    const stripped = applyPsbtMutations(
      variant.output.finalizedPsbt,
      doc.maps.flatMap((m) =>
        m.entries
          .filter(
            (e) =>
              (m.location.kind === "input" && [29, 30].includes(e.keyType)) ||
              (m.location.kind === "output" && [9, 10].includes(e.keyType)),
          )
          .map((e) => ({
            kind: "delete-entry" as const,
            location: m.location,
            keyType: e.keyType,
            keyDataHex: e.keyData.toString("hex"),
          })),
      ),
    );
    const clean = parsePsbtDocument(stripped);
    const outputs = clean.maps.filter((m) => m.location.kind === "output");
    // Scanner-only mutation: changing signed output order invalidates its signatures.
    const reversed = applyPsbtMutations(stripped, [
      ...outputs.flatMap((m) =>
        m.entries.map((e) => ({
          kind: "delete-entry" as const,
          location: m.location,
          keyType: e.keyType,
          keyDataHex: e.keyData.toString("hex"),
        })),
      ),
      ...[...outputs].reverse().flatMap((m, index) =>
        m.entries.map((e) => ({
          kind: "set-entry" as const,
          location: { kind: "output" as const, index },
          keyType: e.keyType,
          keyDataHex: e.keyData.toString("hex"),
          valueHex: e.value.toString("hex"),
        })),
      ),
    ]);
    const original = discoverReceiverOutputs(stripped),
      actual = discoverReceiverOutputs(reversed);
    expect(actual.map((o) => o.index)).toEqual(original.map((o) => 2 - o.index));
    expect(actual.map((o) => o.tweakHex)).toEqual(original.map((o) => o.tweakHex));
  });
}

for (const v of fixture.variants)
  test(`verifies two-output sender intent and proofs: shuffled=${v.shuffle}`, () => {
    expect(verifyMultiSender(fixture.template, v.output.psbt, "per-input", false, v.shuffle)).toBe(
      true,
    );
    expect(verifyMultiSender(fixture.template, v.output.psbt, "per-input", false, !v.shuffle)).toBe(
      false,
    );
    const changed = applyPsbtMutations(v.output.psbt, [
      {
        kind: "replace-value",
        location: { kind: "output", index: 1 },
        keyType: 3,
        valueHex: "0100000000000000",
      },
    ]);
    expect(verifyMultiSender(fixture.template, changed, "per-input", false, v.shuffle)).toBe(false);
  });

test.each([
  { receiver: "native", correctIdentity: true },
  { receiver: "spdk", correctIdentity: true },
  { receiver: "spdk", correctIdentity: false },
] as const)(
  "runs both layouts with $receiver signing; correct wallet identity: $correctIdentity",
  async ({ receiver, correctIdentity }) => {
    const commitment = `sha256:${"a".repeat(64)}`;
    const initial = fixture.variants[0];
    if (!initial) throw new Error("Missing fixture");
    let active = initial;
    const calls: string[] = [];
    const request = async (req: AdapterRequest): Promise<AdapterResponse> => {
      const base = {
        protocol: req.protocol,
        id: req.id,
        implementation: { name: "test", version: "test", artifactDigest: commitment },
      };
      if (req.operation === "convert")
        return {
          ...base,
          status: "ok",
          output: { psbt: fixture.template, unsignedTxSha256: commitment },
        };
      if (req.operation === "silent-payment-send") {
        const v = fixture.variants.find((v) => v.shuffle === req.payload["shuffleOutputs"]);
        if (!v) throw new Error("Missing layout");
        active = v;
        return { ...base, status: "ok", output: v.output };
      }
      if (req.operation === "extract")
        return {
          ...base,
          status: "ok",
          output: {
            transaction:
              req.payload["psbt"] === active.output.finalizedPsbt
                ? active.output.transaction
                : active.receiverOutput.transaction,
          },
        };
      if (req.payload["network"] !== "regtest")
        return {
          ...base,
          status: "rejected",
          error: { class: "policy.network_not_allowed", message: "canary" },
        };
      if (req.payload["psbt"] !== active.child)
        return {
          ...base,
          status: "rejected",
          error: { class: "silent_payment.receiver_link_invalid", message: "canary" },
        };
      expect(req.payload["receiver"]).toBe(receiver === "spdk" ? "spdk" : undefined);
      return {
        ...base,
        status: "ok",
        output: {
          ...active.receiverOutput,
          ...(receiver === "spdk"
            ? {
                receiverImplementation: correctIdentity
                  ? "spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7"
                  : "spdk-wallet/unknown",
              }
            : {}),
        },
      };
    };
    const call = async (method: string, params: unknown) => {
      calls.push(method);
      const { rawtxs } = params as { rawtxs: string[] };
      return rawtxs.length === 2
        ? [
            { allowed: true, txid: active.output.transactionId },
            { allowed: true, txid: active.receiverOutput.transactionId },
          ]
        : rawtxs[0] === active.output.transaction
          ? [{ allowed: true, txid: active.output.transactionId }]
          : [
              {
                allowed: false,
                txid: active.receiverOutput.transactionId,
                "reject-reason": "missing-inputs",
              },
            ];
    };
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
    const prepared = {
      id: "bip352-multi-output",
      psbtVersion: 0,
      inputCount: 2,
      outputCount: 3,
      initialPsbt: fixture.template,
      unsignedTxSha256: commitment,
    } as PsbtFixture;
    const result = await createSilentPaymentLifecycleScenario(prepared, receiver).run(context);
    const failed = result.assertions.filter((a) => !a.passed);
    if (correctIdentity) expect(failed).toEqual([]);
    else {
      expect(failed).toHaveLength(2);
      expect(failed.every((a) => a.name.includes("spdk-implementation"))).toBe(true);
    }
    expect(result.policyAccepted).toBe(true);
    expect(result.assertions).toHaveLength(receiver === "spdk" ? 46 : 44);
    expect(context.checkpoints).toHaveLength(12);
    expect(new Set(context.checkpoints.map((c) => c.stage)).size).toBe(12);
    expect(calls).toEqual(Array(6).fill("testmempoolaccept"));
  },
);
