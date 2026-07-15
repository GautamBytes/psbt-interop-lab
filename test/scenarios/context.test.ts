import { describe, expect, test, vi } from "vitest";
import type { RpcCaller } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import {
  type AdapterRequestClient,
  ScenarioExecutionContext,
} from "../../src/scenarios/context.js";
import { ScenarioAssertionError } from "../../src/scenarios/engine.js";

const magic = Buffer.from("70736274ff", "hex");

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
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

function unsignedTransaction(): Buffer {
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x11),
    Buffer.from("01000000", "hex"),
    Buffer.from([0]),
    Buffer.from("feffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1]),
    Buffer.from("51", "hex"),
    Buffer.from("00000000", "hex"),
  ]);
}

function psbt(globalEntries: Buffer[]): string {
  return Buffer.concat([magic, map(...globalEntries), map(), map()]).toString("base64");
}

const unsignedTxEntry = entry(0x00, unsignedTransaction());
const proprietaryEntry = entry(
  0xfc,
  Buffer.from("private metadata"),
  Buffer.from("036c616201", "hex"),
);

function response(
  request: AdapterRequest,
  status: AdapterResponse["status"] = "ok",
): AdapterResponse {
  const implementation = {
    name: "rust-bitcoin",
    version: "0.1.0",
    artifactDigest: `sha256:${"a".repeat(64)}`,
  };
  if (status === "ok") {
    return {
      protocol: "psbt-lab.adapter/0.2",
      id: request.id,
      status,
      implementation,
      output: { psbt: request.payload["psbt"] ?? "" },
    };
  }
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status,
    implementation,
    error: { class: `adapter.${status}`, message: `${status} response` },
  };
}

function fakeAdapter(
  status: AdapterResponse["status"] = "ok",
): AdapterRequestClient & { requests: AdapterRequest[] } {
  const requests: AdapterRequest[] = [];
  return {
    requests,
    request: vi.fn(async (request: AdapterRequest) => {
      requests.push(request);
      return response(request, status);
    }),
  };
}

function context(
  adapter: AdapterRequestClient = fakeAdapter(),
  rpc: RpcCaller = { call: vi.fn() },
): ScenarioExecutionContext {
  return new ScenarioExecutionContext({
    rpc,
    artifacts: { checkpoint: vi.fn() },
    adapters: new Map([["rust-bitcoin", adapter]]),
    adapterTimeoutMs: 1_000,
  });
}

describe("ScenarioExecutionContext", () => {
  test("accepts semantic roundtrip preservation despite map reordering", () => {
    const before = psbt([unsignedTxEntry, proprietaryEntry]);
    const after = psbt([proprietaryEntry, unsignedTxEntry]);

    expect(context().transitionEvidence("roundtrip", "metadata-preserved", before, after)).toEqual({
      name: "metadata-preserved",
      policy: "roundtrip",
      passed: true,
      exactBytesEqual: false,
      failures: [],
    });
  });

  test("returns sanitized field-level mutation evidence", () => {
    const evidence = context().transitionEvidence(
      "roundtrip",
      "metadata-preserved",
      psbt([unsignedTxEntry, proprietaryEntry]),
      psbt([unsignedTxEntry]),
    );

    expect(evidence).toMatchObject({
      passed: false,
      failures: [{ code: "ENTRY_REMOVED", location: { kind: "global" }, keyType: 252 }],
    });
    expect(JSON.stringify(evidence)).not.toContain("private metadata");
  });

  test("turns a semantic transition failure into a normal scenario assertion", () => {
    expect(() =>
      context().requireTransition(
        "roundtrip",
        "metadata-preserved",
        psbt([unsignedTxEntry, proprietaryEntry]),
        psbt([unsignedTxEntry]),
      ),
    ).toThrow(ScenarioAssertionError);
  });

  test("frames adapter requests with stable incrementing protocol ids", async () => {
    const adapter = fakeAdapter();
    const value = context(adapter);

    await value.request("rust-bitcoin", "roundtrip", { psbt: "first" });
    await value.request("rust-bitcoin", "roundtrip", { psbt: "second" });

    expect(adapter.requests.map(({ protocol, id }) => ({ protocol, id }))).toEqual([
      { protocol: "psbt-lab.adapter/0.2", id: "request-1" },
      { protocol: "psbt-lab.adapter/0.2", id: "request-2" },
    ]);
  });

  test("treats a normal adapter rejection as a scenario assertion failure", async () => {
    const value = context(fakeAdapter("rejected"));
    const rejected = await value.request("rust-bitcoin", "sign", {});

    expect(() => value.outputString(rejected, "psbt", "sign")).toThrow(ScenarioAssertionError);
  });

  test.each(["crashed", "timeout"] as const)(
    "treats adapter %s as an infrastructure failure",
    async (status) => {
      const value = context(fakeAdapter(status));
      const failed = await value.request("rust-bitcoin", "sign", {});

      expect(() => value.outputString(failed, "psbt", "sign")).toThrowError(
        new Error(`rust-bitcoin sign failed: adapter.${status}: ${status} response`),
      );
    },
  );

  test("rejects an unknown adapter before sending a request", async () => {
    await expect(context().request("missing", "hello", {})).rejects.toThrow(/not available/i);
  });

  test("finalizes with Core and policy-checks the extracted transaction", async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce({ complete: true, hex: "02000000" })
      .mockResolvedValueOnce([{ allowed: true, txid: "d".repeat(64) }]);
    const value = context(fakeAdapter(), { call } as unknown as RpcCaller);

    const finalized = await value.finalizeWithCore("encoded-psbt");
    const policy = await value.policyCheck(finalized);

    expect(finalized).toEqual({ complete: true, hex: "02000000" });
    expect(policy).toEqual({ allowed: true, txid: "d".repeat(64) });
    expect(call).toHaveBeenNthCalledWith(1, "finalizepsbt", {
      psbt: "encoded-psbt",
      extract: true,
    });
    expect(call).toHaveBeenNthCalledWith(2, "testmempoolaccept", { rawtxs: ["02000000"] });
  });

  test("does not ask Core policy about an incomplete PSBT", async () => {
    const call = vi.fn();
    const value = context(fakeAdapter(), { call } as unknown as RpcCaller);

    await expect(value.policyCheck({ complete: false })).resolves.toEqual({
      allowed: false,
      rejectReason: "PSBT was not complete",
    });
    expect(call).not.toHaveBeenCalled();
  });

  test("rejects malformed Core finalization and policy responses", async () => {
    const invalidFinalize = context(fakeAdapter(), {
      call: vi.fn().mockResolvedValue({ complete: "yes" }),
    } as unknown as RpcCaller);
    await expect(invalidFinalize.finalizeWithCore("encoded-psbt")).rejects.toThrow(
      /completion status/i,
    );

    const invalidPolicy = context(fakeAdapter(), {
      call: vi.fn().mockResolvedValue([]),
    } as unknown as RpcCaller);
    await expect(invalidPolicy.policyCheck({ complete: true, hex: "02000000" })).rejects.toThrow(
      /result count/i,
    );
  });
});
