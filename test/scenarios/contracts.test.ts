import { describe, expect, test } from "vitest";
import type {
  AdapterImplementation,
  AdapterResponse,
  JsonValue,
} from "../../src/protocol/types.js";
import {
  assertAdapterHello,
  assertByteIdenticalRoundtrip,
  RUST_ADAPTER_CONTRACT,
} from "../../src/scenarios/contracts.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const IMPLEMENTATION: AdapterImplementation = {
  name: "rust-bitcoin",
  version: "0.1.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
  sourceRevision: "bitcoin-crate-0.32.101",
};

function success(
  output: Record<string, JsonValue>,
  implementation: AdapterImplementation = IMPLEMENTATION,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: "request-1",
    status: "ok",
    implementation,
    output,
  };
}

function hello(
  implementation: Partial<AdapterImplementation> = {},
  output: Record<string, JsonValue> = {
    operations: [...RUST_ADAPTER_CONTRACT.operations],
    roles: [...RUST_ADAPTER_CONTRACT.roles],
    psbtVersions: [0],
    scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
  },
): AdapterResponse {
  return success(output, { ...IMPLEMENTATION, ...implementation });
}

describe("adapter contracts", () => {
  test("rejects a lying byte-identical response", () => {
    const source = MINIMAL_PSBT;
    const changedBytes = Buffer.from(source, "base64");
    changedBytes[8] = changedBytes[8] === 1 ? 2 : 1;
    const changed = changedBytes.toString("base64");
    const response = success({ psbt: changed, byteIdentical: true });

    expect(() => assertByteIdenticalRoundtrip(response, source, "rust-bitcoin")).toThrow(
      /changed/i,
    );
  });

  test("returns a genuinely identical PSBT", () => {
    const response = success({ psbt: MINIMAL_PSBT, byteIdentical: true });
    expect(assertByteIdenticalRoundtrip(response, MINIMAL_PSBT, "rust-bitcoin")).toBe(MINIMAL_PSBT);
  });

  test("rejects a wrong adapter source revision", () => {
    const response = hello({ sourceRevision: "bitcoin-crate-0.32.100" });
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/source revision/i);
  });

  test("rejects a missing required operation", () => {
    const response = hello(
      {},
      {
        operations: ["hello", "roundtrip"],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [0],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
      },
    );
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/operation sign/i);
  });

  test("rejects an adapter without PSBTv0 support", () => {
    const response = hello(
      {},
      {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [2],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
      },
    );
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/PSBTv0/i);
  });

  test.each([
    ["role", "roles", ["parser", "signer"]],
    ["script type", "scriptTypes", ["p2wpkh"]],
  ] as const)("rejects falsely declared required %s support", (_label, key, value) => {
    const response = hello(
      {},
      {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [...RUST_ADAPTER_CONTRACT.psbtVersions],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        [key]: [...value],
      },
    );

    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(
      /omitted|does not support/i,
    );
  });

  test("returns typed negotiated capabilities", () => {
    const negotiated = assertAdapterHello(hello(), RUST_ADAPTER_CONTRACT);

    expect(negotiated).toEqual({
      implementation: IMPLEMENTATION,
      capabilities: {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [...RUST_ADAPTER_CONTRACT.psbtVersions],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
      },
    });
  });
});
