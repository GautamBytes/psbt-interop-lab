import { describe, expect, test } from "vitest";
import {
  parseAdapterHelloCapabilities,
  validateAdapterRequest,
  validateAdapterResponse,
} from "../../src/protocol/schema.js";

const VALID_DIGEST = `sha256:${"a".repeat(64)}`;

describe("adapter protocol schemas", () => {
  test("accepts a hello request", () => {
    expect(
      validateAdapterRequest({
        protocol: "psbt-lab.adapter/0.2",
        id: "hello-1",
        operation: "hello",
        payload: {},
      }),
    ).toEqual({ ok: true });
  });

  test("rejects unknown request properties", () => {
    const result = validateAdapterRequest({
      protocol: "psbt-lab.adapter/0.2",
      id: "hello-1",
      operation: "hello",
      payload: {},
      command: "rm -rf /",
    });

    expect(result.ok).toBe(false);
  });

  test("rejects unsafe request identifiers", () => {
    const result = validateAdapterRequest({
      protocol: "psbt-lab.adapter/0.2",
      id: "../../artifact",
      operation: "hello",
      payload: {},
    });

    expect(result.ok).toBe(false);
  });

  test.each(["fixture-finalize-input", "broadcast"])(
    "rejects unknown operation %s",
    (operation) => {
      const result = validateAdapterRequest({
        protocol: "psbt-lab.adapter/0.2",
        id: "request-1",
        operation,
        payload: {},
      });

      expect(result.ok).toBe(false);
    },
  );

  test("accepts a successful response", () => {
    expect(
      validateAdapterResponse({
        protocol: "psbt-lab.adapter/0.2",
        id: "hello-1",
        status: "ok",
        implementation: {
          name: "fake",
          version: "1.0.0",
          artifactDigest: VALID_DIGEST,
        },
        output: {},
      }),
    ).toEqual({ ok: true });
  });

  test("requires error details for rejected responses", () => {
    const result = validateAdapterResponse({
      protocol: "psbt-lab.adapter/0.2",
      id: "sign-1",
      status: "rejected",
      implementation: {
        name: "fake",
        version: "1.0.0",
        artifactDigest: VALID_DIGEST,
      },
    });

    expect(result.ok).toBe(false);
  });

  test.each([
    "sha256:deadbeef",
    `sha256:${"A".repeat(64)}`,
    `sha256:${"a".repeat(63)}`,
    `sha256:${"a".repeat(65)}`,
  ])("rejects noncanonical implementation digest %s", (artifactDigest) => {
    const result = validateAdapterResponse({
      protocol: "psbt-lab.adapter/0.2",
      id: "hello-1",
      status: "ok",
      implementation: { name: "fake", version: "1.0.0", artifactDigest },
      output: {},
    });
    expect(result.ok).toBe(false);
  });

  test("parses a strict hello capability object", () => {
    expect(
      parseAdapterHelloCapabilities({
        operations: ["hello", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2wsh", "p2tr-keypath"],
        operationScriptTypes: {
          roundtrip: ["p2wsh", "p2tr-keypath"],
        },
        features: ["historical-regression.bdk-wallet-488"],
      }),
    ).toEqual({
      operations: ["hello", "roundtrip"],
      roles: ["parser"],
      psbtVersions: [0, 2],
      scriptTypes: ["p2wsh", "p2tr-keypath"],
      operationScriptTypes: {
        roundtrip: ["p2wsh", "p2tr-keypath"],
      },
      features: ["historical-regression.bdk-wallet-488"],
    });
  });

  test.each([
    ["an undeclared operation", { sign: ["p2wsh"] }],
    ["an undeclared script type", { roundtrip: ["p2tr-keypath"] }],
  ])("rejects operation-scoped capabilities with %s", (_label, operationScriptTypes) => {
    expect(() =>
      parseAdapterHelloCapabilities({
        operations: ["hello", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        operationScriptTypes,
      }),
    ).toThrow(/hello capabilities/i);
  });

  test.each([
    ["duplicate operations", { operations: ["hello", "hello"] }],
    ["unknown roles", { roles: ["broadcaster"] }],
    ["unsupported PSBT versions", { psbtVersions: [1] }],
    ["unknown script types", { scriptTypes: ["p2sh"] }],
    ["empty required arrays", { roles: [] }],
    ["unsafe features", { features: ["not a safe feature"] }],
    ["unknown properties", { signingPolicy: "anything" }],
  ])("rejects hello capabilities with %s", (_label, override) => {
    expect(() =>
      parseAdapterHelloCapabilities({
        operations: ["hello"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        ...override,
      }),
    ).toThrow(/hello capabilities/i);
  });
});
