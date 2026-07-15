import { describe, expect, test } from "vitest";
import { validateAdapterRequest, validateAdapterResponse } from "../../src/protocol/schema.js";

const VALID_DIGEST = `sha256:${"a".repeat(64)}`;

describe("adapter protocol schemas", () => {
  test("accepts a hello request", () => {
    expect(
      validateAdapterRequest({
        protocol: "psbt-lab.adapter/0.1",
        id: "hello-1",
        operation: "hello",
        payload: {},
      }),
    ).toEqual({ ok: true });
  });

  test("rejects unknown request properties", () => {
    const result = validateAdapterRequest({
      protocol: "psbt-lab.adapter/0.1",
      id: "hello-1",
      operation: "hello",
      payload: {},
      command: "rm -rf /",
    });

    expect(result.ok).toBe(false);
  });

  test("rejects unsafe request identifiers", () => {
    const result = validateAdapterRequest({
      protocol: "psbt-lab.adapter/0.1",
      id: "../../artifact",
      operation: "hello",
      payload: {},
    });

    expect(result.ok).toBe(false);
  });

  test("accepts a successful response", () => {
    expect(
      validateAdapterResponse({
        protocol: "psbt-lab.adapter/0.1",
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
      protocol: "psbt-lab.adapter/0.1",
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
      protocol: "psbt-lab.adapter/0.1",
      id: "hello-1",
      status: "ok",
      implementation: { name: "fake", version: "1.0.0", artifactDigest },
      output: {},
    });
    expect(result.ok).toBe(false);
  });
});
