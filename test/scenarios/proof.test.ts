import { describe, expect, test } from "vitest";
import type { AdapterResponse } from "../../src/protocol/types.js";
import {
  classifyHappyPath,
  classifyRegression,
  serializeFixtureCommitments,
} from "../../src/scenarios/proof.js";

const expectedBdkFailure: AdapterResponse = {
  protocol: "psbt-lab.adapter/0.2",
  id: "reg-bdk",
  status: "rejected",
  implementation: {
    name: "bdkpython",
    version: "2.3.1",
    artifactDigest: `sha256:${"a".repeat(64)}`,
    sourceRevision: "bdk-ffi-v2.3.1",
  },
  error: {
    class: "finalize.missing_witness_script",
    message: "Expected historical failure",
  },
};

describe("proof scenario classification", () => {
  test("passes a complete policy-accepted happy path", () => {
    expect(classifyHappyPath(true, { allowed: true, txid: "abc" })).toMatchObject({
      policyAccepted: true,
      transactionId: "abc",
      summary: expect.stringMatching(/signed.*accepted/i),
    });
  });

  test("fails a happy path rejected by Core policy", () => {
    expect(
      classifyHappyPath(true, {
        allowed: false,
        rejectReason: "mandatory-script-verify-flag-failed",
      }),
    ).toMatchObject({
      policyAccepted: false,
      summary: expect.stringContaining("mandatory-script-verify-flag-failed"),
    });
  });

  test("passes when BDK reproduces issue 488 and Core accepts the same PSBT", () => {
    expect(
      classifyRegression(expectedBdkFailure, true, { allowed: true, txid: "def" }),
    ).toMatchObject({
      expectedFailure: {
        implementation: "bdkpython@2.3.1",
        errorClass: "finalize.missing_witness_script",
      },
      policyAccepted: true,
    });
  });

  test("fails when the historical BDK rejection is not reproduced", () => {
    const unexpectedSuccess: AdapterResponse = {
      ...expectedBdkFailure,
      status: "ok",
      output: {},
    };
    delete (unexpectedSuccess as Partial<AdapterResponse> & { error?: unknown }).error;

    expect(
      classifyRegression(unexpectedSuccess, true, { allowed: true, txid: "def" }),
    ).toMatchObject({
      summary: expect.stringMatching(/did not all match/i),
    });
  });

  test("serializes only bounded fixture ids and unsigned transaction commitments", () => {
    expect(
      serializeFixtureCommitments([
        { id: "happy-path", unsignedTxSha256: `sha256:${"b".repeat(64)}` },
        {
          id: "bdk-finalize-regression",
          unsignedTxSha256: `sha256:${"c".repeat(64)}`,
        },
      ]),
    ).toBe(
      JSON.stringify({
        "happy-path": `sha256:${"b".repeat(64)}`,
        "bdk-finalize-regression": `sha256:${"c".repeat(64)}`,
      }),
    );

    expect(() =>
      serializeFixtureCommitments([
        { id: "../unsafe", unsignedTxSha256: `sha256:${"b".repeat(64)}` },
      ]),
    ).toThrow(/fixture id/i);
  });
});
