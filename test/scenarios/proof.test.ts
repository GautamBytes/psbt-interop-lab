import { describe, expect, test } from "vitest";
import type { AdapterResponse } from "../../src/protocol/types.js";
import { classifyHappyPath, classifyRegression } from "../../src/scenarios/proof.js";

const expectedBdkFailure: AdapterResponse = {
  protocol: "psbt-lab.adapter/0.1",
  id: "reg-bdk",
  status: "rejected",
  implementation: {
    name: "bdkpython",
    version: "2.3.1",
    artifactDigest: `sha256:${"a".repeat(64)}`,
  },
  error: {
    class: "finalize.missing_witness_script",
    message: "Expected historical failure",
  },
};

describe("proof scenario classification", () => {
  test("passes a complete policy-accepted happy path", () => {
    expect(classifyHappyPath(true, { allowed: true, txid: "abc" })).toMatchObject({
      id: "happy-path",
      outcome: "passed",
      policyAccepted: true,
      transactionId: "abc",
    });
  });

  test("fails a happy path rejected by Core policy", () => {
    expect(
      classifyHappyPath(true, {
        allowed: false,
        rejectReason: "mandatory-script-verify-flag-failed",
      }),
    ).toMatchObject({ outcome: "failed", policyAccepted: false });
  });

  test("passes when BDK reproduces issue 488 and Core accepts the same PSBT", () => {
    expect(
      classifyRegression(expectedBdkFailure, true, { allowed: true, txid: "def" }),
    ).toMatchObject({
      id: "bdk-finalize-regression",
      outcome: "passed",
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
    ).toMatchObject({ outcome: "failed" });
  });
});
