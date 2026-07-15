import type { PsbtFixture } from "../core/fixtures.js";
import type { AdapterResponse } from "../protocol/types.js";
import type { CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import type { ScenarioDefinition, ScenarioExecutionOutput } from "./definition.js";

const EXPECTED_ERROR_CLASS = "finalize.missing_witness_script";

function isExpectedBdkFailure(response: AdapterResponse): boolean {
  return (
    response.status === "rejected" &&
    response.implementation.name === "bdkpython" &&
    response.implementation.version === "2.3.1" &&
    response.error.class === EXPECTED_ERROR_CLASS
  );
}

export function classifyRegression(
  bdkResponse: AdapterResponse,
  coreComplete: boolean,
  policy: CorePolicyResult,
): Pick<
  ScenarioExecutionOutput,
  "summary" | "expectedFailure" | "policyAccepted" | "transactionId"
> {
  const reproduced = isExpectedBdkFailure(bdkResponse);
  const passed = reproduced && coreComplete && policy.allowed;
  return {
    summary: passed
      ? "BDK Python 2.3.1 reproduced issue #488 on an already-finalized first input, while Bitcoin Core finalized the same PSBT and accepted the extracted transaction under mempool policy."
      : "The historical BDK failure, Core finalization, and policy acceptance did not all match the expected regression behavior.",
    ...(reproduced
      ? {
          expectedFailure: {
            implementation: `${bdkResponse.implementation.name}@${bdkResponse.implementation.version}`,
            errorClass: EXPECTED_ERROR_CLASS,
          },
        }
      : {}),
    policyAccepted: policy.allowed,
    ...(policy.txid ? { transactionId: policy.txid } : {}),
  };
}

export interface RegressionScenarioOptions {
  readonly adapter: string;
  readonly id: string;
  readonly title: string;
}

const DEFAULT_REGRESSION_OPTIONS: RegressionScenarioOptions = {
  adapter: "rust-bitcoin",
  id: "bdk-finalize-regression",
  title: "BDK mixed-input finalization regression",
};

export function createBdkRegressionScenario(
  fixture: PsbtFixture,
  options: RegressionScenarioOptions = DEFAULT_REGRESSION_OPTIONS,
): ScenarioDefinition<ScenarioExecutionContext> {
  const assertionPrefix = options.adapter === "rust-bitcoin" ? "rust" : options.adapter;
  return {
    id: options.id,
    title: options.title,
    category: "historical-regression",
    summary:
      "A mixed finalized and partial PSBT reproduces BDK issue #488 without invalidating it.",
    requirements: [
      {
        adapter: options.adapter,
        operations: ["sign", "finalize-inputs"],
        roles: ["signer", "finalizer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "bdkpython",
        operations: ["roundtrip", "finalize"],
        roles: ["parser", "finalizer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["historical-regression.bdk-wallet-488"],
      },
    ],
    async run(context) {
      const assertions = [];
      await context.checkpoint(options.id, "core-created", fixture.initialPsbt);

      const roundtripResponse = await context.request("bdkpython", "roundtrip", {
        psbt: fixture.initialPsbt,
      });
      const roundtripPsbt = context.outputString(roundtripResponse, "psbt", "roundtrip");
      assertions.push(
        context.requireTransition("roundtrip", "bdk-roundtrip", fixture.initialPsbt, roundtripPsbt),
      );

      const signResponse = await context.request(options.adapter, "sign", {
        psbt: roundtripPsbt,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signedPsbt = context.outputString(signResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          `${assertionPrefix}-signing-transition`,
          roundtripPsbt,
          signedPsbt,
        ),
      );
      assertions.push(
        context.requireAddedInputField(
          `${assertionPrefix}-added-signature`,
          roundtripPsbt,
          signedPsbt,
          [0x02, 0x13, 0x14],
        ),
      );
      await context.checkpoint(options.id, `${assertionPrefix}-signed`, signedPsbt);

      const finalizeResponse = await context.request(options.adapter, "finalize-inputs", {
        psbt: signedPsbt,
        network: "regtest",
        fixtureId: fixture.id,
        inputIndexes: [0],
      });
      const mixedPsbt = context.outputString(finalizeResponse, "psbt", "finalize-inputs");
      assertions.push(
        context.requireTransition(
          "finalize",
          `${assertionPrefix}-finalization-transition`,
          signedPsbt,
          mixedPsbt,
        ),
      );
      assertions.push(
        context.requireAddedInputField(
          `${assertionPrefix}-finalized-input-0`,
          signedPsbt,
          mixedPsbt,
          [0x07, 0x08],
          [0],
        ),
      );
      await context.checkpoint(options.id, "input-0-finalized", mixedPsbt);

      const bdkResponse = await context.request("bdkpython", "finalize", {
        psbt: mixedPsbt,
        network: "regtest",
        fixtureId: fixture.id,
      });
      if (bdkResponse.status === "crashed" || bdkResponse.status === "timeout") {
        throw new Error(
          `bdkpython finalize failed: ${bdkResponse.error.class}: ${bdkResponse.error.message}`,
        );
      }
      const reproduced = isExpectedBdkFailure(bdkResponse);
      assertions.push({
        name: "bdk-regression-reproduced",
        passed: reproduced,
        summary: reproduced
          ? `BDK returned ${EXPECTED_ERROR_CLASS}`
          : "BDK did not return the frozen regression error",
      });

      const finalized = await context.finalizeWithCore(mixedPsbt);
      const policy = await context.policyCheck(finalized);
      assertions.push({
        name: "core-finalized",
        passed: finalized.complete && typeof finalized.hex === "string",
        summary: finalized.complete
          ? "Core finalized the mixed PSBT"
          : "Core could not finalize the mixed PSBT",
      });
      assertions.push({
        name: "core-policy-accepted",
        passed: policy.allowed,
        summary: policy.allowed
          ? "Core accepted the mixed-state transaction"
          : `Core rejected the transaction${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
      });

      return {
        ...classifyRegression(bdkResponse, finalized.complete, policy),
        assertions,
      };
    },
  };
}
