import type { PsbtFixture } from "../core/fixtures.js";
import type { CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import type { ScenarioDefinition, ScenarioExecutionOutput } from "./definition.js";

export function classifyHappyPath(
  complete: boolean,
  policy: CorePolicyResult,
  adapterName = "rust-bitcoin",
): Pick<ScenarioExecutionOutput, "summary" | "policyAccepted" | "transactionId"> {
  const passed = complete && policy.allowed;
  return {
    summary: passed
      ? `${adapterName} signed the Core-created PSBT; Bitcoin Core finalized it and accepted the transaction under current regtest mempool policy.`
      : `The happy path did not produce a complete policy-accepted transaction${policy.rejectReason ? ` (${policy.rejectReason})` : ""}.`,
    policyAccepted: policy.allowed,
    ...(policy.txid ? { transactionId: policy.txid } : {}),
  };
}

export interface SigningHandoffScenarioOptions {
  readonly adapter: string;
  readonly id: string;
  readonly title: string;
}

const DEFAULT_HANDOFF_OPTIONS: SigningHandoffScenarioOptions = {
  adapter: "rust-bitcoin",
  id: "happy-path",
  title: "Core to rust-bitcoin signing handoff",
};

export function createHappyPathScenario(
  fixture: PsbtFixture,
  options: SigningHandoffScenarioOptions = DEFAULT_HANDOFF_OPTIONS,
): ScenarioDefinition<ScenarioExecutionContext> {
  const assertionPrefix = options.adapter === "rust-bitcoin" ? "rust" : options.adapter;
  return {
    id: options.id,
    title: options.title,
    category: "cross-library-signing",
    summary: "A Core-created P2WSH PSBT survives rust-bitcoin signing and Core finalization.",
    requirements: [
      {
        adapter: options.adapter,
        operations: ["roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions = [];
      await context.checkpoint(options.id, "core-created", fixture.initialPsbt);

      const roundtripResponse = await context.request(options.adapter, "roundtrip", {
        psbt: fixture.initialPsbt,
      });
      const roundtripPsbt = context.outputString(roundtripResponse, "psbt", "roundtrip");
      assertions.push(
        context.requireTransition(
          "roundtrip",
          `${assertionPrefix}-roundtrip`,
          fixture.initialPsbt,
          roundtripPsbt,
        ),
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

      const finalized = await context.finalizeWithCore(signedPsbt);
      const policy = await context.policyCheck(finalized);
      assertions.push({
        name: "core-finalized",
        passed: finalized.complete && typeof finalized.hex === "string",
        summary: finalized.complete
          ? "Core finalized the PSBT"
          : "Core could not finalize the PSBT",
      });
      assertions.push({
        name: "core-policy-accepted",
        passed: policy.allowed,
        summary: policy.allowed
          ? "Core accepted the transaction under regtest mempool policy"
          : `Core rejected the transaction${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
      });

      return {
        ...classifyHappyPath(finalized.complete, policy, options.adapter),
        assertions,
      };
    },
  };
}
