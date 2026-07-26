import { FIXTURE_PUBLIC_KEYS } from "../core/fixture-profiles.js";
import type { PsbtFixture } from "../core/fixtures.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export const HWI_DEVICE_FINGERPRINT = "73c5da0a";
export const HWI_DERIVATION_PATH_HEX = "5400008001000080000000800000000000000000";

export function initializeHwiKeyOrigin(psbt: string): string {
  return applyPsbtMutations(psbt, [
    {
      kind: "set-entry",
      location: { kind: "input", index: 0 },
      keyType: 0x06,
      keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
      valueHex: `${HWI_DEVICE_FINGERPRINT}${HWI_DERIVATION_PATH_HEX}`,
    },
  ]);
}

export function createHwiSimulatorScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (!fixture.scriptTypes.includes("p2wpkh")) {
    throw new Error("The HWI simulator scenario requires a P2WPKH fixture");
  }
  return {
    id: "hwi-simulator-p2wpkh",
    title: "Simulator-backed HWI signing handoff",
    category: "hardware-signing",
    summary:
      "Exercises an HWI-compatible JSON process, simulated user refusal, origin-scoped signing, and Bitcoin Core finalization without requiring a physical device.",
    requirements: [
      {
        adapter: "hwi-simulator",
        operations: ["roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
        features: [
          "fixture-commitment-sha256",
          "hwi-json-process-v1",
          "hwi-simulator-v1",
          "simulated-user-confirmation-v1",
          "network-free",
        ],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const originPsbt = initializeHwiKeyOrigin(fixture.initialPsbt);
      await context.checkpoint("hwi-simulator-p2wpkh", "device-origin", originPsbt);

      const roundtripResponse = await context.request("hwi-simulator", "roundtrip", {
        psbt: originPsbt,
      });
      const roundtripPsbt = context.outputString(
        roundtripResponse,
        "psbt",
        "HWI simulator roundtrip",
      );
      assertions.push(
        context.requireTransition(
          "roundtrip",
          "hwi-preserved-device-origin",
          originPsbt,
          roundtripPsbt,
          "hwi-simulator",
        ),
      );

      const refused = await context.request("hwi-simulator", "sign", {
        psbt: roundtripPsbt,
        network: "regtest",
        fixtureId: fixture.id,
        userAction: "reject",
      });
      assertions.push({
        name: "simulated-user-refusal",
        passed: refused.status === "rejected" && refused.error.class === "hwi.action_canceled",
        likelyImplementation: "hwi-simulator",
        summary:
          refused.status === "rejected"
            ? `The simulated device refused signing as ${refused.error.class}.`
            : `The simulated device returned ${refused.status} for a refused confirmation.`,
      });

      const signResponse = await context.request("hwi-simulator", "sign", {
        psbt: roundtripPsbt,
        network: "regtest",
        fixtureId: fixture.id,
        userAction: "approve",
      });
      const signedPsbt = context.outputString(signResponse, "psbt", "HWI simulator sign");
      assertions.push(
        context.requireTransition(
          "sign",
          "hwi-signature-only-transition",
          roundtripPsbt,
          signedPsbt,
          "hwi-simulator",
        ),
      );
      assertions.push(
        context.requireAddedInputField(
          "hwi-added-p2wpkh-signature",
          roundtripPsbt,
          signedPsbt,
          [0x02],
        ),
      );
      await context.checkpoint("hwi-simulator-p2wpkh", "device-signed", signedPsbt);

      const finalized = await context.finalizeWithCore(signedPsbt);
      const policy = await context.policyCheck(finalized);
      assertions.push({
        name: "core-finalized-hwi-signature",
        passed: finalized.complete && typeof finalized.hex === "string",
        summary: finalized.complete
          ? "Core finalized the simulator-signed PSBT."
          : "Core could not finalize the simulator-signed PSBT.",
      });
      assertions.push({
        name: "core-policy-accepted-hwi-spend",
        passed: policy.allowed,
        summary: policy.allowed
          ? "Core accepted the simulator-signed transaction under regtest mempool policy."
          : `Core rejected the simulator-signed transaction${policy.rejectReason ? `: ${policy.rejectReason}` : "."}`,
      });

      return {
        summary:
          finalized.complete && policy.allowed
            ? "The HWI-compatible simulator enforced confirmation and key-origin policy, signed in a separate process, and produced a Core-accepted transaction."
            : "The simulator-backed hardware signing workflow did not produce a complete policy-accepted transaction.",
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
        assertions,
      };
    },
  };
}
