import type { PsbtFixture } from "../core/fixtures.js";
import type { CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const ROUNDTRIP_CHAIN = ["bdkpython", "rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"] as const;

function coreAssertions(
  complete: boolean,
  hasTransaction: boolean,
  policy: CorePolicyResult,
): ScenarioAssertionEvidence[] {
  return [
    {
      name: "core-finalized",
      passed: complete && hasTransaction,
      summary: complete ? "Core finalized the PSBT" : "Core could not finalize the PSBT",
    },
    {
      name: "core-policy-accepted",
      passed: policy.allowed,
      summary: policy.allowed
        ? "Core accepted the extracted transaction"
        : `Core rejected the transaction${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
    },
  ];
}

export function createRoundtripChainScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "four-library-roundtrip-chain",
    title: "Four-library roundtrip and signing chain",
    category: "multi-library-handoff",
    summary:
      "The same PSBT passes through four implementations before signing and Core validation.",
    requirements: [
      ...ROUNDTRIP_CHAIN.map((adapter) => ({
        adapter,
        operations: ["roundtrip"] as const,
        roles: ["parser"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2wsh"] as const,
      })),
      {
        adapter: "bitcoinjs-lib",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      await context.checkpoint("four-library-roundtrip-chain", "core-created", fixture.initialPsbt);
      let current = fixture.initialPsbt;
      for (const adapter of ROUNDTRIP_CHAIN) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition("roundtrip", `${adapter}-roundtrip`, before, current),
        );
      }

      const signResponse = await context.request("bitcoinjs-lib", "sign", {
        psbt: current,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(signResponse, "psbt", "sign");
      assertions.push(
        context.requireTransition("sign", "bitcoinjs-lib-signing-transition", current, signed),
      );
      assertions.push(
        context.requireAddedInputField(
          "bitcoinjs-lib-added-signature",
          current,
          signed,
          [0x02, 0x13, 0x14],
        ),
      );
      await context.checkpoint("four-library-roundtrip-chain", "bitcoinjs-lib-signed", signed);

      const finalized = await context.finalizeWithCore(signed);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "BDK, rust-bitcoin, btcsuite, and bitcoinjs-lib preserved the PSBT before bitcoinjs-lib signed it and Core accepted it."
            : "The four-library handoff did not end in a complete policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function createParallelCombineScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "parallel-sign-and-combine",
    title: "Parallel rust-bitcoin and btcsuite signing",
    category: "parallel-signing",
    summary:
      "Two libraries sign different inputs on independent copies before bitcoinjs-lib combines their contributions and Core validates them.",
    requirements: [
      {
        adapter: "rust-bitcoin",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "btcsuite-go",
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
        features: ["fixture-commitment-sha256"],
      },
      {
        adapter: "bitcoinjs-lib",
        operations: ["combine"],
        roles: ["combiner"],
        psbtVersions: [0],
        scriptTypes: ["p2wsh"],
      },
    ],
    async run(context) {
      if (fixture.inputCount < 2) {
        throw new Error("Parallel signing requires a fixture with at least two inputs");
      }
      const assertions: ScenarioAssertionEvidence[] = [];
      await context.checkpoint("parallel-sign-and-combine", "core-created", fixture.initialPsbt);
      const signedCopies: string[] = [];

      for (const [inputIndex, adapter] of ["rust-bitcoin", "btcsuite-go"].entries()) {
        const response = await context.request(adapter, "sign", {
          psbt: fixture.initialPsbt,
          network: "regtest",
          fixtureId: fixture.id,
          inputIndexes: [inputIndex],
        });
        const signed = context.outputString(response, "psbt", "sign");
        assertions.push(
          context.requireTransition(
            "sign",
            `${adapter}-signing-transition`,
            fixture.initialPsbt,
            signed,
          ),
        );
        assertions.push(
          context.requireAddedInputField(
            `${adapter}-added-signature`,
            fixture.initialPsbt,
            signed,
            [0x02, 0x13, 0x14],
            [inputIndex],
          ),
        );
        assertions.push(
          context.requireInputFieldAbsence(
            `${adapter}-did-not-sign-other-input`,
            signed,
            [0x02, 0x13, 0x14],
            [inputIndex === 0 ? 1 : 0],
          ),
        );
        signedCopies.push(signed);
      }

      const combineResponse = await context.request("bitcoinjs-lib", "combine", {
        psbts: signedCopies,
      });
      const combined = context.outputString(combineResponse, "psbt", "combine");
      for (const [index, signed] of signedCopies.entries()) {
        assertions.push(
          context.requireTransition("combine", `combined-copy-${index + 1}`, signed, combined),
        );
      }
      assertions.push(
        context.requireAddedInputField(
          "combined-union-of-both-signatures",
          fixture.initialPsbt,
          combined,
          [0x02, 0x13, 0x14],
          [0, 1],
        ),
      );
      await context.checkpoint("parallel-sign-and-combine", "bitcoinjs-lib-combined", combined);

      const finalized = await context.finalizeWithCore(combined);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        ...coreAssertions(finalized.complete, typeof finalized.hex === "string", policy),
      );
      return {
        summary:
          finalized.complete && policy.allowed
            ? "rust-bitcoin signed input 0, btcsuite signed input 1, bitcoinjs-lib preserved both contributions, and Core accepted the result."
            : "The independently signed copies did not combine into a complete policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
