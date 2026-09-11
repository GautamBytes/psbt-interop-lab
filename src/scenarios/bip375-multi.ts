import type { PsbtFixture } from "../core/fixtures.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import { MULTI_KEYS, verifyMultiSender, verifyMultiWitnesses } from "./bip375-multi-verify.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const ID = "bip375-core-funded-multi-input-rust-psbt-v2";
const RUST = "rust-psbt-v2",
  WALLY = "libwally";
export function multiSenderCanaries(template: string) {
  const mutations: [string, PsbtMutationRecipe][] = [
    [
      "changed-second-input",
      {
        kind: "replace-value",
        location: { kind: "input", index: 1 },
        keyType: 15,
        valueHex: "01000000",
      },
    ],
    [
      "changed-recipient-amount",
      {
        kind: "replace-value",
        location: { kind: "output", index: 0 },
        keyType: 3,
        valueHex: "0100000000000000",
      },
    ],
    [
      "changed-change-script",
      {
        kind: "replace-value",
        location: { kind: "output", index: 1 },
        keyType: 4,
        valueHex: `0014${"00".repeat(20)}`,
      },
    ],
    [
      "supplied-recipient",
      {
        kind: "set-entry",
        location: { kind: "output", index: 0 },
        keyType: 9,
        valueHex: MULTI_KEYS[1].repeat(2),
      },
    ],
    [
      "supplied-share",
      {
        kind: "set-entry",
        location: { kind: "input", index: 1 },
        keyType: 29,
        keyDataHex: MULTI_KEYS[1],
        valueHex: MULTI_KEYS[1],
      },
    ],
    [
      "supplied-proof",
      {
        kind: "set-entry",
        location: { kind: "input", index: 1 },
        keyType: 30,
        keyDataHex: MULTI_KEYS[1],
        valueHex: "00".repeat(64),
      },
    ],
  ];
  const canaries = mutations.map(([name, mutation]) => ({
    name,
    psbt: applyPsbtMutations(template, [mutation]),
    errorClass:
      name === "supplied-share" || name === "supplied-proof"
        ? "psbt.parse_failed"
        : name.startsWith("changed")
          ? "policy.fixture_commitment_mismatch"
          : "silent_payment.funded_template_invalid",
  }));
  canaries.push({
    name: "supplied-share-and-proof",
    errorClass: "silent_payment.funded_template_invalid",
    psbt: applyPsbtMutations(template, [
      {
        kind: "set-entry",
        location: { kind: "input", index: 1 },
        keyType: 29,
        keyDataHex: MULTI_KEYS[1],
        valueHex: MULTI_KEYS[1],
      },
      {
        kind: "set-entry",
        location: { kind: "input", index: 1 },
        keyType: 30,
        keyDataHex: MULTI_KEYS[1],
        valueHex: "00".repeat(64),
      },
    ]),
  });
  return canaries;
}
export function createBip375MultiSenderScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (
    fixture.id !== "bip375-multi" ||
    fixture.psbtVersion !== 0 ||
    fixture.inputCount !== 2 ||
    fixture.outputCount !== 2
  )
    throw new TypeError("Multi-input sender requires the two-key funded fixture");
  return {
    id: ID,
    title: "Core-funded multi-input BIP375 sender through rust-psbt-v2",
    category: "silent-payment-interop",
    summary:
      "Prove two-key input aggregation, input-order invariance and unchanged ordinary change with independent extraction and Core policy acceptance.",
    requirements: [
      {
        adapter: WALLY,
        operations: ["convert", "extract"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2wpkh"],
        features: ["psbt-v0-v2-conversion", "unsigned-tx-sha256"],
      },
      {
        adapter: RUST,
        operations: ["silent-payment-send"],
        roles: ["updater", "signer", "finalizer", "extractor"],
        psbtVersions: [2],
        scriptTypes: ["p2wpkh"],
        features: ["bip375-core-funded-multi-input", "fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const record = (name: string, passed: boolean, summary: string) =>
        assertions.push({ name: `bip375-multi-${name}`, passed, summary });
      const converted = await context.request(WALLY, "convert", {
        psbt: fixture.initialPsbt,
        targetVersion: 2,
      });
      const template = context.outputString(converted, "psbt", "convert");
      const conversion =
        converted.status === "ok" &&
        converted.output["unsignedTxSha256"] === fixture.unsignedTxSha256 &&
        parsePsbtDocument(template).psbtVersion === 2;
      record(
        "conversion",
        conversion,
        "The converted template must match the run-scoped original transaction commitment",
      );
      if (!conversion)
        return {
          summary: "Funding conversion changed transaction intent.",
          assertions,
          policyAccepted: false,
        };
      await context.checkpoint(ID, "funded-template", template);
      const scripts: string[] = [];
      let allPolicyAccepted = true;
      for (const shareMode of ["global", "per-input"] as const)
        for (const reverseInputs of [false, true]) {
          const label = `${shareMode}-${reverseInputs ? "reversed" : "ordered"}`;
          const response = await context.request(RUST, "silent-payment-send", {
            psbt: template,
            network: "regtest",
            fixtureId: fixture.id,
            shareMode,
            reverseInputs,
          });
          const signed = context.outputString(response, "psbt", "silent-payment-send");
          const finalized = context.outputString(response, "finalizedPsbt", "silent-payment-send");
          const transaction = context.outputString(response, "transaction", "silent-payment-send");
          record(
            `${label}-cryptography-and-intent`,
            verifyMultiSender(template, signed, shareMode, reverseInputs),
            "Independent BIP374/BIP352 checks must verify complete shares, fixed recipient, both input keys, amounts, change and the requested order",
          );
          const script = parsePsbtDocument(signed)
            .maps.find(({ location }) => location.kind === "output" && location.index === 0)
            ?.entries.find(({ keyType }) => keyType === 4)
            ?.value.toString("hex");
          scripts.push(script ?? "");
          await context.checkpoint(ID, `${label}-signed`, signed);
          await context.checkpoint(ID, `${label}-finalized`, finalized);
          assertions.push(
            context.transitionEvidence(
              "finalize",
              `bip375-multi-${label}-finalization`,
              signed,
              finalized,
              RUST,
            ),
          );
          record(
            `${label}-witnesses`,
            verifyMultiWitnesses(signed, finalized),
            "Both finalized witnesses must contain their exact SIGHASH_ALL signature and public key",
          );
          const extracted = await context.request(WALLY, "extract", { psbt: finalized });
          record(
            `${label}-independent-extraction`,
            context.outputString(extracted, "transaction", "extract") === transaction &&
              response.status === "ok" &&
              response.output["signedInputs"] === 2 &&
              response.output["finalized"] === true,
            "libwally must extract the exact native transaction after both inputs are finalized",
          );
          const policy = await context.policyCheckTransaction(transaction);
          const accepted =
            policy.allowed &&
            typeof policy.txid === "string" &&
            /^[0-9a-f]{64}$/.test(policy.txid) &&
            response.status === "ok" &&
            response.output["transactionId"] === policy.txid;
          record(
            `${label}-core-policy`,
            accepted,
            accepted
              ? "Core accepted this funded transaction and confirmed its txid without broadcasting"
              : `Core policy or transaction identity failed: ${policy.rejectReason ?? "txid mismatch"}`,
          );
          allPolicyAccepted &&= accepted;
        }
      record(
        "equivalent-recipient",
        scripts.length === 4 &&
          scripts.every((script) => script.length === 68 && script === scripts[0]),
        "Global and per-input shares in both input orders must produce the identical recipient script",
      );
      for (const canary of multiSenderCanaries(template)) {
        const rejected = await context.request(RUST, "silent-payment-send", {
          psbt: canary.psbt,
          network: "regtest",
          fixtureId: fixture.id,
          shareMode: "per-input",
          reverseInputs: false,
        });
        record(
          canary.name,
          rejected.status === "rejected" && rejected.error.class === canary.errorClass,
          `The signer must reject ${canary.name} before signing`,
        );
      }
      const mainnet = await context.request(RUST, "silent-payment-send", {
        psbt: template,
        network: "mainnet",
        fixtureId: fixture.id,
        shareMode: "global",
        reverseInputs: false,
      });
      record(
        "mainnet-rejected",
        mainnet.status === "rejected" && mainnet.error.class === "policy.network_not_allowed",
        "Funded multi-input signing remains regtest-only",
      );
      return {
        summary: assertions.every(({ passed }) => passed)
          ? "All four funded variants preserve change, agree on the recipient, and pass independent cryptographic, extraction, policy and tamper checks without broadcasting."
          : "The multi-input sender failed one or more required checks.",
        assertions,
        policyAccepted: allPolicyAccepted,
      };
    },
  };
}
