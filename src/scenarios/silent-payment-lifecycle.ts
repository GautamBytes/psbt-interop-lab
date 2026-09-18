import type { PsbtFixture } from "../core/fixtures.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import { MULTI_KEYS, verifyMultiSender, verifyMultiWitnesses } from "./bip375-multi-verify.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";
import { createReceiverPsbt, discoverReceiverOutput } from "./silent-payment-receiver.js";

const ID = "bip352-sender-receiver-lifecycle-rust-psbt-v2";
const RUST = "rust-psbt-v2",
  WALLY = "libwally";
export function createSilentPaymentLifecycleScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (
    fixture.id !== "bip375-multi" ||
    fixture.psbtVersion !== 0 ||
    fixture.inputCount !== 2 ||
    fixture.outputCount !== 2
  )
    throw new TypeError("Lifecycle requires the two-key funded fixture");
  return {
    id: ID,
    title: "Funded Silent Payment discovery and receiver spend",
    category: "silent-payment-interop",
    summary:
      "Derive the receiver output from public sender inputs, spend that exact output, and require Core acceptance of the parent/child package without broadcasting.",
    requirements: [
      {
        adapter: WALLY,
        operations: ["convert", "extract"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2wpkh", "p2tr-keypath"],
        features: ["psbt-v0-v2-conversion", "unsigned-tx-sha256"],
      },
      {
        adapter: RUST,
        operations: ["silent-payment-send"],
        roles: ["updater", "signer", "finalizer", "extractor"],
        psbtVersions: [2],
        scriptTypes: ["p2wpkh"],
        features: [
          "bip375-core-funded-multi-input",
          "bip352-receiver-discovery",
          "fixture-commitment-sha256",
        ],
      },
      {
        adapter: RUST,
        operations: ["silent-payment-spend"],
        psbtVersions: [2],
        scriptTypes: ["p2tr-keypath"],
        features: ["bip352-receiver-discovery", "fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const record = (name: string, passed: boolean, summary: string) =>
        assertions.push({ name: `lifecycle-${name}`, passed, summary });
      const failed = () => ({
        summary: "The linked sender/receiver lifecycle failed a required check.",
        assertions,
        policyAccepted: false,
      });
      const conversion = await context.request(WALLY, "convert", {
        psbt: fixture.initialPsbt,
        targetVersion: 2,
      });
      const template = context.outputString(conversion, "psbt", "convert");
      record(
        "funding-commitment",
        conversion.status === "ok" &&
          conversion.output["unsignedTxSha256"] === fixture.unsignedTxSha256 &&
          parsePsbtDocument(template).psbtVersion === 2,
        "Conversion must preserve the original funding transaction commitment",
      );
      if (assertions.some((a) => !a.passed)) return failed();
      await context.checkpoint(ID, "funded-template", template);
      const sender = await context.request(RUST, "silent-payment-send", {
        psbt: template,
        network: "regtest",
        fixtureId: fixture.id,
        shareMode: "per-input",
        reverseInputs: false,
      });
      const parentSigned = context.outputString(sender, "psbt", "silent-payment-send");
      const parent = context.outputString(sender, "finalizedPsbt", "silent-payment-send");
      const parentTx = context.outputString(sender, "transaction", "silent-payment-send");
      const parentId = context.outputString(sender, "transactionId", "silent-payment-send");
      record(
        "sender-derivation",
        verifyMultiSender(template, parentSigned, "per-input", false),
        "Verify sender proofs, input aggregation, recipient derivation, amounts and change independently",
      );
      record(
        "sender-witnesses",
        verifyMultiWitnesses(parentSigned, parent),
        "Both parent signatures must match their finalized witnesses",
      );
      assertions.push(
        context.transitionEvidence(
          "finalize",
          "lifecycle-parent-finalization",
          parentSigned,
          parent,
          RUST,
        ),
      );
      await context.checkpoint(ID, "sender-signed", parentSigned);
      await context.checkpoint(ID, "sender-finalized", parent);
      const extractedParent = await context.request(WALLY, "extract", { psbt: parent });
      record(
        "parent-extraction",
        context.outputString(extractedParent, "transaction", "extract") === parentTx,
        "libwally must independently extract the exact parent transaction",
      );
      const parentPolicy = await context.policyCheckTransaction(parentTx);
      record(
        "parent-policy",
        parentPolicy.allowed && parentPolicy.txid === parentId,
        "Core must accept the funded parent and confirm its transaction ID",
      );
      if (assertions.some((a) => !a.passed)) return failed();
      const discovered = discoverReceiverOutput(parent);
      record(
        "receiver-discovery",
        discovered?.index === 0,
        "The receiver must find the recipient output using public input witnesses/outpoints and its scan/spend keys",
      );
      record(
        "wrong-receiver",
        discoverReceiverOutput(parent, 3n) === undefined &&
          discoverReceiverOutput(parent, 2n, MULTI_KEYS[1]) === undefined,
        "Wrong receiver scan or spend keys must not discover an output",
      );
      if (!discovered || assertions.some((a) => !a.passed)) return failed();
      const child = createReceiverPsbt(parentId, discovered);
      await context.checkpoint(ID, "receiver-discovered", child);
      const payload = {
        psbt: child,
        parentPsbt: parent,
        templatePsbt: template,
        network: "regtest",
        fixtureId: fixture.id,
      };
      const receiver = await context.request(RUST, "silent-payment-spend", payload);
      const signed = context.outputString(receiver, "psbt", "silent-payment-spend");
      const finalized = context.outputString(receiver, "finalizedPsbt", "silent-payment-spend");
      const childTx = context.outputString(receiver, "transaction", "silent-payment-spend");
      const childId = context.outputString(receiver, "transactionId", "silent-payment-spend");
      const diff = diffPsbtDocuments(parsePsbtDocument(child), parsePsbtDocument(signed));
      record(
        "receiver-signature-only",
        diff.removed.length === 0 &&
          diff.changed.length === 0 &&
          diff.added.length === 1 &&
          diff.added[0]?.keyType === 0x13 &&
          diff.added[0].location.kind === "input" &&
          diff.added[0].location.index === 0,
        "The receiver signer may only add a Taproot signature to the exact discovered-output spend",
      );
      const finalDiff = diffPsbtDocuments(parsePsbtDocument(signed), parsePsbtDocument(finalized));
      record(
        "child-finalization",
        finalDiff.changed.length === 0 &&
          finalDiff.added.length === 1 &&
          finalDiff.added[0]?.location.kind === "input" &&
          finalDiff.added[0].location.index === 0 &&
          finalDiff.added[0].keyType === 8 &&
          finalDiff.removed.every(
            (entry) =>
              entry.location.kind === "input" &&
              entry.location.index === 0 &&
              [1, 0x13, 0x1f, 0x20].includes(entry.keyType),
          ),
        "Finalization may only add the witness and remove the spent UTXO, signature and BIP376 fields",
      );
      const field = (psbt: string, type: number) =>
        parsePsbtDocument(psbt)
          .maps.find((m) => m.location.kind === "input")
          ?.entries.find((e) => e.keyType === type)?.value;
      const signature = field(signed, 0x13);
      record(
        "receiver-witness",
        signature?.length === 64 &&
          field(finalized, 8)?.equals(Buffer.concat([Buffer.from([1, 64]), signature])) === true,
        "The final witness must contain the exact SIGHASH_DEFAULT receiver signature",
      );
      record(
        "receiver-field-cleanup",
        field(finalized, 0x13) === undefined &&
          field(finalized, 0x1f) === undefined &&
          field(finalized, 0x20) === undefined,
        "Finalization must remove BIP376 spend-key and tweak fields",
      );
      await context.checkpoint(ID, "receiver-signed", signed);
      await context.checkpoint(ID, "receiver-finalized", finalized);
      const extractedChild = await context.request(WALLY, "extract", { psbt: finalized });
      record(
        "child-extraction",
        context.outputString(extractedChild, "transaction", "extract") === childTx,
        "libwally must independently extract the exact receiver spend",
      );
      const standalone = await context.policyCheckTransaction(childTx);
      record(
        "child-needs-parent",
        !standalone.allowed && standalone.rejectReason === "missing-inputs",
        "The unbroadcast child must fail alone because its parent is not in the mempool",
      );
      const policy = await context.policyCheckPackage([parentTx, childTx]);
      const accepted =
        policy[0]?.allowed === true &&
        policy[0].txid === parentId &&
        policy[1]?.allowed === true &&
        policy[1].txid === childId;
      record(
        "package-policy",
        accepted,
        "Core must accept both transactions together and confirm both transaction IDs without broadcasting",
      );
      const mutations: [string, PsbtMutationRecipe][] = [
        [
          "wrong-outpoint",
          {
            kind: "replace-value",
            location: { kind: "input", index: 0 },
            keyType: 15,
            valueHex: "01000000",
          },
        ],
        [
          "wrong-tweak",
          {
            kind: "replace-value",
            location: { kind: "input", index: 0 },
            keyType: 0x20,
            valueHex: "03".repeat(32),
          },
        ],
        [
          "changed-destination",
          {
            kind: "replace-value",
            location: { kind: "output", index: 0 },
            keyType: 4,
            valueHex: `0014${"11".repeat(20)}`,
          },
        ],
      ];
      for (const [name, mutation] of mutations) {
        const response = await context.request(RUST, "silent-payment-spend", {
          ...payload,
          psbt: applyPsbtMutations(child, [mutation]),
        });
        record(
          name,
          response.status === "rejected" &&
            response.error.class === "silent_payment.receiver_link_invalid",
          "Reject a receiver spend that no longer matches the independently discovered payment",
        );
      }
      const mainnet = await context.request(RUST, "silent-payment-spend", {
        ...payload,
        network: "mainnet",
      });
      record(
        "mainnet-rejected",
        mainnet.status === "rejected" && mainnet.error.class === "policy.network_not_allowed",
        "Receiver signing remains restricted to regtest fixtures",
      );
      return {
        summary: assertions.every((a) => a.passed)
          ? "The funded sender, independently discovered recipient and exact receiver spend passed linked Core package policy without broadcasting."
          : failed().summary,
        assertions,
        policyAccepted: accepted,
        transactionId: childId,
      };
    },
  };
}
