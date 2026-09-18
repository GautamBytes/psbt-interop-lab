import type { PsbtFixture } from "../core/fixtures.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { type PsbtDocument, parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import { MULTI_KEYS, verifyMultiSender, verifyMultiWitnesses } from "./bip375-multi-verify.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";
import { createReceiverPsbt, discoverReceiverOutputs } from "./silent-payment-receiver.js";

const SINGLE_ID = "bip352-sender-receiver-lifecycle-rust-psbt-v2";
const RUST = "rust-psbt-v2",
  WALLY = "libwally";
export function createSilentPaymentLifecycleScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  const multiOutput = fixture.id === "bip352-multi-output";
  const count = multiOutput ? 2 : 1;
  const ID = multiOutput ? "bip352-multi-output-lifecycle-rust-psbt-v2" : SINGLE_ID;
  if (
    (!multiOutput && fixture.id !== "bip375-multi") ||
    fixture.psbtVersion !== 0 ||
    fixture.inputCount !== 2 ||
    fixture.outputCount !== count + 1
  )
    throw new TypeError("Lifecycle requires the two-key funded fixture");
  return {
    id: ID,
    title: multiOutput
      ? "Two-output Silent Payment discovery and combined receiver spend"
      : "Funded Silent Payment discovery and receiver spend",
    category: "silent-payment-interop",
    summary:
      "Discover recipient outputs from public sender inputs, spend the exact outputs, and require Core acceptance of each parent/child package without broadcasting.",
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
          ...(multiOutput ? ["bip352-multi-output-lifecycle"] : ["bip352-receiver-discovery"]),
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
      const runVariant = async (shuffleOutputs: boolean) => {
        const prefix = multiOutput ? (shuffleOutputs ? "shuffled-" : "ordered-") : "";
        const checkpoint = (stage: string, psbt: string) =>
          context.checkpoint(ID, `${prefix}${stage}`, psbt);
        const assertions: ScenarioAssertionEvidence[] = [];
        const record = (name: string, passed: boolean, summary: string) =>
          assertions.push({ name: `lifecycle-${prefix}${name}`, passed, summary });
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
        await checkpoint("funded-template", template);
        const sender = await context.request(RUST, "silent-payment-send", {
          psbt: template,
          network: "regtest",
          fixtureId: fixture.id,
          shareMode: "per-input",
          reverseInputs: false,
          ...(multiOutput ? { shuffleOutputs } : {}),
        });
        const parentSigned = context.outputString(sender, "psbt", "silent-payment-send");
        const parent = context.outputString(sender, "finalizedPsbt", "silent-payment-send");
        const parentTx = context.outputString(sender, "transaction", "silent-payment-send");
        const parentId = context.outputString(sender, "transactionId", "silent-payment-send");
        record(
          "sender-derivation",
          verifyMultiSender(template, parentSigned, "per-input", false, shuffleOutputs),
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
            `lifecycle-${prefix}parent-finalization`,
            parentSigned,
            parent,
            RUST,
          ),
        );
        await checkpoint("sender-signed", parentSigned);
        await checkpoint("sender-finalized", parent);
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
        const discovered = discoverReceiverOutputs(parent);
        record(
          "receiver-discovery",
          discovered.length === count && (multiOutput || discovered[0]?.index === 0),
          "The receiver must find the recipient output using public input witnesses/outpoints and its scan/spend keys",
        );
        record(
          "wrong-receiver",
          discoverReceiverOutputs(parent, 3n).length === 0 &&
            discoverReceiverOutputs(parent, 2n, MULTI_KEYS[1]).length === 0,
          "Wrong receiver scan or spend keys must not discover an output",
        );
        if (discovered.length !== count || assertions.some((a) => !a.passed)) return failed();
        const child = createReceiverPsbt(parentId, discovered);
        await checkpoint("receiver-discovered", child);
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
        const signedDocument = parsePsbtDocument(signed);
        const finalizedDocument = parsePsbtDocument(finalized);
        const diff = diffPsbtDocuments(parsePsbtDocument(child), signedDocument);
        record(
          "receiver-signature-only",
          diff.removed.length === 0 &&
            diff.changed.length === 0 &&
            diff.added.length === count &&
            new Set(diff.added.map((e) => (e.location.kind === "input" ? e.location.index : -1)))
              .size === count &&
            diff.added.every(
              (e) => e.keyType === 0x13 && e.location.kind === "input" && e.location.index < count,
            ),
          "The receiver signer may only add a Taproot signature to the exact discovered-output spend",
        );
        const finalDiff = diffPsbtDocuments(signedDocument, finalizedDocument);
        record(
          "child-finalization",
          finalDiff.changed.length === 0 &&
            finalDiff.added.length === count &&
            new Set(
              finalDiff.added.map((e) => (e.location.kind === "input" ? e.location.index : -1)),
            ).size === count &&
            finalDiff.added.every(
              (e) => e.keyType === 8 && e.location.kind === "input" && e.location.index < count,
            ) &&
            finalDiff.removed.every(
              (entry) =>
                entry.location.kind === "input" &&
                entry.location.index < count &&
                [1, 0x13, 0x1f, 0x20].includes(entry.keyType),
            ),
          "Finalization may only add the witness and remove the spent UTXO, signature and BIP376 fields",
        );
        const field = (document: PsbtDocument, index: number, type: number) =>
          document.maps
            .find((m) => m.location.kind === "input" && m.location.index === index)
            ?.entries.find((e) => e.keyType === type)?.value;
        const indexes = Array.from({ length: count }, (_, i) => i);
        record(
          "receiver-witness",
          indexes.every((index) => {
            const signature = field(signedDocument, index, 0x13);
            return (
              signature?.length === 64 &&
              field(finalizedDocument, index, 8)?.equals(
                Buffer.concat([Buffer.from([1, 64]), signature]),
              ) === true
            );
          }),
          "Every final witness must contain its exact SIGHASH_DEFAULT receiver signature",
        );
        record(
          "receiver-field-cleanup",
          indexes.every((index) =>
            [0x13, 0x1f, 0x20].every((type) => field(finalizedDocument, index, type) === undefined),
          ),
          "Finalization must remove all signatures and BIP376 spend-key/tweak fields",
        );
        await checkpoint("receiver-signed", signed);
        await checkpoint("receiver-finalized", finalized);
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
        const canaries: [string, PsbtMutationRecipe[]][] = [
          [
            "wrong-outpoint",
            [
              {
                kind: "replace-value",
                location: { kind: "input", index: 0 },
                keyType: 15,
                valueHex: multiOutput ? (shuffleOutputs ? "00000000" : "02000000") : "01000000",
              },
            ],
          ],
          [
            "wrong-tweak",
            [
              {
                kind: "replace-value",
                location: { kind: "input", index: 0 },
                keyType: 0x20,
                valueHex: "03".repeat(32),
              },
            ],
          ],
          [
            "changed-destination",
            [
              {
                kind: "replace-value",
                location: { kind: "output", index: 0 },
                keyType: 4,
                valueHex: `0014${"11".repeat(20)}`,
              },
            ],
          ],
        ];
        if (multiOutput) {
          const first = discovered[0],
            second = discovered[1];
          if (!first || !second) return failed();
          canaries.push([
            "swapped-tweaks",
            [
              {
                kind: "replace-value",
                location: { kind: "input", index: 0 },
                keyType: 0x20,
                valueHex: second.tweakHex,
              },
              {
                kind: "replace-value",
                location: { kind: "input", index: 1 },
                keyType: 0x20,
                valueHex: first.tweakHex,
              },
            ],
          ]);
          const changedAmount = Buffer.alloc(8);
          changedAmount.writeBigUInt64LE(first.amountSats + second.amountSats - 10_000n + 1n);
          canaries.push([
            "changed-value",
            [
              {
                kind: "replace-value",
                location: { kind: "output", index: 0 },
                keyType: 3,
                valueHex: changedAmount.toString("hex"),
              },
            ],
          ]);
          const vout = Buffer.alloc(4);
          vout.writeUInt32LE(first.index);
          canaries.push([
            "duplicate-input",
            [
              {
                kind: "replace-value",
                location: { kind: "input", index: 1 },
                keyType: 15,
                valueHex: vout.toString("hex"),
              },
            ],
          ]);
        }
        for (const [name, recipes] of canaries) {
          const response = await context.request(RUST, "silent-payment-spend", {
            ...payload,
            psbt: applyPsbtMutations(child, recipes),
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
      };
      if (!multiOutput) return runVariant(false);
      const results = [];
      for (const shuffled of [false, true]) results.push(await runVariant(shuffled));
      const assertions = results.flatMap((result) => result.assertions);
      return {
        summary: assertions.every((a) => a.passed)
          ? "Both output layouts independently discover and spend two recipient outputs, preserve change and pass Core package policy without broadcasting."
          : "A two-output lifecycle requirement failed.",
        assertions,
        policyAccepted: results.every((result) => result.policyAccepted),
      };
    },
  };
}
