import { FIXTURE_PUBLIC_KEYS } from "../core/fixture-profiles.js";
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
  receiver: "native" | "spdk" = "native",
): ScenarioDefinition<ScenarioExecutionContext> {
  const multiReceiver = fixture.id === "bip352-multi-receiver";
  const multiOutput = multiReceiver || fixture.id === "bip352-multi-output";
  const count = multiOutput ? 2 : 1;
  const spdk = receiver === "spdk";
  const ID = multiReceiver
    ? "bip352-multi-receiver-spdk"
    : spdk
      ? "bip352-spdk-wallet-interop"
      : multiOutput
        ? "bip352-multi-output-lifecycle-rust-psbt-v2"
        : SINGLE_ID;
  if (
    (spdk && !multiOutput) ||
    (multiReceiver && !spdk) ||
    (!multiOutput && fixture.id !== "bip375-multi") ||
    fixture.psbtVersion !== 0 ||
    fixture.inputCount !== 2 ||
    fixture.outputCount !== (multiReceiver ? 4 : count + 1)
  )
    throw new TypeError("Lifecycle requires the two-key funded fixture");
  return {
    id: ID,
    title: multiReceiver
      ? "Independent Silent Payment receiver ownership and spending"
      : spdk
        ? "Independent SPDK wallet discovery and combined spend"
        : multiOutput
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
        features: [
          "bip352-receiver-discovery",
          "fixture-commitment-sha256",
          ...(spdk ? ["bip352-spdk-wallet-interop"] : []),
          ...(multiReceiver ? ["bip352-multi-receiver"] : []),
        ],
      },
    ],
    async run(context) {
      const runVariant = async (shuffleOutputs: boolean, receiverIndex: 0 | 1 = 0) => {
        const count = multiReceiver ? 2 - receiverIndex : multiOutput ? 2 : 1;
        const spendKey =
          receiverIndex === 1 ? FIXTURE_PUBLIC_KEYS.scalar2 : FIXTURE_PUBLIC_KEYS.scalar1;
        const scan = BigInt(2 + receiverIndex);
        const prefix =
          (multiOutput ? (shuffleOutputs ? "shuffled-" : "ordered-") : "") +
          (multiReceiver ? `${receiverIndex === 0 ? "alice" : "bob"}-` : "");
        const checkpoint = (stage: string, psbt: string) =>
          context.checkpoint(ID, `${prefix}${stage}`, psbt);
        const assertions: ScenarioAssertionEvidence[] = [];
        const record = (name: string, passed: boolean, summary: string) =>
          assertions.push({ name: `lifecycle-${prefix}${name}`, passed, summary });
        const failed = () => ({
          summary: "The linked sender/receiver lifecycle failed a required check.",
          assertions,
          policyAccepted: false,
          parentId: "",
          ownedOutpoints: [] as number[],
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
        const discovered = discoverReceiverOutputs(parent, scan, spendKey);
        record(
          "receiver-discovery",
          discovered.length === count && (multiOutput || discovered[0]?.index === 0),
          "The receiver must find the recipient output using public input witnesses/outpoints and its scan/spend keys",
        );
        record(
          "wrong-receiver",
          discoverReceiverOutputs(parent, 4n, spendKey).length === 0 &&
            discoverReceiverOutputs(
              parent,
              scan,
              receiverIndex === 0 ? MULTI_KEYS[1] : MULTI_KEYS[0],
            ).length === 0,
          "Wrong receiver scan or spend keys must not discover an output",
        );
        if (discovered.length !== count || assertions.some((a) => !a.passed)) return failed();
        const child = createReceiverPsbt(
          parentId,
          discovered,
          multiReceiver ? receiverIndex : undefined,
        );
        await checkpoint("receiver-discovered", child);
        const payload = {
          psbt: child,
          parentPsbt: parent,
          templatePsbt: template,
          network: "regtest",
          fixtureId: fixture.id,
          ...(spdk ? { receiver: "spdk" } : {}),
          ...(multiReceiver ? { receiverId: receiverIndex === 0 ? "alice" : "bob" } : {}),
        };
        const receiver = await context.request(RUST, "silent-payment-spend", payload);
        if (spdk)
          record(
            "spdk-implementation",
            receiver.status === "ok" &&
              receiver.output["receiverImplementation"] ===
                "spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7",
            "Discovery and signing must use spdk-wallet/0.7.1@a00f9807609b3be16892b7dd671a56db52db88a7",
          );
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
                valueHex: multiOutput
                  ? shuffleOutputs
                    ? "00000000"
                    : multiReceiver
                      ? "03000000"
                      : "02000000"
                  : "01000000",
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
        if (count === 2) {
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
        if (multiReceiver) {
          const other = discoverReceiverOutputs(
            parent,
            receiverIndex === 0 ? 3n : 2n,
            receiverIndex === 0 ? MULTI_KEYS[1] : MULTI_KEYS[0],
          );
          const foreign = other[0];
          if (!foreign) return failed();
          const mixed = createReceiverPsbt(
            parentId,
            [foreign, ...discovered.slice(1)],
            receiverIndex,
          );
          const mixedOwner = await context.request(RUST, "silent-payment-spend", {
            ...payload,
            psbt: mixed,
          });
          record(
            "foreign-input-rejected",
            mixedOwner.status === "rejected" &&
              mixedOwner.error.class === "silent_payment.receiver_link_invalid",
            "Reject a foreign outpoint even when input count, recipient and total value are unchanged",
          );
          const wrongOwner = await context.request(RUST, "silent-payment-spend", {
            ...payload,
            receiverId: receiverIndex === 0 ? "bob" : "alice",
          });
          record(
            "other-receiver-rejected",
            wrongOwner.status === "rejected" &&
              wrongOwner.error.class === "silent_payment.receiver_link_invalid",
            "Another receiver must not authorize these outpoints or receive a signature",
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
          parentId,
          ownedOutpoints: discovered.map((o) => o.index),
        };
      };
      if (!multiOutput) return runVariant(false);
      const results = [];
      for (const shuffled of [false, true]) {
        results.push(await runVariant(shuffled));
        if (multiReceiver) results.push(await runVariant(shuffled, 1));
      }
      const assertions = results.flatMap((result) => result.assertions);
      if (multiReceiver) {
        for (const [index, [a, b]] of [
          [results[0], results[1]],
          [results[2], results[3]],
        ].entries()) {
          assertions.push({
            name: `receiver-isolation-${index === 0 ? "ordered" : "shuffled"}`,
            passed:
              !!a &&
              !!b &&
              a.parentId === b.parentId &&
              new Set([...a.ownedOutpoints, ...b.ownedOutpoints]).size === 3,
            summary: "Alice and Bob spend disjoint outputs from the exact same parent",
          });
        }
      }
      return {
        summary: assertions.every((a) => a.passed)
          ? multiReceiver
            ? "Two independent receivers discover and spend only their own outputs in both layouts; SPDK, libwally and Core policy agree."
            : spdk
              ? "SPDK independently discovers and signs both output layouts; libwally extraction and Core parent/child policy pass without broadcasting."
              : "Both output layouts independently discover and spend two recipient outputs, preserve change and pass Core package policy without broadcasting."
          : "A Silent Payment lifecycle requirement failed.",
        assertions,
        policyAccepted: results.every((result) => result.policyAccepted),
      };
    },
  };
}
