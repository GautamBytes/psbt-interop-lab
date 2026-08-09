import type { PsbtFixture } from "../core/fixtures.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const RUST = "rust-psbt-v2";
const WALLY = "libwally";
const SPEND_PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const EXPECTED_OUTPUT_KEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const VALID_TWEAK = `${"00".repeat(31)}02`;
const WRONG_TWEAK = `${"00".repeat(31)}03`;

export function bip376SpendPsbt(psbt: string, tweak = VALID_TWEAK): string {
  return applyPsbtMutations(psbt, [
    {
      kind: "set-entry",
      location: { kind: "input", index: 0 },
      keyType: 0x1f,
      keyDataHex: SPEND_PUBLIC_KEY,
      valueHex: "00000000",
    },
    {
      kind: "set-entry",
      location: { kind: "input", index: 0 },
      keyType: 0x20,
      valueHex: tweak,
    },
  ]);
}

function inputFieldTypes(psbt: string): ReadonlySet<number> {
  const input = parsePsbtDocument(psbt).maps.find(
    ({ location }) => location.kind === "input" && location.index === 0,
  );
  return new Set(input?.entries.map(({ keyType }) => keyType) ?? []);
}

function signatureTransition(before: string, after: string): ScenarioAssertionEvidence {
  const difference = diffPsbtDocuments(parsePsbtDocument(before), parsePsbtDocument(after));
  const signatureOnly =
    difference.removed.length === 0 &&
    difference.changed.length === 0 &&
    difference.added.length === 1 &&
    difference.added[0]?.location.kind === "input" &&
    difference.added[0].location.index === 0 &&
    difference.added[0].keyType === 0x13;
  return {
    name: "bip376-native-signature-transition",
    passed: signatureOnly,
    likelyImplementation: RUST,
    summary: signatureOnly
      ? "The receiver signer added only the Taproot key-path signature"
      : "The receiver signer changed fields outside the permitted signature transition",
  };
}

export function createBip376SpendScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (fixture.id !== "bip376-spend" || fixture.psbtVersion !== 0 || fixture.inputCount !== 1) {
    throw new TypeError("BIP376 spend workflow requires the committed bip376-spend fixture");
  }
  return {
    id: "bip376-spend-workflow-rust-psbt-v2",
    title: "BIP376 Silent Payment receiver spend through rust-psbt-v2",
    category: "silent-payment-interop",
    summary:
      "Core funds a deterministic Silent Payment output, libwally converts it to PSBTv2, rust-psbt-v2 verifies the BIP376 tweak and spends it, and Core checks the result.",
    requirements: [
      {
        adapter: WALLY,
        operations: ["convert"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2tr-keypath"],
        features: ["psbt-v0-v2-conversion", "unsigned-tx-sha256"],
      },
      {
        adapter: RUST,
        operations: ["silent-payment-spend"],
        roles: ["signer", "finalizer", "extractor"],
        psbtVersions: [2],
        scriptTypes: ["p2tr-keypath"],
        features: ["bip376-spend-workflow", "fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const convertedResponse = await context.request(WALLY, "convert", {
        psbt: fixture.initialPsbt,
        targetVersion: 2,
      });
      const converted = context.outputString(convertedResponse, "psbt", "convert");
      const conversionPassed =
        parsePsbtDocument(converted).psbtVersion === 2 &&
        convertedResponse.status === "ok" &&
        convertedResponse.output["unsignedTxSha256"] === fixture.unsignedTxSha256;
      assertions.push({
        name: "bip376-v2-conversion-preserved-intent",
        passed: conversionPassed,
        likelyImplementation: WALLY,
        summary: conversionPassed
          ? "libwally converted the Core fixture to PSBTv2 without changing transaction intent"
          : "The PSBTv2 conversion changed or omitted the committed transaction identity",
      });

      const inProgress = bip376SpendPsbt(converted);
      await context.checkpoint("bip376-spend-workflow-rust-psbt-v2", "bip376-fields", inProgress);
      const injectedFields = inputFieldTypes(inProgress);
      const fieldsPassed =
        injectedFields.has(0x01) && injectedFields.has(0x1f) && injectedFields.has(0x20);
      assertions.push({
        name: "bip376-receiver-fields-present",
        passed: fieldsPassed,
        summary: fieldsPassed
          ? "The receiver PSBT contains the witness UTXO, spend key, and output tweak"
          : "The receiver PSBT is missing required BIP376 signing material",
      });

      const response = await context.request(RUST, "silent-payment-spend", {
        psbt: inProgress,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(response, "psbt", "silent-payment-spend");
      const finalized = context.outputString(response, "finalizedPsbt", "silent-payment-spend");
      const transaction = context.outputString(response, "transaction", "silent-payment-spend");
      assertions.push(signatureTransition(inProgress, signed));
      await context.checkpoint("bip376-spend-workflow-rust-psbt-v2", "signed", signed);
      await context.checkpoint("bip376-spend-workflow-rust-psbt-v2", "finalized", finalized);

      const finalizedFields = inputFieldTypes(finalized);
      const cleanupPassed =
        finalizedFields.has(0x08) &&
        !finalizedFields.has(0x01) &&
        !finalizedFields.has(0x13) &&
        !finalizedFields.has(0x1f) &&
        !finalizedFields.has(0x20) &&
        response.status === "ok" &&
        response.output["finalized"] === true &&
        response.output["signedInputs"] === 1 &&
        response.output["derivedOutputKey"] === EXPECTED_OUTPUT_KEY;
      assertions.push({
        name: "bip376-finalized-fields-cleaned",
        passed: cleanupPassed,
        likelyImplementation: RUST,
        summary: cleanupPassed
          ? "The derived key matched the output and finalization removed spent signing material"
          : "The finalized PSBT retained BIP376 signing data or derived the wrong output key",
      });

      const policy = await context.policyCheckTransaction(transaction);
      assertions.push({
        name: "bip376-core-policy-accepted",
        passed: policy.allowed,
        summary: policy.allowed
          ? "Bitcoin Core accepted the extracted Silent Payment spend under regtest policy"
          : `Bitcoin Core rejected the Silent Payment spend${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
      });

      const mainnet = await context.request(RUST, "silent-payment-spend", {
        psbt: inProgress,
        network: "mainnet",
        fixtureId: fixture.id,
      });
      const wrongTweak = await context.request(RUST, "silent-payment-spend", {
        psbt: bip376SpendPsbt(converted, WRONG_TWEAK),
        network: "regtest",
        fixtureId: fixture.id,
      });
      const canariesPassed =
        mainnet.status === "rejected" &&
        mainnet.error.class === "policy.network_not_allowed" &&
        wrongTweak.status === "rejected" &&
        wrongTweak.error.class === "silent_payment.output_key_mismatch";
      assertions.push({
        name: "bip376-bounded-rejection-canaries",
        passed: canariesPassed,
        summary: canariesPassed
          ? "Mainnet use and a tweak that does not match the funded output were rejected"
          : "A forbidden network or mismatched Silent Payment tweak reached the signing path",
      });

      return {
        summary: assertions.every(({ passed }) => passed)
          ? "The committed BIP376 receiver output was independently verified, spent, and accepted by Bitcoin Core."
          : "The BIP376 receiver spend failed one or more interoperability checks.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
