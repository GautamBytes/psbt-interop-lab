import type { PsbtFixture } from "../core/fixtures.js";
import { validateBip375ReferencePsbt } from "../psbt/bip375-validator.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const RUST = "rust-psbt-v2";
const WALLY = "libwally";
const ID = "bip375-core-funded-sender-rust-psbt-v2";
const SPEND_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SCAN_KEY = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

export function verifyFundedSender(template: string, signed: string): boolean {
  try {
    const before = parsePsbtDocument(template);
    const after = parsePsbtDocument(signed);
    if (
      before.psbtVersion !== 2 ||
      after.psbtVersion !== 2 ||
      after.inputCount !== 1 ||
      after.outputCount !== 1
    )
      return false;
    const global = after.maps.find(({ location }) => location.kind === "global");
    const input = after.maps.find(({ location }) => location.kind === "input");
    const output = after.maps.find(({ location }) => location.kind === "output");
    const flags = global?.entries.find(({ keyType }) => keyType === 0x06);
    const info = output?.entries.find(({ keyType }) => keyType === 0x09);
    const signature = input?.entries.find(({ keyType }) => keyType === 0x02);
    if (
      flags?.value.toString("hex") !== "00" ||
      info?.value.toString("hex") !== SCAN_KEY + SPEND_KEY ||
      signature?.keyData.toString("hex") !== SPEND_KEY
    )
      return false;
    const diff = diffPsbtDocuments(before, after);
    const origin = input?.entries.find(
      ({ keyType, keyData }) => keyType === 0x06 && keyData.toString("hex") === SPEND_KEY,
    );
    const expected = new Set(["input:2", "input:29", "input:30", "output:9"]);
    for (const entry of diff.added) {
      if (entry.location.kind === "global" && entry.keyType === 0x06) continue;
      if (
        entry.location.kind === "input" &&
        entry.keyType === 0x06 &&
        entry.completeKeySha256 === origin?.completeKeySha256 &&
        origin.value.toString("hex") === "00000000"
      )
        continue;
      if (!expected.delete(`${entry.location.kind}:${entry.keyType}`)) return false;
    }
    return (
      expected.size === 0 &&
      diff.removed.length === 0 &&
      diff.changed.some(
        ({ location, keyType }) => location.kind === "output" && keyType === 0x04,
      ) &&
      diff.changed.every(
        ({ location, keyType }) =>
          (location.kind === "output" && keyType === 0x04) ||
          (location.kind === "global" && keyType === 0x06),
      ) &&
      validateBip375ReferencePsbt(signed).valid
    );
  } catch {
    return false;
  }
}

export function fundedSenderCanaries(template: string) {
  const input = parsePsbtDocument(template).maps.find(({ location }) => location.kind === "input");
  const index = input?.entries.find(({ keyType }) => keyType === 0x0f)?.value;
  if (!index) throw new Error("Funded template lacks output index");
  const changedIndex = Buffer.from(index);
  changedIndex[0] = (changedIndex[0] ?? 0) ^ 1;
  return [
    {
      name: "changed-input",
      errorClass: "policy.fixture_commitment_mismatch",
      psbt: applyPsbtMutations(template, [
        {
          kind: "replace-value",
          location: { kind: "input", index: 0 },
          keyType: 0x0f,
          valueHex: changedIndex.toString("hex"),
        },
      ]),
    },
    {
      name: "supplied-recipient",
      errorClass: "silent_payment.funded_template_invalid",
      psbt: applyPsbtMutations(template, [
        {
          kind: "set-entry",
          location: { kind: "output", index: 0 },
          keyType: 0x09,
          valueHex: SCAN_KEY + SCAN_KEY,
        },
      ]),
    },
    {
      name: "supplied-dleq",
      errorClass: "silent_payment.funded_template_invalid",
      psbt: applyPsbtMutations(template, [
        {
          kind: "set-entry",
          location: { kind: "input", index: 0 },
          keyType: 0x1d,
          keyDataHex: SCAN_KEY,
          valueHex: SCAN_KEY,
        },
        {
          kind: "set-entry",
          location: { kind: "input", index: 0 },
          keyType: 0x1e,
          keyDataHex: SCAN_KEY,
          valueHex: "00".repeat(64),
        },
      ]),
    },
  ];
}

function signatureMatchesWitness(signed: string, finalized: string): boolean {
  const input = parsePsbtDocument(signed).maps.find(({ location }) => location.kind === "input");
  const finalInput = parsePsbtDocument(finalized).maps.find(
    ({ location }) => location.kind === "input",
  );
  const signature = input?.entries.find(
    ({ keyType, keyData }) => keyType === 0x02 && keyData.toString("hex") === SPEND_KEY,
  )?.value;
  const witness = finalInput?.entries.find(({ keyType }) => keyType === 0x08)?.value;
  if (
    !signature ||
    signature.length < 9 ||
    signature.length > 73 ||
    signature.at(-1) !== 1 ||
    !witness
  )
    return false;
  const expectedWitness = Buffer.concat([
    Buffer.from([2, signature.length]),
    signature,
    Buffer.from([33]),
    Buffer.from(SPEND_KEY, "hex"),
  ]);
  return (
    witness.equals(expectedWitness) &&
    !finalInput?.entries.some(({ keyType }) => keyType === 0x02 || keyType === 0x07)
  );
}

export function createBip375FundedSenderScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (
    fixture.id !== "p2wpkh" ||
    fixture.psbtVersion !== 0 ||
    fixture.inputCount !== 1 ||
    fixture.outputCount !== 1
  ) {
    throw new TypeError("Core-funded sender requires the one-input P2WPKH fixture");
  }
  return {
    id: ID,
    title: "Core-funded BIP375 sender through rust-psbt-v2",
    category: "silent-payment-interop",
    summary:
      "Derive, sign, finalize, independently extract, and require Core policy acceptance for a funded regtest Silent Payment sender.",
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
        features: ["bip375-core-funded-sender", "fixture-commitment-sha256"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const record = (name: string, passed: boolean, summary: string) =>
        assertions.push({ name: `bip375-funded-${name}`, passed, summary });
      const convertedResponse = await context.request(WALLY, "convert", {
        psbt: fixture.initialPsbt,
        targetVersion: 2,
      });
      const template = context.outputString(convertedResponse, "psbt", "convert");
      const conversionPassed =
        parsePsbtDocument(template).psbtVersion === 2 &&
        convertedResponse.status === "ok" &&
        convertedResponse.output["unsignedTxSha256"] === fixture.unsignedTxSha256;
      record(
        "conversion",
        conversionPassed,
        "The converted funding template must retain the run-scoped transaction commitment",
      );
      // Do not request signing after a failed conversion check.
      if (!conversionPassed)
        return {
          summary: "Funding template conversion changed transaction intent.",
          assertions,
          policyAccepted: false,
        };
      await context.checkpoint(ID, "funded-template", template);
      const response = await context.request(RUST, "silent-payment-send", {
        psbt: template,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(response, "psbt", "silent-payment-send");
      const finalized = context.outputString(response, "finalizedPsbt", "silent-payment-send");
      const transaction = context.outputString(response, "transaction", "silent-payment-send");
      const verified = verifyFundedSender(template, signed);
      record(
        "cryptography-and-intent",
        verified,
        "Independent BIP374/BIP352 validation must match the fixed recipient while preserving the funding input, amounts, and other metadata",
      );
      await context.checkpoint(ID, "signed", signed);
      await context.checkpoint(ID, "finalized", finalized);
      const transition = context.transitionEvidence(
        "finalize",
        "bip375-funded-finalization",
        signed,
        finalized,
        RUST,
      );
      assertions.push(transition);
      record(
        "signature-witness",
        signatureMatchesWitness(signed, finalized),
        "The finalized P2WPKH witness must contain the exact SIGHASH_ALL signature and public key from the signed PSBT",
      );
      const independent = await context.request(WALLY, "extract", { psbt: finalized });
      const extracted = context.outputString(independent, "transaction", "extract");
      record(
        "independent-extraction",
        extracted === transaction &&
          response.status === "ok" &&
          response.output["finalized"] === true &&
          response.output["signedInputs"] === 1,
        "libwally must independently extract the exact transaction returned by rust-psbt-v2",
      );
      const policy = await context.policyCheckTransaction(transaction);
      const policyPassed =
        policy.allowed &&
        typeof policy.txid === "string" &&
        /^[0-9a-f]{64}$/.test(policy.txid) &&
        response.status === "ok" &&
        response.output["transactionId"] === policy.txid;
      record(
        "core-policy",
        policyPassed,
        policyPassed
          ? "Bitcoin Core accepted the funded sender under regtest policy and confirmed its txid; no transaction was broadcast"
          : `Core policy or transaction identity failed: ${policy.rejectReason ?? "txid mismatch"}`,
      );
      for (const canary of fundedSenderCanaries(template)) {
        const rejected = await context.request(RUST, "silent-payment-send", {
          psbt: canary.psbt,
          network: "regtest",
          fixtureId: fixture.id,
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
      });
      record(
        "mainnet-rejected",
        mainnet.status === "rejected" && mainnet.error.class === "policy.network_not_allowed",
        "The funded sender remains regtest-only",
      );
      return {
        summary: assertions.every(({ passed }) => passed)
          ? "The Core-funded Silent Payment sender passed independent cryptographic, extraction, policy, and tamper checks without broadcasting."
          : "The Core-funded sender failed one or more required checks.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
