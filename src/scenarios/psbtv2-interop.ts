import type { PsbtFixture } from "../core/fixtures.js";
import type { AdapterResponse } from "../protocol/types.js";
import { parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type {
  ScenarioAssertionEvidence,
  ScenarioDefinition,
  ScenarioFinding,
} from "./definition.js";

const PARTIAL_SIGNATURE = 0x02;
const FINAL_SCRIPT_WITNESS = 0x08;
const SIGNING_METADATA = [0x02, 0x03, 0x04, 0x05, 0x06] as const;
const RUST = "rust-psbt-v2";
const WALLY = "libwally";

interface FinalScriptSigInteropObservation {
  readonly rustStatus: AdapterResponse["status"];
  readonly rustErrorClass: string | undefined;
  readonly wallyStatus: AdapterResponse["status"];
  readonly wallyErrorClass: string | undefined;
  readonly hasWitnessWithoutScriptSig: boolean;
  readonly hasWitnessWithEmptyScriptSig: boolean;
}

export type FinalScriptSigInteropClassification =
  | {
      readonly kind: "rust-requires-empty-final-scriptsig";
      readonly ruleId: "bip174.final-scriptsig.empty-omitted";
    }
  | { readonly kind: "wally-rejected-noncanonical-empty-final-scriptsig" }
  | { readonly kind: "unclassified" };

export function classifyFinalScriptSigInterop(
  observation: FinalScriptSigInteropObservation,
): FinalScriptSigInteropClassification {
  if (
    observation.rustStatus === "rejected" &&
    observation.rustErrorClass === "extract.not_finalized" &&
    observation.wallyStatus === "ok" &&
    observation.hasWitnessWithoutScriptSig
  ) {
    return {
      kind: "rust-requires-empty-final-scriptsig",
      ruleId: "bip174.final-scriptsig.empty-omitted",
    };
  }
  if (
    observation.rustStatus === "ok" &&
    observation.wallyStatus === "rejected" &&
    observation.wallyErrorClass === "psbt.parse_failed" &&
    observation.hasWitnessWithEmptyScriptSig
  ) {
    return { kind: "wally-rejected-noncanonical-empty-final-scriptsig" };
  }
  return { kind: "unclassified" };
}

function partialSignatureKeys(psbt: string): readonly string[] {
  const keys: string[] = [];
  for (const map of parsePsbtDocument(psbt).maps) {
    if (map.location.kind !== "input") continue;
    for (const entry of map.entries) {
      if (entry.keyType === PARTIAL_SIGNATURE) {
        keys.push(`${map.location.index}:${entry.keyData.toString("hex")}`);
      }
    }
  }
  return keys.sort();
}

function sameKeys(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function distinctMultisigContributionEvidence(
  unsigned: string,
  rustSigned: string,
  wallySigned: string,
  combined: string,
): ScenarioAssertionEvidence {
  const unsignedKeys = partialSignatureKeys(unsigned);
  const rustKeys = partialSignatureKeys(rustSigned);
  const wallyKeys = partialSignatureKeys(wallySigned);
  const combinedKeys = partialSignatureKeys(combined);
  const expectedCombined = [...new Set([...rustKeys, ...wallyKeys])].sort();
  const passed =
    unsignedKeys.length === 0 &&
    rustKeys.length === 1 &&
    wallyKeys.length === 1 &&
    rustKeys[0] !== wallyKeys[0] &&
    expectedCombined.length === 2 &&
    sameKeys(combinedKeys, expectedCombined);
  return {
    name: "psbtv2-distinct-multisig-contributions-preserved",
    passed,
    summary: passed
      ? "rust-psbt-v2 and libwally added distinct pubkey signatures and the combiner preserved both"
      : "The PSBTv2 branches did not contribute and preserve two distinct pubkey signatures",
  };
}

interface Direction {
  readonly id: "psbtv2-p2wpkh-rust-to-libwally" | "psbtv2-p2wpkh-libwally-to-rust";
  readonly signer: typeof RUST | typeof WALLY;
  readonly finalizer: typeof RUST | typeof WALLY;
}

const DIRECTIONS: readonly Direction[] = [
  {
    id: "psbtv2-p2wpkh-rust-to-libwally",
    signer: RUST,
    finalizer: WALLY,
  },
  {
    id: "psbtv2-p2wpkh-libwally-to-rust",
    signer: WALLY,
    finalizer: RUST,
  },
];

function requireFixture(fixture: PsbtFixture, id: "p2wpkh" | "p2wsh-2-of-3"): void {
  if (fixture.id !== id || fixture.psbtVersion !== 0 || fixture.inputCount < 1) {
    throw new TypeError(`PSBTv2 interoperability requires the ${id} PSBTv0 fixture`);
  }
}

function outputNumber(response: AdapterResponse, key: string, operation: string): number {
  if (response.status !== "ok") {
    throw new Error(`${response.implementation.name} ${operation} returned ${response.status}`);
  }
  const value = response.output[key];
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`${response.implementation.name} ${operation} omitted integer ${key}`);
  }
  return value as number;
}

function conversionEvidence(
  name: string,
  response: AdapterResponse,
  psbt: string,
  expectedVersion: 0 | 2,
  expectedUnsignedTxSha256: string,
): ScenarioAssertionEvidence {
  const version = parsePsbtDocument(psbt).psbtVersion;
  const reportedVersion = outputNumber(response, "psbtVersion", "convert");
  const reportedIdentity =
    response.status === "ok" ? response.output["unsignedTxSha256"] : undefined;
  const passed =
    version === expectedVersion &&
    reportedVersion === expectedVersion &&
    reportedIdentity === expectedUnsignedTxSha256;
  return {
    name,
    passed,
    likelyImplementation: WALLY,
    summary: passed
      ? `libwally converted to PSBTv${expectedVersion} without changing transaction intent`
      : `PSBT conversion did not preserve the expected version and unsigned transaction hash`,
  };
}

async function convert(
  context: ScenarioExecutionContext,
  fixture: PsbtFixture,
  psbt: string,
  targetVersion: 0 | 2,
  assertions: ScenarioAssertionEvidence[],
  stage: string,
): Promise<string> {
  const response = await context.request(WALLY, "convert", { psbt, targetVersion });
  const converted = context.outputString(response, "psbt", "convert");
  assertions.push(
    conversionEvidence(
      `${stage}-preserved-transaction-intent`,
      response,
      converted,
      targetVersion,
      fixture.unsignedTxSha256,
    ),
  );
  return converted;
}

async function extractWithBoth(
  context: ScenarioExecutionContext,
  finalizedPsbt: string,
  assertions: ScenarioAssertionEvidence[],
): Promise<{
  readonly findings: readonly ScenarioFinding[];
  readonly transaction: string;
  readonly libwallyCanParse: boolean;
}> {
  const wally = await context.request(WALLY, "extract", { psbt: finalizedPsbt });
  const rust = await context.request(RUST, "extract", { psbt: finalizedPsbt });
  const document = parsePsbtDocument(finalizedPsbt);
  const inputs = Array.from({ length: document.inputCount }, (_, index) =>
    document.maps.find(({ location }) => location.kind === "input" && location.index === index),
  );
  const hasWitnessWithoutScriptSig = inputs.every(
    (input) =>
      input?.entries.some(({ keyType }) => keyType === FINAL_SCRIPT_WITNESS) === true &&
      input.entries.every(({ keyType }) => keyType !== 0x07),
  );
  const hasWitnessWithEmptyScriptSig = inputs.every((input) => {
    const scriptSig = input?.entries.find(({ keyType }) => keyType === 0x07);
    return (
      input?.entries.some(({ keyType }) => keyType === FINAL_SCRIPT_WITNESS) === true &&
      scriptSig?.value.byteLength === 0
    );
  });
  const classification = classifyFinalScriptSigInterop({
    rustStatus: rust.status,
    rustErrorClass: rust.status === "ok" ? undefined : rust.error.class,
    wallyStatus: wally.status,
    wallyErrorClass: wally.status === "ok" ? undefined : wally.error.class,
    hasWitnessWithoutScriptSig,
    hasWitnessWithEmptyScriptSig,
  });

  if (rust.status !== "ok") {
    const knownDivergence = classification.kind === "rust-requires-empty-final-scriptsig";
    if (!knownDivergence) {
      context.outputString(rust, "transaction", "extract");
    }
    const transaction = context.outputString(wally, "transaction", "extract");
    assertions.push({
      name: "rust-psbt-reported-final-scriptsig-interop-divergence",
      passed: true,
      likelyImplementation: RUST,
      summary:
        "rust-psbt-v2 requires an explicit empty final scriptSig before extracting a SegWit PSBT finalized by libwally",
    });
    return {
      transaction,
      libwallyCanParse: true,
      findings: [
        {
          id: "rust-psbt-v2-final-scriptsig-required",
          ruleId: "bip174.final-scriptsig.empty-omitted",
          implementation: RUST,
          summary:
            "rust-psbt-v2 rejected a finalized SegWit PSBT whose empty final scriptSig was correctly omitted.",
          actual:
            "The extractor required PSBT_IN_FINAL_SCRIPTSIG to be present with a zero-length value.",
        },
      ],
    };
  }

  const rustTransaction = context.outputString(rust, "transaction", "extract");
  if (wally.status !== "ok") {
    const expectedStrictRejection =
      classification.kind === "wally-rejected-noncanonical-empty-final-scriptsig";
    if (!expectedStrictRejection) {
      context.outputString(wally, "transaction", "extract");
    }
    assertions.push({
      name: "libwally-rejected-noncanonical-empty-final-scriptsig",
      passed: true,
      likelyImplementation: WALLY,
      summary:
        "libwally strictly rejected the explicit empty final scriptSig that BIP174 says must be omitted",
    });
    return {
      transaction: rustTransaction,
      libwallyCanParse: false,
      findings: [],
    };
  }
  const wallyTransaction = context.outputString(wally, "transaction", "extract");
  assertions.push({
    name: "cross-library-extracted-transaction-match",
    passed: rustTransaction === wallyTransaction,
    summary:
      rustTransaction === wallyTransaction
        ? "rust-psbt and libwally extracted the same finalized transaction"
        : "Native extractors produced different finalized transactions",
  });
  return { findings: [], transaction: rustTransaction, libwallyCanParse: true };
}

async function corePolicyCheck(
  context: ScenarioExecutionContext,
  fixture: PsbtFixture,
  finalizedV2: string,
  extractedTransaction: string,
  libwallyCanParse: boolean,
  assertions: ScenarioAssertionEvidence[],
): Promise<{ readonly allowed: boolean; readonly txid?: string }> {
  const policy = libwallyCanParse
    ? await context.policyCheck(
        await context.finalizeWithCore(
          await convert(context, fixture, finalizedV2, 0, assertions, "finalized-v2-to-v0"),
        ),
      )
    : await context.policyCheckTransaction(extractedTransaction);
  assertions.push({
    name: "core-policy-accepted-psbtv2-result",
    passed: policy.allowed,
    summary: policy.allowed
      ? "Bitcoin Core accepted the transaction produced by the PSBTv2 handoff"
      : `Bitcoin Core rejected the PSBTv2 result${policy.rejectReason ? `: ${policy.rejectReason}` : ""}`,
  });
  return { allowed: policy.allowed, ...(policy.txid ? { txid: policy.txid } : {}) };
}

function adapterRequirement(adapter: typeof RUST | typeof WALLY) {
  return {
    adapter,
    operations: ["sign", "finalize", "extract"] as const,
    roles: ["signer", "finalizer", "extractor"] as const,
    psbtVersions: [2] as const,
    scriptTypes: ["p2wpkh"] as const,
    features: ["fixture-commitment-sha256", "unsigned-tx-sha256"] as const,
  };
}

function p2wpkhScenario(
  fixture: PsbtFixture,
  direction: Direction,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: direction.id,
    title: `PSBTv2 P2WPKH ${direction.signer} to ${direction.finalizer}`,
    category: "psbtv2-interop",
    summary: `${WALLY} converts the Core fixture to PSBTv2, ${direction.signer} signs it, and ${direction.finalizer} finalizes it.`,
    requirements: [
      adapterRequirement(RUST),
      { ...adapterRequirement(WALLY), operations: ["convert", "sign", "finalize", "extract"] },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const v2 = await convert(
        context,
        fixture,
        fixture.initialPsbt,
        2,
        assertions,
        "core-v0-to-v2",
      );
      await context.checkpoint(direction.id, "converted-v2", v2);

      const sign = await context.request(direction.signer, "sign", {
        psbt: v2,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const signed = context.outputString(sign, "psbt", "sign");
      assertions.push(
        context.requireTransition(
          "sign",
          `${direction.signer}-psbtv2-signing-transition`,
          v2,
          signed,
          direction.signer,
        ),
        context.requireAddedInputField(`${direction.signer}-added-psbtv2-signature`, v2, signed, [
          PARTIAL_SIGNATURE,
        ]),
      );
      await context.checkpoint(direction.id, `${direction.signer}-signed`, signed);

      const finalize = await context.request(direction.finalizer, "finalize", {
        psbt: signed,
        network: "regtest",
        fixtureId: fixture.id,
      });
      const finalized = context.outputString(finalize, "psbt", "finalize");
      const indexes = Array.from({ length: fixture.inputCount }, (_, index) => index);
      assertions.push(
        context.requireTransition(
          "finalize",
          `${direction.finalizer}-psbtv2-finalization-transition`,
          signed,
          finalized,
          direction.finalizer,
        ),
        context.requireInputFieldPresence(
          `${direction.finalizer}-returned-final-witness`,
          finalized,
          [FINAL_SCRIPT_WITNESS],
          indexes,
        ),
        context.requireInputFieldAbsence(
          `${direction.finalizer}-removed-signing-metadata`,
          finalized,
          SIGNING_METADATA,
          indexes,
        ),
      );
      await context.checkpoint(direction.id, `${direction.finalizer}-finalized`, finalized);

      const extraction = await extractWithBoth(context, finalized, assertions);
      const policy = await corePolicyCheck(
        context,
        fixture,
        finalized,
        extraction.transaction,
        extraction.libwallyCanParse,
        assertions,
      );
      return {
        summary: `${direction.signer} signed and ${direction.finalizer} finalized one PSBTv2 transaction accepted by Core.`,
        assertions,
        ...(extraction.findings.length > 0 ? { findings: extraction.findings } : {}),
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}

export function createP2wpkhPsbtv2InteropScenarios(
  fixture: PsbtFixture,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  requireFixture(fixture, "p2wpkh");
  return DIRECTIONS.map((direction) => p2wpkhScenario(fixture, direction));
}

export function createMultisigPsbtv2InteropScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  requireFixture(fixture, "p2wsh-2-of-3");
  return {
    id: "psbtv2-2-of-3-cross-library",
    title: "PSBTv2 2-of-3 cross-library signing and finalization",
    category: "psbtv2-interop",
    summary:
      "rust-psbt and libwally independently sign one PSBTv2 multisig input, then combine, finalize, and extract it across libraries.",
    requirements: [
      {
        ...adapterRequirement(RUST),
        operations: ["sign", "combine", "finalize", "extract"],
        scriptTypes: ["p2wsh"],
      },
      {
        ...adapterRequirement(WALLY),
        operations: ["convert", "sign", "combine", "finalize", "extract"],
        scriptTypes: ["p2wsh"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const v2 = await convert(
        context,
        fixture,
        fixture.initialPsbt,
        2,
        assertions,
        "multisig-v0-to-v2",
      );
      const signPayload = { psbt: v2, network: "regtest", fixtureId: fixture.id } as const;
      const rustSigned = context.outputString(
        await context.request(RUST, "sign", signPayload),
        "psbt",
        "sign",
      );
      const wallySigned = context.outputString(
        await context.request(WALLY, "sign", signPayload),
        "psbt",
        "sign",
      );
      assertions.push(
        context.requireTransition("sign", "rust-psbt-v2-multisig-signature", v2, rustSigned, RUST),
        context.requireTransition("sign", "libwally-multisig-signature", v2, wallySigned, WALLY),
      );

      const combined = context.outputString(
        await context.request(RUST, "combine", { psbts: [rustSigned, wallySigned] }),
        "psbt",
        "combine",
      );
      assertions.push(
        context.requireTransition(
          "combine",
          "rust-psbt-combined-libwally-signature",
          rustSigned,
          combined,
          RUST,
        ),
        distinctMultisigContributionEvidence(v2, rustSigned, wallySigned, combined),
      );
      await context.checkpoint("psbtv2-2-of-3-cross-library", "combined", combined);

      const finalized = context.outputString(
        await context.request(WALLY, "finalize", {
          psbt: combined,
          network: "regtest",
          fixtureId: fixture.id,
        }),
        "psbt",
        "finalize",
      );
      assertions.push(
        context.requireTransition(
          "finalize",
          "libwally-finalized-combined-psbtv2",
          combined,
          finalized,
          WALLY,
        ),
      );
      const extraction = await extractWithBoth(context, finalized, assertions);
      const policy = await corePolicyCheck(
        context,
        fixture,
        finalized,
        extraction.transaction,
        extraction.libwallyCanParse,
        assertions,
      );
      return {
        summary:
          "rust-psbt and libwally contributed distinct signatures and produced one Core-accepted multisig transaction.",
        assertions,
        ...(extraction.findings.length > 0 ? { findings: extraction.findings } : {}),
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
