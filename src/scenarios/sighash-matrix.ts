import type { PsbtFixture } from "../core/fixtures.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export interface SighashCase {
  readonly id: string;
  readonly value: number;
  readonly base: "ALL" | "NONE" | "SINGLE";
  readonly anyoneCanPay: boolean;
}

export const ECDSA_SIGHASH_CASES = [
  { id: "all", value: 0x01, base: "ALL", anyoneCanPay: false },
  { id: "none", value: 0x02, base: "NONE", anyoneCanPay: false },
  { id: "single", value: 0x03, base: "SINGLE", anyoneCanPay: false },
  { id: "all-anyonecanpay", value: 0x81, base: "ALL", anyoneCanPay: true },
  { id: "none-anyonecanpay", value: 0x82, base: "NONE", anyoneCanPay: true },
  { id: "single-anyonecanpay", value: 0x83, base: "SINGLE", anyoneCanPay: true },
] as const satisfies readonly SighashCase[];

export const TAPROOT_SIGHASH_CASES = [
  { id: "default", value: 0x00, base: "ALL", anyoneCanPay: false },
  ...ECDSA_SIGHASH_CASES,
] as const satisfies readonly SighashCase[];

export interface SighashCommitments {
  readonly committedInputOutpoints: readonly number[];
  readonly permittedInputOutpoints: readonly number[];
  readonly committedInputSequences: readonly number[];
  readonly permittedInputSequences: readonly number[];
  readonly committedOutputs: readonly number[];
  readonly permittedOutputs: readonly number[];
}

function indexes(length: number): number[] {
  return Array.from({ length }, (_, index) => index);
}

export function classifySighashCommitments(
  family: "ecdsa" | "taproot",
  sighashType: number,
  signingInput: number,
  inputCount: number,
  outputCount: number,
): SighashCommitments {
  if (
    !Number.isSafeInteger(signingInput) ||
    signingInput < 0 ||
    signingInput >= inputCount ||
    inputCount < 1 ||
    outputCount < 0
  ) {
    throw new RangeError("Sighash commitment dimensions are invalid");
  }
  const normalized = sighashType === 0 ? 0x01 : sighashType;
  const base = normalized & 0x1f;
  if (![0x01, 0x02, 0x03].includes(base) || (normalized & ~0x9f) !== 0) {
    throw new RangeError("Sighash type is not a standard matrix value");
  }
  const allInputs = indexes(inputCount);
  const allOutputs = indexes(outputCount);
  const anyoneCanPay = (normalized & 0x80) !== 0;
  const committedInputOutpoints = anyoneCanPay ? [signingInput] : allInputs;
  const committedInputSequences =
    anyoneCanPay || (family === "ecdsa" && (base === 0x02 || base === 0x03))
      ? [signingInput]
      : allInputs;
  const committedOutputs =
    base === 0x01
      ? allOutputs
      : base === 0x02
        ? []
        : signingInput < outputCount
          ? [signingInput]
          : [];
  return {
    committedInputOutpoints,
    permittedInputOutpoints: allInputs.filter((index) => !committedInputOutpoints.includes(index)),
    committedInputSequences,
    permittedInputSequences: allInputs.filter((index) => !committedInputSequences.includes(index)),
    committedOutputs,
    permittedOutputs: allOutputs.filter((index) => !committedOutputs.includes(index)),
  };
}

interface SighashMutationChecks {
  readonly signedInputSequenceValid: boolean;
  readonly otherInputOutpointValid: boolean;
  readonly otherInputSequenceValid: boolean;
  readonly outputValueValid: readonly boolean[];
}

function mutationChecks(value: unknown): SighashMutationChecks | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const object = value as Record<string, unknown>;
  const outputValueValid = object["outputValueValid"];
  if (
    typeof object["signedInputSequenceValid"] !== "boolean" ||
    typeof object["otherInputOutpointValid"] !== "boolean" ||
    typeof object["otherInputSequenceValid"] !== "boolean" ||
    !Array.isArray(outputValueValid) ||
    outputValueValid.some((item) => typeof item !== "boolean")
  ) {
    return undefined;
  }
  return {
    signedInputSequenceValid: object["signedInputSequenceValid"],
    otherInputOutpointValid: object["otherInputOutpointValid"],
    otherInputSequenceValid: object["otherInputSequenceValid"],
    outputValueValid: outputValueValid as boolean[],
  };
}

function encodeUint32(value: number): string {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value);
  return buffer.toString("hex");
}

export function withSighashType(psbt: string, sighashType: number, inputCount: number): string {
  if (sighashType === 0) return psbt;
  const recipes: PsbtMutationRecipe[] = indexes(inputCount).map((index) => ({
    kind: "set-entry",
    location: { kind: "input", index },
    keyType: 0x03,
    valueHex: encodeUint32(sighashType),
  }));
  return applyPsbtMutations(psbt, recipes);
}

function signatureEvidence(
  family: "ecdsa" | "taproot",
  testCase: SighashCase,
  signedPsbt: string,
  inputCount: number,
): ScenarioAssertionEvidence {
  const document = parsePsbtDocument(signedPsbt);
  const keyType = family === "ecdsa" ? 0x02 : 0x13;
  const signatures = document.maps
    .filter((map) => map.location.kind === "input")
    .map((map) => map.entries.filter((entry) => entry.keyType === keyType));
  const exact =
    signatures.length === inputCount &&
    signatures.every((entries) => {
      if (entries.length !== 1) return false;
      const value = entries[0]?.value;
      if (!value) return false;
      if (family === "ecdsa") return value.at(-1) === testCase.value;
      return testCase.value === 0
        ? value.byteLength === 64
        : value.byteLength === 65 && value.at(-1) === testCase.value;
    });
  return {
    name: `${testCase.id}-signature-encoding`,
    passed: exact,
    summary: exact
      ? `${family} signatures encode ${testCase.id} on every input`
      : `${family} signatures do not encode ${testCase.id} exactly`,
  };
}

export interface SighashScenarioOptions {
  readonly adapter: string;
  readonly family: "ecdsa" | "taproot";
}

export function createSighashMatrixScenario(
  fixture: PsbtFixture,
  options: SighashScenarioOptions,
): ScenarioDefinition<ScenarioExecutionContext> {
  const cases = options.family === "ecdsa" ? ECDSA_SIGHASH_CASES : TAPROOT_SIGHASH_CASES;
  const scriptType = options.family === "ecdsa" ? "p2wpkh" : "p2tr-keypath";
  return {
    id: `${options.family}-sighash-matrix-${options.adapter}`,
    title: `${options.family === "ecdsa" ? "ECDSA" : "Taproot"} sighash matrix through ${options.adapter}`,
    category: "sighash-safety",
    summary:
      "Signs every standard sighash mode, records its mutation commitments, and requires Core policy acceptance.",
    requirements: [
      {
        adapter: options.adapter,
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: [scriptType],
        features: ["fixture-commitment-sha256", "sighash-matrix-v1"],
      },
    ],
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      for (const testCase of cases) {
        const prepared = withSighashType(fixture.initialPsbt, testCase.value, fixture.inputCount);
        const response = await context.request(options.adapter, "sign", {
          psbt: prepared,
          network: "regtest",
          fixtureId: fixture.id,
          sighashType: testCase.value,
        });
        if (response.status !== "ok" || typeof response.output["psbt"] !== "string") {
          assertions.push({
            name: `${testCase.id}-sign`,
            passed: false,
            likelyImplementation: options.adapter,
            summary:
              response.status === "ok"
                ? `${options.adapter} omitted the signed PSBT`
                : `${options.adapter} returned ${response.status}: ${response.error.class}`,
          });
          continue;
        }
        const signedPsbt = response.output["psbt"];
        assertions.push({
          name: `${testCase.id}-sign`,
          passed: true,
          likelyImplementation: options.adapter,
          summary: `${options.adapter} signed ${testCase.id}`,
        });
        assertions.push(
          signatureEvidence(options.family, testCase, signedPsbt, fixture.inputCount),
        );
        const commitments = classifySighashCommitments(
          options.family,
          testCase.value,
          0,
          fixture.inputCount,
          fixture.outputCount,
        );
        const measured = mutationChecks(response.output["mutationChecks"]);
        const expectedOtherOutpoint = commitments.permittedInputOutpoints.includes(1);
        const expectedOtherSequence = commitments.permittedInputSequences.includes(1);
        const expectedOutputs = indexes(fixture.outputCount).map((index) =>
          commitments.permittedOutputs.includes(index),
        );
        const exactMutationEvidence =
          measured !== undefined &&
          measured.signedInputSequenceValid === false &&
          measured.otherInputOutpointValid === expectedOtherOutpoint &&
          measured.otherInputSequenceValid === expectedOtherSequence &&
          measured.outputValueValid.length === expectedOutputs.length &&
          measured.outputValueValid.every((valid, index) => valid === expectedOutputs[index]);
        assertions.push({
          name: `${testCase.id}-mutation-signature-validity`,
          passed: exactMutationEvidence,
          likelyImplementation: options.adapter,
          summary: exactMutationEvidence
            ? `${testCase.id} cryptographically matched the expected outpoint, sequence, and output commitments`
            : `${testCase.id} did not return the expected cryptographic mutation evidence`,
        });
        await context.checkpoint(
          `${options.family}-sighash-matrix-${options.adapter}`,
          testCase.id,
          signedPsbt,
        );
        const finalized = await context.finalizeWithCore(signedPsbt);
        assertions.push({
          name: `${testCase.id}-core-finalize`,
          passed: finalized.complete && typeof finalized.hex === "string",
          summary: finalized.complete
            ? `Bitcoin Core finalized ${testCase.id}`
            : `Bitcoin Core did not finalize ${testCase.id}`,
        });
        if (finalized.complete && finalized.hex) {
          const policy = await context.policyCheck(finalized);
          assertions.push({
            name: `${testCase.id}-core-policy`,
            passed: policy.allowed,
            summary: policy.allowed
              ? `Bitcoin Core policy accepted ${testCase.id}`
              : `Bitcoin Core policy rejected ${testCase.id}`,
          });
        }
      }

      if (options.family === "taproot") {
        const invalid = withSighashType(fixture.initialPsbt, 0x80, fixture.inputCount);
        const response = await context.request(options.adapter, "sign", {
          psbt: invalid,
          network: "regtest",
          fixtureId: fixture.id,
          sighashType: 0x80,
        });
        assertions.push({
          name: "default-anyonecanpay-rejected",
          passed: response.status === "rejected",
          likelyImplementation: options.adapter,
          summary:
            response.status === "rejected"
              ? `${options.adapter} rejected invalid DEFAULT|ANYONECANPAY`
              : `${options.adapter} returned ${response.status} for invalid DEFAULT|ANYONECANPAY`,
        });
      }

      return {
        summary: `Checked ${cases.length} standard ${options.family} sighash modes through ${options.adapter}.`,
        assertions,
      };
    },
  };
}
