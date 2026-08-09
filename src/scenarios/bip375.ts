import { validateBip375ReferencePsbt } from "../psbt/bip375-validator.js";
import {
  BIP375_INVALID_VECTORS,
  BIP375_VALID_VECTORS,
  type Bip375VectorStage,
} from "../psbt/bip375-vectors.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const INVALID_STAGES = [
  "psbt structure",
  "ecdh coverage",
  "input eligibility",
  "output scripts",
] as const satisfies readonly Bip375VectorStage[];

const NATIVE_STRUCTURAL_INVALID_IDS = new Set([
  "invalid-01",
  "invalid-02",
  "invalid-03",
  "invalid-04",
  "invalid-06",
]);

const SILENT_PAYMENT_FIELD_TYPES = {
  globalEcdhShares: ["global", 0x07],
  globalDleqProofs: ["global", 0x08],
  inputEcdhShares: ["input", 0x1d],
  inputDleqProofs: ["input", 0x1e],
  outputsWithInfo: ["output", 0x09],
  outputsWithLabel: ["output", 0x0a],
} as const;

type SilentPaymentFieldCounts = Record<keyof typeof SILENT_PAYMENT_FIELD_TYPES, number>;

function expectedSilentPaymentFields(psbt: string): SilentPaymentFieldCounts {
  const document = parsePsbtDocument(psbt);
  return Object.fromEntries(
    Object.entries(SILENT_PAYMENT_FIELD_TYPES).map(([name, [scope, keyType]]) => [
      name,
      document.maps.reduce(
        (count, map) =>
          count +
          (map.location.kind === scope
            ? map.entries.filter((entry) => entry.keyType === keyType).length
            : 0),
        0,
      ),
    ]),
  ) as SilentPaymentFieldCounts;
}

function nativeSilentPaymentFields(value: unknown): SilentPaymentFieldCounts | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const entries = Object.keys(SILENT_PAYMENT_FIELD_TYPES).map(
    (name) => [name, record[name]] as const,
  );
  if (entries.some(([, count]) => !Number.isSafeInteger(count) || Number(count) < 0)) {
    return undefined;
  }
  return Object.fromEntries(entries) as SilentPaymentFieldCounts;
}

function sameCounts(left: SilentPaymentFieldCounts, right: SilentPaymentFieldCounts): boolean {
  return Object.keys(SILENT_PAYMENT_FIELD_TYPES).every(
    (name) =>
      left[name as keyof SilentPaymentFieldCounts] ===
      right[name as keyof SilentPaymentFieldCounts],
  );
}

function onlyMaterializesEmptyOutputScripts(beforePsbt: string, afterPsbt: string): boolean {
  const difference = diffPsbtDocuments(parsePsbtDocument(beforePsbt), parsePsbtDocument(afterPsbt));
  return (
    difference.removed.length === 0 &&
    difference.changed.length === 0 &&
    difference.added.length > 0 &&
    difference.added.every(
      (entry) =>
        entry.location.kind === "output" &&
        entry.keyType === 0x04 &&
        entry.keyBytes === 1 &&
        entry.valueBytes === 0,
    )
  );
}

function safeAdapterId(adapter: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(adapter)) {
    throw new TypeError("BIP375 adapter id must be a safe identifier");
  }
  return adapter;
}

function invalidStageAssertion(stage: Bip375VectorStage): ScenarioAssertionEvidence {
  const failures = BIP375_INVALID_VECTORS.filter(
    (vector) => vector.expectedStage === stage,
  ).flatMap((vector) => {
    const result = validateBip375ReferencePsbt(vector.base64);
    return !result.valid && result.stage === stage
      ? []
      : [`${vector.id}: expected ${stage}, got ${result.valid ? "accepted" : result.stage}`];
  });

  return {
    name: `bip375-invalid-${stage.replaceAll(" ", "-")}`,
    passed: failures.length === 0,
    summary:
      failures.length === 0
        ? `All invalid ${stage} vectors failed at the expected stage`
        : `Mismatches: ${failures.join(", ")}`,
  };
}

export function createBip375ReferenceScenario(): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "bip375-official-reference-vectors",
    title: "Official BIP375 Silent Payment reference vectors",
    category: "silent-payment-conformance",
    summary:
      "The complete official BIP375 corpus is checked with local cryptographic and structural validation.",
    requirements: [],
    async run() {
      const validFailures = BIP375_VALID_VECTORS.flatMap((vector) => {
        const result = validateBip375ReferencePsbt(vector.base64);
        return result.valid ? [] : [`${vector.id}: ${result.stage}: ${result.message}`];
      });
      const assertions: ScenarioAssertionEvidence[] = [
        {
          name: "bip375-valid-vectors",
          passed: validFailures.length === 0,
          summary:
            validFailures.length === 0
              ? `All ${BIP375_VALID_VECTORS.length} valid vectors passed`
              : `Failures: ${validFailures.join(", ")}`,
        },
        ...INVALID_STAGES.map(invalidStageAssertion),
      ];
      const passed = assertions.every((assertion) => assertion.passed);

      return {
        summary: passed
          ? `All ${BIP375_VALID_VECTORS.length + BIP375_INVALID_VECTORS.length} official BIP375 vectors matched their expected outcomes.`
          : "The local validator disagreed with the official BIP375 corpus.",
        assertions,
      };
    },
  };
}

export function createBip375NativeParserScenario(
  adapterName: string,
  nativeParserName = adapterName,
): ScenarioDefinition<ScenarioExecutionContext> {
  const adapter = safeAdapterId(adapterName);
  const nativeParser = safeAdapterId(nativeParserName);
  return {
    id: `bip375-official-vectors-${adapter}`,
    title: `Official BIP375 vectors through ${adapter}`,
    category: "silent-payment-interop",
    summary:
      "The native PSBTv2 parser recognizes typed Silent Payment fields and classifies the complete official BIP375 corpus.",
    requirements: [
      {
        adapter,
        operations: ["native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [2],
        features: ["bip375-silent-payments"],
      },
    ],
    async run(context) {
      const validFailures: string[] = [];
      const structuralFailures: string[] = [];
      const semanticFailures: string[] = [];
      const materializedOutputScripts: string[] = [];
      const acceptedOfficialInvalids: string[] = [];
      let semanticAccepted = 0;
      let semanticRejected = 0;

      for (const vector of BIP375_VALID_VECTORS) {
        const expectedFields = expectedSilentPaymentFields(vector.base64);
        const parsed = await context.request(adapter, "native-parse", { psbt: vector.base64 });
        const parsedFields =
          parsed.status === "ok"
            ? nativeSilentPaymentFields(parsed.output["silentPaymentFields"])
            : undefined;
        if (
          parsed.status !== "ok" ||
          parsed.output["nativeParser"] !== nativeParser ||
          parsedFields === undefined ||
          !sameCounts(parsedFields, expectedFields)
        ) {
          validFailures.push(`${vector.id}:native-parse`);
          continue;
        }

        const roundtrip = await context.request(adapter, "roundtrip", { psbt: vector.base64 });
        const returned = roundtrip.status === "ok" ? roundtrip.output["psbt"] : undefined;
        const roundtripFields =
          roundtrip.status === "ok"
            ? nativeSilentPaymentFields(roundtrip.output["silentPaymentFields"])
            : undefined;
        if (typeof returned !== "string" || roundtripFields === undefined) {
          validFailures.push(`${vector.id}:roundtrip`);
          continue;
        }
        const transition = context.transitionEvidence(
          "roundtrip",
          `${vector.id}-roundtrip`,
          vector.base64,
          returned,
          adapter,
        );
        if (!sameCounts(roundtripFields, expectedFields)) {
          validFailures.push(`${vector.id}:roundtrip-fields`);
        } else if (!transition.passed) {
          if (onlyMaterializesEmptyOutputScripts(vector.base64, returned)) {
            materializedOutputScripts.push(vector.id);
          } else {
            validFailures.push(`${vector.id}:roundtrip`);
          }
        }
      }

      for (const vector of BIP375_INVALID_VECTORS) {
        const parsed = await context.request(adapter, "native-parse", { psbt: vector.base64 });
        if (NATIVE_STRUCTURAL_INVALID_IDS.has(vector.id)) {
          if (parsed.status !== "rejected" || parsed.error.class !== "psbt.native_parse_failed") {
            structuralFailures.push(`${vector.id}:${parsed.status}`);
          }
          continue;
        }

        if (parsed.status === "ok") {
          const fields = nativeSilentPaymentFields(parsed.output["silentPaymentFields"]);
          if (parsed.output["nativeParser"] !== nativeParser || fields === undefined) {
            semanticFailures.push(`${vector.id}:invalid-native-view`);
          } else {
            semanticAccepted += 1;
            if (vector.expectedStage === "psbt structure") {
              acceptedOfficialInvalids.push(vector.id);
            }
          }
        } else if (
          parsed.status === "rejected" &&
          parsed.error.class === "psbt.native_parse_failed"
        ) {
          semanticRejected += 1;
        } else {
          semanticFailures.push(`${vector.id}:${parsed.status}`);
        }
      }

      const assertions: ScenarioAssertionEvidence[] = [
        {
          name: "bip375-native-valid-vectors",
          passed: validFailures.length === 0,
          summary:
            validFailures.length === 0
              ? `All ${BIP375_VALID_VECTORS.length} valid vectors parsed with typed fields and roundtripped semantically`
              : `Failures: ${validFailures.join(", ")}`,
        },
        {
          name: "bip375-native-structural-rejections",
          passed: structuralFailures.length === 0,
          summary:
            structuralFailures.length === 0
              ? `All ${NATIVE_STRUCTURAL_INVALID_IDS.size} malformed-field vectors were rejected by the native parser`
              : `Unexpected outcomes: ${structuralFailures.join(", ")}`,
        },
        {
          name: "bip375-native-semantic-classification",
          passed: semanticFailures.length === 0,
          summary:
            semanticFailures.length === 0
              ? `${semanticAccepted} later-validation vectors were parsed structurally and ${semanticRejected} were rejected; the reference scenario owns cross-field and cryptographic validity`
              : `Unbounded outcomes: ${semanticFailures.join(", ")}`,
        },
      ];
      const findings = [
        ...(materializedOutputScripts.length > 0
          ? [
              {
                id: "bip375-empty-output-script-materialized",
                ruleId: "lab.fields.no-unexpected-addition" as const,
                implementation: adapter,
                summary: `${adapter} materialized explicit empty PSBT_OUT_SCRIPT fields while roundtripping ${materializedOutputScripts.join(", ")}.`,
                actual:
                  "The native serializer added an empty output script to an in-progress Silent Payment output that omitted the field.",
                evidence: materializedOutputScripts,
              },
            ]
          : []),
        ...(acceptedOfficialInvalids.length > 0
          ? [
              {
                id: "bip375-cross-field-invalid-accepted",
                ruleId: "bip375.invalid-vectors.rejected" as const,
                implementation: adapter,
                summary: `${adapter} parsed ${acceptedOfficialInvalids.join(", ")} structurally; the reference validator rejects the BIP375 cross-field constraint.`,
                actual:
                  "The native parser accepted an official invalid vector whose failure requires BIP375 cross-field validation.",
                evidence: acceptedOfficialInvalids,
              },
            ]
          : []),
      ];
      return {
        summary: assertions.every(({ passed }) => passed)
          ? `${adapter} classified all ${BIP375_VALID_VECTORS.length + BIP375_INVALID_VECTORS.length} official BIP375 vectors without losing typed Silent Payment fields${findings.length > 0 ? `, with ${findings.length} explicit compatibility findings` : ""}.`
          : `${adapter} disagreed with the expected BIP375 parser boundary.`,
        assertions,
        ...(findings.length > 0 ? { findings } : {}),
      };
    },
  };
}
