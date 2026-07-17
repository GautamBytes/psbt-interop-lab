import { BIP370_INVALID_VECTORS, BIP370_VALID_VECTORS } from "../psbt/bip370-vectors.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioDefinition } from "./definition.js";

function safeAdapterId(adapter: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(adapter)) {
    throw new TypeError("BIP370 adapter id must be a safe identifier");
  }
  return adapter;
}

export function createBip370VectorScenario(
  adapterName: string,
  nativeParserName = adapterName,
  allowedValidNativeRejections: readonly string[] = [],
): ScenarioDefinition<ScenarioExecutionContext> {
  const adapter = safeAdapterId(adapterName);
  const nativeParser = safeAdapterId(nativeParserName);
  const allowedRejections = new Set(allowedValidNativeRejections.map(safeAdapterId));
  return {
    id: `bip370-official-vectors-${adapter}`,
    title: `Official BIP370 vectors through ${adapter}`,
    category: "psbtv2-conformance",
    summary:
      "The native PSBTv2 parser and serializer are checked against the complete deployed BIP370 parse corpus.",
    requirements: [
      {
        adapter,
        operations: ["native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [2],
      },
    ],
    async run(context) {
      const validFailures: string[] = [];
      const invalidFailures: string[] = [];

      for (const vector of BIP370_VALID_VECTORS) {
        const parsed = await context.request(adapter, "native-parse", { psbt: vector.base64 });
        if (parsed.status !== "ok" || parsed.output["nativeParser"] !== nativeParser) {
          validFailures.push(`${vector.id}:native-parse`);
          continue;
        }
        const roundtrip = await context.request(adapter, "roundtrip", { psbt: vector.base64 });
        const returned = roundtrip.status === "ok" ? roundtrip.output["psbt"] : undefined;
        if (
          typeof returned !== "string" ||
          !context.transitionEvidence(
            "roundtrip",
            `${vector.id}-roundtrip`,
            vector.base64,
            returned,
          ).passed
        ) {
          validFailures.push(`${vector.id}:roundtrip`);
        }
      }

      for (const vector of BIP370_INVALID_VECTORS) {
        const parsed = await context.request(adapter, "native-parse", { psbt: vector.base64 });
        if (parsed.status !== "rejected" || parsed.error.class !== "psbt.native_parse_failed") {
          invalidFailures.push(vector.id);
        }
      }

      const expectedValidRejections = validFailures.filter((failure) => {
        const [vectorId, stage] = failure.split(":");
        return stage === "native-parse" && vectorId !== undefined && allowedRejections.has(vectorId);
      });
      const unexpectedValidFailures = validFailures.filter(
        (failure) => !expectedValidRejections.includes(failure),
      );
      const validPassed = unexpectedValidFailures.length === 0;
      const invalidPassed = invalidFailures.length === 0;

      return {
        summary:
          validPassed && invalidPassed
            ? `${adapter} matched the BIP370 corpus${expectedValidRejections.length > 0 ? ` with ${expectedValidRejections.length} explicit compatibility findings` : ""}.`
            : `${adapter} disagreed with the official BIP370 corpus.`,
        assertions: [
          {
            name: "bip370-valid-vectors",
            passed: validPassed,
            summary:
              unexpectedValidFailures.length === 0
                ? `All valid vectors were accepted or recorded as bounded compatibility findings`
                : `Failures: ${unexpectedValidFailures.join(", ")}`,
          },
          {
            name: "bip370-invalid-vectors",
            passed: invalidPassed,
            summary:
              invalidFailures.length === 0
                ? "All 21 invalid vectors were rejected by the native parser"
                : `Unexpected acceptances: ${invalidFailures.join(", ")}`,
            },
        ],
        ...(expectedValidRejections.length > 0
          ? {
              findings: [
                {
                  id: "bip370-valid-tx-modifiable-flags-rejected",
                  implementation: adapter,
                  summary: `Native strict parsing rejected valid vectors ${expectedValidRejections
                    .map((failure) => failure.split(":")[0])
                    .join(", ")} containing undefined transaction-modifiable flag bits.`,
                },
              ],
            }
          : {}),
      };
    },
  };
}
