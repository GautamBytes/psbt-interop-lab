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
): ScenarioDefinition<ScenarioExecutionContext> {
  const adapter = safeAdapterId(adapterName);
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
        if (parsed.status !== "ok" || parsed.output["nativeParser"] !== adapter) {
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

      return {
        summary:
          validFailures.length === 0 && invalidFailures.length === 0
            ? `${adapter} accepted 14 valid BIP370 vectors, preserved each roundtrip, and rejected 21 invalid vectors.`
            : `${adapter} disagreed with the official BIP370 corpus.`,
        assertions: [
          {
            name: "bip370-valid-vectors",
            passed: validFailures.length === 0,
            summary:
              validFailures.length === 0
                ? "All 14 valid vectors parsed and roundtripped semantically"
                : `Failures: ${validFailures.join(", ")}`,
          },
          {
            name: "bip370-invalid-vectors",
            passed: invalidFailures.length === 0,
            summary:
              invalidFailures.length === 0
                ? "All 21 invalid vectors were rejected by the native parser"
                : `Unexpected acceptances: ${invalidFailures.join(", ")}`,
          },
        ],
      };
    },
  };
}
