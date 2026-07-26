import { BIP371_INVALID_VECTORS, BIP371_VALID_VECTORS } from "../psbt/bip371-vectors.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { taprootTreeMerkleRoot } from "../psbt/taproot-tree.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioDefinition } from "./definition.js";

function safeAdapterId(adapter: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(adapter)) {
    throw new TypeError("BIP371 adapter id must be a safe identifier");
  }
  return adapter;
}

function safeParserName(parser: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/.test(parser)) {
    throw new TypeError("BIP371 native parser name must be a safe identifier");
  }
  return parser;
}

function outputTaprootTreeRoots(psbt: string): readonly string[] {
  return parsePsbtDocument(psbt)
    .maps.filter(({ location }) => location.kind === "output")
    .flatMap((map) =>
      map.entries
        .filter(({ keyType }) => keyType === 0x06)
        .map(({ value }) => taprootTreeMerkleRoot(value)),
    );
}

function validRoundtripPassed(
  context: ScenarioExecutionContext,
  name: string,
  before: string,
  after: string,
  adapter: string,
): boolean {
  const strict = context.transitionEvidence("roundtrip", name, before, after, adapter);
  if (strict.passed) return true;
  const beforeRoots = outputTaprootTreeRoots(before);
  const afterRoots = outputTaprootTreeRoots(after);
  return (
    (strict.failures?.length ?? 0) > 0 &&
    strict.failures?.every(
      ({ location, keyType }) => location.kind === "output" && keyType === 0x06,
    ) === true &&
    beforeRoots.length === afterRoots.length &&
    beforeRoots.every((root, index) => root === afterRoots[index])
  );
}

export function createBip371VectorScenario(
  adapterName: string,
  nativeParserName = adapterName,
): ScenarioDefinition<ScenarioExecutionContext> {
  const adapter = safeAdapterId(adapterName);
  const nativeParser = safeParserName(nativeParserName);
  return {
    id: `bip371-official-vectors-${adapter}`,
    title: `Official BIP371 vectors through ${adapter}`,
    category: "taproot-conformance",
    summary:
      "The native PSBT parser and serializer are checked against the complete official BIP371 Taproot corpus.",
    requirements: [
      {
        adapter,
        operations: ["native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
      },
    ],
    async run(context) {
      const validFailures: string[] = [];
      const invalidAcceptances: string[] = [];

      for (const vector of BIP371_VALID_VECTORS) {
        const parsed = await context.request(adapter, "native-parse", {
          psbt: vector.base64,
        });
        if (parsed.status !== "ok" || parsed.output["nativeParser"] !== nativeParser) {
          validFailures.push(`${vector.id}:native-parse`);
          continue;
        }

        const roundtrip = await context.request(adapter, "roundtrip", {
          psbt: vector.base64,
        });
        const returned = roundtrip.status === "ok" ? roundtrip.output["psbt"] : undefined;
        if (
          typeof returned !== "string" ||
          !validRoundtripPassed(context, `${vector.id}-roundtrip`, vector.base64, returned, adapter)
        ) {
          validFailures.push(`${vector.id}:roundtrip`);
        }
      }

      for (const vector of BIP371_INVALID_VECTORS) {
        const parsed = await context.request(adapter, "native-parse", {
          psbt: vector.base64,
        });
        if (parsed.status !== "rejected" || parsed.error.class !== "psbt.native_parse_failed") {
          invalidAcceptances.push(vector.id);
        }
      }

      return {
        summary:
          validFailures.length === 0 && invalidAcceptances.length === 0
            ? `${adapter} matched all 17 official BIP371 vectors.`
            : `${adapter} disagreed with the official BIP371 corpus.`,
        assertions: [
          {
            name: "bip371-valid-vectors",
            passed: validFailures.length === 0,
            summary:
              validFailures.length === 0
                ? "All 6 valid vectors parsed and roundtripped semantically"
                : `Failures: ${validFailures.join(", ")}`,
          },
          {
            name: "bip371-invalid-vectors",
            passed: invalidAcceptances.length === 0,
            summary:
              invalidAcceptances.length === 0
                ? "All 11 invalid vectors were rejected by the native parser"
                : `Unexpected acceptances: ${invalidAcceptances.join(", ")}`,
          },
        ],
      };
    },
  };
}
