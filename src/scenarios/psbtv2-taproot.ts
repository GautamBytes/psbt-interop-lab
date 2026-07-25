import { BIP371_VALID_VECTORS, type Bip371Vector } from "../psbt/bip371-vectors.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { taprootTreeMerkleRoot } from "../psbt/taproot-tree.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const RUST = "rust-psbt-v2";
const WALLY = "libwally";

interface Direction {
  readonly id: "psbtv2-taproot-rust-to-libwally" | "psbtv2-taproot-libwally-to-rust";
  readonly first: typeof RUST | typeof WALLY;
  readonly second: typeof RUST | typeof WALLY;
}

const DIRECTIONS: readonly Direction[] = [
  {
    id: "psbtv2-taproot-rust-to-libwally",
    first: RUST,
    second: WALLY,
  },
  {
    id: "psbtv2-taproot-libwally-to-rust",
    first: WALLY,
    second: RUST,
  },
];

function taprootFingerprints(psbt: string): readonly string[] {
  const fingerprints: string[] = [];
  for (const map of parsePsbtDocument(psbt).maps) {
    const isTaprootType =
      map.location.kind === "input"
        ? (keyType: number) => keyType >= 0x13 && keyType <= 0x18
        : map.location.kind === "output"
          ? (keyType: number) => keyType >= 0x05 && keyType <= 0x07
          : () => false;
    const location =
      map.location.kind === "global" ? "global" : `${map.location.kind}:${map.location.index}`;
    for (const entry of map.entries) {
      if (!isTaprootType(entry.keyType)) continue;
      const valueCommitment =
        map.location.kind === "output" && entry.keyType === 0x06
          ? taprootTreeMerkleRoot(entry.value)
          : entry.valueSha256;
      fingerprints.push(
        [
          location,
          entry.keyType.toString(16).padStart(2, "0"),
          entry.completeKeySha256,
          valueCommitment,
        ].join(":"),
      );
    }
  }
  return fingerprints.sort();
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function acceptsTaprootTreeNormalization(
  strict: ScenarioAssertionEvidence,
  before: string,
  after: string,
): boolean {
  if (strict.passed) return true;
  return (
    (strict.failures?.length ?? 0) > 0 &&
    strict.failures?.every(
      ({ location, keyType }) => location.kind === "output" && keyType === 0x06,
    ) === true &&
    sameStrings(taprootFingerprints(before), taprootFingerprints(after))
  );
}

function semanticTaprootRoundtripPassed(
  context: ScenarioExecutionContext,
  name: string,
  before: string,
  after: string,
  adapter: string,
): boolean {
  return acceptsTaprootTreeNormalization(
    context.transitionEvidence("roundtrip", name, before, after, adapter),
    before,
    after,
  );
}

function aggregateAssertion(
  name: string,
  failures: readonly string[],
  summary: string,
): ScenarioAssertionEvidence {
  return {
    name,
    passed: failures.length === 0,
    summary: failures.length === 0 ? summary : `Failures: ${failures.join(", ")}`,
  };
}

function scenario(
  direction: Direction,
  vectors: readonly Bip371Vector[],
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: direction.id,
    title: `PSBTv2 Taproot ${direction.first} to ${direction.second}`,
    category: "psbtv2-taproot",
    summary:
      "Official BIP371 key-path and script-path vectors are converted to PSBTv2, handed through both native implementations, and reconstructed as PSBTv0.",
    requirements: [
      {
        adapter: RUST,
        operations: ["roundtrip"],
        roles: ["parser"],
        psbtVersions: [2],
        scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
        features: ["bip371-taproot-roundtrip"],
      },
      {
        adapter: WALLY,
        operations: ["convert", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0, 2],
        scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
        features: ["psbt-v0-v2-conversion", "bip371-taproot-roundtrip"],
      },
    ],
    async run(context) {
      const conversionFailures: string[] = [];
      const firstFailures: string[] = [];
      const secondFailures: string[] = [];
      const taprootFailures: string[] = [];
      const reconstructionFailures: string[] = [];

      for (const vector of vectors) {
        const sourceTaproot = taprootFingerprints(vector.base64);
        const convertedResponse = await context.request(WALLY, "convert", {
          psbt: vector.base64,
          targetVersion: 2,
        });
        if (convertedResponse.status !== "ok") {
          conversionFailures.push(vector.id);
          continue;
        }
        const converted = convertedResponse.output["psbt"];
        if (
          typeof converted !== "string" ||
          convertedResponse.output["sourceVersion"] !== 0 ||
          convertedResponse.output["psbtVersion"] !== 2
        ) {
          conversionFailures.push(vector.id);
          continue;
        }
        try {
          if (
            parsePsbtDocument(vector.base64).psbtVersion !== 0 ||
            parsePsbtDocument(converted).psbtVersion !== 2 ||
            !sameStrings(sourceTaproot, taprootFingerprints(converted))
          ) {
            conversionFailures.push(vector.id);
            continue;
          }
        } catch {
          conversionFailures.push(vector.id);
          continue;
        }

        const firstResponse = await context.request(direction.first, "roundtrip", {
          psbt: converted,
        });
        const first = firstResponse.status === "ok" ? firstResponse.output["psbt"] : undefined;
        if (
          typeof first !== "string" ||
          !semanticTaprootRoundtripPassed(
            context,
            `${vector.id}-${direction.first}-roundtrip`,
            converted,
            first,
            direction.first,
          )
        ) {
          firstFailures.push(vector.id);
          continue;
        }

        const secondResponse = await context.request(direction.second, "roundtrip", {
          psbt: first,
        });
        const second = secondResponse.status === "ok" ? secondResponse.output["psbt"] : undefined;
        if (
          typeof second !== "string" ||
          !semanticTaprootRoundtripPassed(
            context,
            `${vector.id}-${direction.second}-roundtrip`,
            first,
            second,
            direction.second,
          )
        ) {
          secondFailures.push(vector.id);
          continue;
        }

        if (!sameStrings(sourceTaproot, taprootFingerprints(second))) {
          taprootFailures.push(vector.id);
        }

        const reconstructedResponse = await context.request(WALLY, "convert", {
          psbt: second,
          targetVersion: 0,
        });
        if (reconstructedResponse.status !== "ok") {
          reconstructionFailures.push(vector.id);
          continue;
        }
        const reconstructed = reconstructedResponse.output["psbt"];
        if (
          typeof reconstructed !== "string" ||
          reconstructedResponse.output["sourceVersion"] !== 2 ||
          reconstructedResponse.output["psbtVersion"] !== 0
        ) {
          reconstructionFailures.push(vector.id);
          continue;
        }
        try {
          if (
            parsePsbtDocument(reconstructed).psbtVersion !== 0 ||
            !semanticTaprootRoundtripPassed(
              context,
              `${vector.id}-v0-reconstruction`,
              vector.base64,
              reconstructed,
              WALLY,
            ) ||
            !sameStrings(sourceTaproot, taprootFingerprints(reconstructed))
          ) {
            reconstructionFailures.push(vector.id);
          }
        } catch {
          reconstructionFailures.push(vector.id);
        }
      }

      const assertions = [
        aggregateAssertion(
          "bip371-vectors-converted-to-psbtv2",
          conversionFailures,
          `All ${vectors.length} valid BIP371 vectors converted to PSBTv2 with their Taproot fields intact`,
        ),
        aggregateAssertion(
          `${direction.first}-psbtv2-taproot-roundtrip`,
          firstFailures,
          `${direction.first} preserved every PSBTv2 Taproot vector`,
        ),
        aggregateAssertion(
          `${direction.second}-psbtv2-taproot-roundtrip`,
          secondFailures,
          `${direction.second} preserved every PSBTv2 Taproot vector`,
        ),
        aggregateAssertion(
          "psbtv2-taproot-fields-preserved",
          taprootFailures,
          "Taproot signatures, scripts, trees, keys, and derivations survived both native handoffs",
        ),
        aggregateAssertion(
          "bip371-v0-reconstruction",
          reconstructionFailures,
          `All ${vectors.length} vectors reconstructed as semantically equivalent PSBTv0 documents`,
        ),
      ];
      return {
        summary: assertions.every(({ passed }) => passed)
          ? `${direction.first} and ${direction.second} preserved all ${vectors.length} official Taproot vectors through PSBTv2.`
          : "The PSBTv2 Taproot handoff changed or rejected official BIP371 data.",
        assertions,
      };
    },
  };
}

export function createPsbtv2TaprootHandoffScenarios(
  vectors: readonly Bip371Vector[] = BIP371_VALID_VECTORS,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  if (vectors.length === 0) {
    throw new TypeError("PSBTv2 Taproot handoffs require at least one vector");
  }
  return DIRECTIONS.map((direction) => scenario(direction, vectors));
}
