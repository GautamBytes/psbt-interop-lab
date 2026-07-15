import type { PsbtFixture } from "../core/fixtures.js";
import { readCompactSize } from "../psbt/compact-size.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const PARSERS = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"] as const;

// Published BIP370 required-fields-only PSBTv2 vector: https://bips.dev/370/
const BIP370_PSBT_V2 =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";

interface InvalidPsbtCase {
  readonly id: string;
  readonly psbt: string;
  readonly description: string;
}

function duplicateFirstGlobalEntry(encoded: string): string {
  const bytes = Buffer.from(encoded, "base64");
  const entryStart = 5;
  const keyLength = readCompactSize(bytes, entryStart);
  const valueLengthOffset = keyLength.nextOffset + keyLength.value;
  const valueLength = readCompactSize(bytes, valueLengthOffset);
  const entryEnd = valueLength.nextOffset + valueLength.value;
  if (entryEnd >= bytes.byteLength) {
    throw new Error("Fixture PSBT has no complete global entry to duplicate");
  }
  return Buffer.concat([
    bytes.subarray(0, entryEnd),
    bytes.subarray(entryStart, entryEnd),
    bytes.subarray(entryEnd),
  ]).toString("base64");
}

export function invalidPsbtCases(fixture: PsbtFixture): readonly InvalidPsbtCase[] {
  const bytes = Buffer.from(fixture.initialPsbt, "base64");
  if (bytes.byteLength < 8) throw new Error("Fixture PSBT is unexpectedly short");
  const wrongMagic = Buffer.from(bytes);
  wrongMagic[0] = (wrongMagic[0] as number) ^ 0xff;
  return [
    {
      id: "invalid-base64",
      psbt: "***not-canonical-base64***",
      description: "non-base64 input",
    },
    {
      id: "wrong-magic",
      psbt: wrongMagic.toString("base64"),
      description: "wrong PSBT magic bytes",
    },
    {
      id: "truncated-map",
      psbt: bytes.subarray(0, -1).toString("base64"),
      description: "truncated final map",
    },
    {
      id: "duplicate-global-key",
      psbt: duplicateFirstGlobalEntry(fixture.initialPsbt),
      description: "duplicate global map key",
    },
    {
      id: "unsupported-psbt-v2",
      psbt: BIP370_PSBT_V2,
      description: "valid but undeclared PSBTv2 input",
    },
  ];
}

export function createInvalidInputScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "invalid-and-unsupported-inputs",
    title: "Invalid and unsupported PSBT rejection matrix",
    category: "invalid-inputs",
    summary: "Every parser must reject malformed and undeclared PSBT formats without crashing.",
    requirements: PARSERS.map((adapter) => ({
      adapter,
      operations: ["roundtrip"] as const,
      roles: ["parser"] as const,
      psbtVersions: [0] as const,
      scriptTypes: ["p2wsh"] as const,
    })),
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      for (const testCase of invalidPsbtCases(fixture)) {
        for (const adapter of PARSERS) {
          const response = await context.request(adapter, "roundtrip", { psbt: testCase.psbt });
          const rejectedCleanly =
            response.status === "rejected" || response.status === "unsupported";
          assertions.push({
            name: `${adapter}-${testCase.id}`,
            passed: rejectedCleanly,
            summary: rejectedCleanly
              ? `${adapter} rejected ${testCase.description} as ${response.status}`
              : `${adapter} returned ${response.status} for ${testCase.description}`,
          });
        }
      }
      const passed = assertions.every((assertion) => assertion.passed);
      return {
        summary: passed
          ? "All four implementations rejected five malformed or undeclared PSBT cases cleanly."
          : "At least one implementation accepted, crashed on, or timed out for invalid PSBT input.",
        assertions,
      };
    },
  };
}
