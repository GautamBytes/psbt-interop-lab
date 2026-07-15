import type { PsbtFixture } from "../core/fixtures.js";
import { readCompactSize } from "../psbt/compact-size.js";
import { parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const PARSERS = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"] as const;

function mapEnd(bytes: Buffer, mapOffset: number): { separator: number; nextOffset: number } {
  let offset = mapOffset;
  while (offset < bytes.byteLength) {
    const keyLength = readCompactSize(bytes, offset);
    if (keyLength.value === 0) {
      return { separator: offset, nextOffset: keyLength.nextOffset };
    }
    const valueLengthOffset = keyLength.nextOffset + keyLength.value;
    if (valueLengthOffset > bytes.byteLength) throw new Error("Fixture PSBT map key is truncated");
    const valueLength = readCompactSize(bytes, valueLengthOffset);
    offset = valueLength.nextOffset + valueLength.value;
    if (offset > bytes.byteLength) throw new Error("Fixture PSBT map value is truncated");
  }
  throw new Error("Fixture PSBT map lacks a separator");
}

function proprietaryEntry(subtype: number, value: string): Buffer {
  if (!Number.isSafeInteger(subtype) || subtype < 0 || subtype > 0xff) {
    throw new TypeError("Proprietary subtype must be one byte");
  }
  const key = Buffer.concat([
    Buffer.from([0xfc, 0x08]),
    Buffer.from("psbt-lab", "ascii"),
    Buffer.from([subtype]),
  ]);
  const encodedValue = Buffer.from(value, "utf8");
  if (key.byteLength >= 0xfd || encodedValue.byteLength >= 0xfd) {
    throw new TypeError("Proprietary fixture entry exceeds its one-byte length encoding");
  }
  return Buffer.concat([
    Buffer.from([key.byteLength]),
    key,
    Buffer.from([encodedValue.byteLength]),
    encodedValue,
  ]);
}

export function enrichPsbtWithProprietaryFields(fixture: PsbtFixture): string {
  const document = parsePsbtDocument(fixture.initialPsbt);
  if (
    document.psbtVersion !== 0 ||
    document.inputCount !== fixture.inputCount ||
    document.outputCount !== fixture.outputCount
  ) {
    throw new Error("Fixture metadata does not match its PSBT structure");
  }
  const bytes = Buffer.from(fixture.initialPsbt, "base64");
  const maps = 1 + fixture.inputCount + fixture.outputCount;
  const chunks: Buffer[] = [bytes.subarray(0, 5)];
  let offset = 5;
  for (let mapIndex = 0; mapIndex < maps; mapIndex += 1) {
    const end = mapEnd(bytes, offset);
    const kind = mapIndex === 0 ? "global" : mapIndex <= fixture.inputCount ? "input" : "output";
    const localIndex =
      kind === "global" ? 0 : kind === "input" ? mapIndex - 1 : mapIndex - fixture.inputCount - 1;
    const subtype =
      kind === "global" ? 1 : kind === "input" ? 0x10 + localIndex : 0x80 + localIndex;
    chunks.push(
      bytes.subarray(offset, end.separator),
      proprietaryEntry(subtype, `psbt-lab:${kind}:${localIndex}`),
      Buffer.from([0]),
    );
    offset = end.nextOffset;
  }
  if (offset !== bytes.byteLength) throw new Error("Fixture PSBT contains trailing map data");
  const encoded = Buffer.concat(chunks).toString("base64");
  parsePsbtDocument(encoded);
  return encoded;
}

export function createMetadataPreservationScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "proprietary-metadata-preservation",
    title: "Unknown and proprietary field preservation",
    category: "metadata-preservation",
    summary:
      "Every implementation must preserve extension fields in global, input, and output maps.",
    requirements: PARSERS.map((adapter) => ({
      adapter,
      operations: ["roundtrip"] as const,
      roles: ["parser"] as const,
      psbtVersions: [0] as const,
      scriptTypes: ["p2wsh"] as const,
    })),
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      const enriched = enrichPsbtWithProprietaryFields(fixture);
      await context.checkpoint("proprietary-metadata-preservation", "metadata-enriched", enriched);
      let current = enriched;
      for (const adapter of PARSERS) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition(
            "roundtrip",
            `${adapter}-preserved-proprietary-fields`,
            before,
            current,
          ),
        );
      }
      await context.checkpoint("proprietary-metadata-preservation", "all-roundtripped", current);
      return {
        summary:
          "rust-bitcoin, btcsuite, bitcoinjs-lib, and BDK preserved all injected proprietary fields.",
        assertions,
      };
    },
  };
}
