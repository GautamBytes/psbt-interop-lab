import type { PsbtFixture } from "../core/fixtures.js";
import { readCompactSize } from "../psbt/compact-size.js";
import { parsePsbtDocument } from "../psbt/document.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";
import { exactFieldUnionEvidence } from "./interop-matrix.js";

const PARSERS = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"] as const;
const SIGNERS = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"] as const;
const PROPRIETARY_IDENTIFIER = Buffer.from("psbt-lab", "ascii");
const UNKNOWN_KEY_TYPE = 0x50;

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
    PROPRIETARY_IDENTIFIER,
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

function unknownEntry(kind: "global" | "input" | "output", index: number): Buffer {
  const kindByte = kind === "global" ? 0 : kind === "input" ? 1 : 2;
  const key = Buffer.from([UNKNOWN_KEY_TYPE, kindByte, index]);
  const value = Buffer.from(`psbt-lab-unknown:${kind}:${index}`, "utf8");
  return Buffer.concat([
    Buffer.from([key.byteLength]),
    key,
    Buffer.from([value.byteLength]),
    value,
  ]);
}

function expectedSubtype(kind: "global" | "input" | "output", index: number): number {
  return kind === "global" ? 1 : kind === "input" ? 0x10 + index : 0x80 + index;
}

function hasExpectedProprietaryEntry(
  entries: ReturnType<typeof parsePsbtDocument>["maps"][number]["entries"],
  kind: "global" | "input" | "output",
  index: number,
): boolean {
  const subtype = expectedSubtype(kind, index);
  return entries.some(
    (entry) =>
      entry.keyType === 0xfc &&
      entry.keyData.equals(
        Buffer.concat([
          Buffer.from([PROPRIETARY_IDENTIFIER.byteLength]),
          PROPRIETARY_IDENTIFIER,
          Buffer.from([subtype]),
        ]),
      ) &&
      entry.value.equals(Buffer.from(`psbt-lab:${kind}:${index}`, "utf8")),
  );
}

function hasExpectedUnknownEntry(
  entries: ReturnType<typeof parsePsbtDocument>["maps"][number]["entries"],
  kind: "global" | "input" | "output",
  index: number,
): boolean {
  const kindByte = kind === "global" ? 0 : kind === "input" ? 1 : 2;
  return entries.some(
    (entry) =>
      entry.keyType === UNKNOWN_KEY_TYPE &&
      entry.keyData.equals(Buffer.from([kindByte, index])) &&
      entry.value.equals(Buffer.from(`psbt-lab-unknown:${kind}:${index}`, "utf8")),
  );
}

function expectedMaps(fixture: PsbtFixture) {
  return [
    { kind: "global" as const, index: 0 },
    ...Array.from({ length: fixture.inputCount }, (_, index) => ({
      kind: "input" as const,
      index,
    })),
    ...Array.from({ length: fixture.outputCount }, (_, index) => ({
      kind: "output" as const,
      index,
    })),
  ];
}

export function verifyInjectedProprietaryFields(
  encoded: string,
  fixture: PsbtFixture,
): ScenarioAssertionEvidence {
  const document = parsePsbtDocument(encoded);
  const maps = expectedMaps(fixture);
  const missing = maps.filter(({ kind, index }) => {
    const map = document.maps.find((candidate) => {
      if (candidate.location.kind !== kind) return false;
      return candidate.location.kind === "global" || candidate.location.index === index;
    });
    return !map || !hasExpectedProprietaryEntry(map.entries, kind, index);
  });
  return {
    name: "valid-proprietary-field-in-every-map",
    passed: missing.length === 0,
    summary:
      missing.length === 0
        ? `Verified ${maps.length} BIP174 proprietary fields across every PSBT map.`
        : `Missing or invalid proprietary fields in: ${missing.map(({ kind, index }) => (kind === "global" ? kind : `${kind}[${index}]`)).join(", ")}`,
  };
}

export function verifyInjectedExtensionFields(
  encoded: string,
  fixture: PsbtFixture,
): ScenarioAssertionEvidence {
  const document = parsePsbtDocument(encoded);
  const maps = expectedMaps(fixture);
  const missing = maps.filter(({ kind, index }) => {
    const map = document.maps.find((candidate) => {
      if (candidate.location.kind !== kind) return false;
      return candidate.location.kind === "global" || candidate.location.index === index;
    });
    return (
      !map ||
      !hasExpectedProprietaryEntry(map.entries, kind, index) ||
      !hasExpectedUnknownEntry(map.entries, kind, index)
    );
  });
  return {
    name: "valid-extension-fields-in-every-map",
    passed: missing.length === 0,
    summary:
      missing.length === 0
        ? `Verified proprietary and unknown fields across all ${maps.length} PSBT maps.`
        : `Missing extension fields in: ${missing.map(({ kind, index }) => (kind === "global" ? kind : `${kind}[${index}]`)).join(", ")}`,
  };
}

function enrichFixture(fixture: PsbtFixture, includeUnknown: boolean): string {
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
    const subtype = expectedSubtype(kind, localIndex);
    chunks.push(
      bytes.subarray(offset, end.separator),
      proprietaryEntry(subtype, `psbt-lab:${kind}:${localIndex}`),
      ...(includeUnknown ? [unknownEntry(kind, localIndex)] : []),
      Buffer.from([0]),
    );
    offset = end.nextOffset;
  }
  if (offset !== bytes.byteLength) throw new Error("Fixture PSBT contains trailing map data");
  const encoded = Buffer.concat(chunks).toString("base64");
  parsePsbtDocument(encoded);
  return encoded;
}

export function enrichPsbtWithProprietaryFields(fixture: PsbtFixture): string {
  return enrichFixture(fixture, false);
}

export function enrichPsbtWithExtensionFields(fixture: PsbtFixture): string {
  return enrichFixture(fixture, true);
}

export function createMetadataPreservationScenario(
  fixture: PsbtFixture,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "proprietary-metadata-preservation",
    title: "Unknown and proprietary field preservation",
    category: "metadata-preservation",
    summary: "Unknown and proprietary fields must survive parsing, signing, and combining.",
    requirements: [
      ...PARSERS.map((adapter) => ({
        adapter,
        operations: ["roundtrip"] as const,
        roles: ["parser"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2wsh"] as const,
      })),
      ...SIGNERS.map((adapter) => ({
        adapter,
        operations: ["sign"] as const,
        roles: ["signer"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2wsh"] as const,
        features: ["fixture-commitment-sha256"] as const,
      })),
      {
        adapter: "bitcoinjs-lib",
        operations: ["combine"] as const,
        roles: ["combiner"] as const,
        psbtVersions: [0] as const,
        scriptTypes: ["p2wsh"] as const,
      },
    ],
    async run(context) {
      if (fixture.id !== "p2wsh-2-of-3" || fixture.inputCount !== 1) {
        throw new Error("Metadata signing and combining requires the p2wsh-2-of-3 fixture");
      }
      const assertions: ScenarioAssertionEvidence[] = [];
      const enriched = enrichPsbtWithExtensionFields(fixture);
      assertions.push(verifyInjectedExtensionFields(enriched, fixture));
      await context.checkpoint("proprietary-metadata-preservation", "metadata-enriched", enriched);
      let current = enriched;
      for (const adapter of PARSERS) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition(
            "roundtrip",
            `${adapter}-preserved-extension-fields`,
            before,
            current,
          ),
        );
      }
      const signed = new Map<string, string>();
      for (const adapter of SIGNERS) {
        const response = await context.request(adapter, "sign", {
          psbt: current,
          network: "regtest",
          fixtureId: fixture.id,
        });
        const signedPsbt = context.outputString(response, "psbt", "sign");
        assertions.push(
          context.requireTransition(
            "sign",
            `${adapter}-preserved-metadata-while-signing`,
            current,
            signedPsbt,
          ),
        );
        assertions.push(
          context.requireAddedInputField(
            `${adapter}-added-signature-with-metadata`,
            current,
            signedPsbt,
            [0x02],
          ),
        );
        signed.set(adapter, signedPsbt);
      }
      const rustSigned = signed.get("rust-bitcoin");
      const bitcoinjsSigned = signed.get("bitcoinjs-lib");
      if (!rustSigned || !bitcoinjsSigned)
        throw new Error("Metadata signer outputs are incomplete");
      const sources = [rustSigned, bitcoinjsSigned];
      const combineResponse = await context.request("bitcoinjs-lib", "combine", { psbts: sources });
      const combined = context.outputString(combineResponse, "psbt", "combine");
      for (const [index, source] of sources.entries()) {
        assertions.push(
          context.requireTransition(
            "combine",
            `metadata-combined-copy-${index + 1}`,
            source,
            combined,
          ),
        );
      }
      assertions.push(exactFieldUnionEvidence(sources, combined));
      assertions.push({
        ...verifyInjectedExtensionFields(combined, fixture),
        name: "combined-preserved-extension-fields",
      });
      await context.checkpoint("proprietary-metadata-preservation", "metadata-combined", combined);
      const coreFinalizedPsbt = await context.finalizePsbtWithCore(combined);
      const corePsbtAvailable =
        coreFinalizedPsbt.complete && typeof coreFinalizedPsbt.psbt === "string";
      assertions.push({ name: "core-returned-finalized-psbt", passed: corePsbtAvailable });
      if (!corePsbtAvailable || !coreFinalizedPsbt.psbt) {
        return {
          summary: "Core did not return a complete finalized PSBT for metadata verification.",
          assertions,
          policyAccepted: false,
        };
      }
      assertions.push(
        context.requireTransition(
          "finalize",
          "core-preserved-metadata-during-finalization",
          combined,
          coreFinalizedPsbt.psbt,
        ),
        {
          ...verifyInjectedExtensionFields(coreFinalizedPsbt.psbt, fixture),
          name: "core-finalized-psbt-preserved-extension-fields",
        },
      );
      await context.checkpoint(
        "proprietary-metadata-preservation",
        "core-finalized-metadata",
        coreFinalizedPsbt.psbt,
      );
      const finalized = await context.finalizeWithCore(coreFinalizedPsbt.psbt);
      const policy = await context.policyCheck(finalized);
      assertions.push(
        {
          name: "core-finalized",
          passed: finalized.complete && typeof finalized.hex === "string",
        },
        { name: "core-policy-accepted", passed: policy.allowed },
      );
      return {
        summary: policy.allowed
          ? "All parsers, signers, the combiner, and Core finalization preserved extension fields before Core accepted the transaction."
          : "The metadata-rich handoff did not produce a policy-accepted transaction.",
        assertions,
        policyAccepted: policy.allowed,
        ...(policy.txid ? { transactionId: policy.txid } : {}),
      };
    },
  };
}
