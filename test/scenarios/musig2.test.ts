import { describe, expect, test } from "vitest";
import {
  FIXTURE_PUBLIC_KEYS,
  MUSIG2_AGGREGATE_PUBLIC_KEY,
} from "../../src/core/fixture-profiles.js";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import {
  createMusig2Scenario,
  initializeBip373ParticipantFields,
  MUSIG2_SIGNER_ONE,
  MUSIG2_SIGNER_TWO,
} from "../../src/scenarios/musig2.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";

const fixture = {
  id: "p2tr-musig2",
  initialPsbt: MINIMAL_PSBT,
  unsignedTxSha256: `sha256:${"a".repeat(64)}`,
} as PsbtFixture;

describe("MuSig2 proof scenario", () => {
  test("adds the ordered BIP373 participant set under the aggregate key", () => {
    const initialized = initializeBip373ParticipantFields(MINIMAL_PSBT);
    const input = parsePsbtDocument(initialized).maps.find(
      (map) => map.location.kind === "input" && map.location.index === 0,
    );
    const participantField = input?.entries.find((entry) => entry.keyType === 0x1a);

    expect(participantField?.keyData.toString("hex")).toBe(MUSIG2_AGGREGATE_PUBLIC_KEY);
    expect(participantField?.value.toString("hex")).toBe(
      `${FIXTURE_PUBLIC_KEYS.scalar1}${FIXTURE_PUBLIC_KEYS.scalar2}`,
    );
  });

  test("requires both isolated signers and independent preservation adapters", () => {
    const scenario = createMusig2Scenario(fixture);

    expect(scenario).toMatchObject({
      id: "bip373-musig2-keypath",
      category: "musig2",
    });
    expect(scenario.requirements.map(({ adapter }) => adapter)).toEqual([
      "rust-bitcoin",
      "bitcoinjs-lib",
      MUSIG2_SIGNER_ONE,
      MUSIG2_SIGNER_TWO,
    ]);
    for (const signer of scenario.requirements.slice(2)) {
      expect(signer.operations).toEqual([
        "roundtrip",
        "musig2-nonce",
        "musig2-partial-sign",
        "musig2-aggregate",
      ]);
      expect(signer.features).toContain("bip327-csprng-nonce-v1");
    }
  });
});
