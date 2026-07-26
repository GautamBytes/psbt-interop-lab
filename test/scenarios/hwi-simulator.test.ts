import { describe, expect, test } from "vitest";
import { FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import {
  createHwiSimulatorScenario,
  HWI_DERIVATION_PATH_HEX,
  HWI_DEVICE_FINGERPRINT,
  initializeHwiKeyOrigin,
} from "../../src/scenarios/hwi-simulator.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";

const fixture: PsbtFixture = {
  id: "p2wpkh",
  initialPsbt: MINIMAL_PSBT,
  outpoints: [],
  inputCount: 1,
  outputCount: 1,
  feeSats: 1_000,
  unsignedTxSha256: `sha256:${"a".repeat(64)}`,
  scriptTypes: ["p2wpkh"],
  inputDescriptors: [],
  outputDescriptor: "",
  psbtVersion: 0,
  transactionId: "b".repeat(64),
  psbtSha256: "c".repeat(64),
};

describe("HWI simulator proof scenario", () => {
  test("adds the device fingerprint and fixed regtest BIP84 derivation", () => {
    const initialized = initializeHwiKeyOrigin(MINIMAL_PSBT);
    const input = parsePsbtDocument(initialized).maps.find(
      (map) => map.location.kind === "input" && map.location.index === 0,
    );
    const origin = input?.entries.find(
      (entry) =>
        entry.keyType === 0x06 && entry.keyData.toString("hex") === FIXTURE_PUBLIC_KEYS.scalar1,
    );

    expect(origin?.value.toString("hex")).toBe(
      `${HWI_DEVICE_FINGERPRINT}${HWI_DERIVATION_PATH_HEX}`,
    );
  });

  test("requires the process boundary and simulated confirmation features", () => {
    const scenario = createHwiSimulatorScenario(fixture);

    expect(scenario).toMatchObject({
      id: "hwi-simulator-p2wpkh",
      category: "hardware-signing",
    });
    expect(scenario.requirements).toEqual([
      {
        adapter: "hwi-simulator",
        operations: ["roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
        features: [
          "fixture-commitment-sha256",
          "hwi-json-process-v1",
          "hwi-simulator-v1",
          "simulated-user-confirmation-v1",
          "network-free",
        ],
      },
    ]);
  });
});
