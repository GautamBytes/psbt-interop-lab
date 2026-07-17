import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";
import { createScriptProfileRoundtripScenario } from "../../src/scenarios/script-profile-roundtrip.js";

const encoded = Buffer.concat([
  Buffer.from("70736274ff", "hex"),
  Buffer.from("01003d0200000001", "hex"),
  Buffer.alloc(32, 1),
  Buffer.from("0000000000fcffffff01102700000000000001512a000000000000", "hex"),
]).toString("base64");

function fixture(id: string, scriptType: "p2sh-p2wpkh" | "p2tr-scriptpath"): PsbtFixture {
  return {
    id,
    initialPsbt: encoded,
    outpoints: [],
    inputCount: 1,
    outputCount: 1,
    feeSats: 1_000,
    scriptTypes: [scriptType],
    inputDescriptors: ["fixture"],
    outputDescriptor: "fixture",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: extractWireFacts(encoded).sha256,
    unsignedTxSha256: `sha256:${"b".repeat(64)}`,
  };
}

describe("script profile roundtrip scenario", () => {
  test.each([
    ["nested-segwit-roundtrip-matrix", "p2sh-p2wpkh"],
    ["taproot-scriptpath-roundtrip-matrix", "p2tr-scriptpath"],
  ] as const)("preserves the %s fixture through every selected adapter", async (id, scriptType) => {
    const adapterNames = ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdk-wallet-current"];
    const requests: string[] = [];
    const adapters = new Map(
      adapterNames.map((name) => [
        name,
        {
          request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
            requests.push(name);
            const psbt = request.payload["psbt"];
            if (typeof psbt !== "string") throw new TypeError("Test adapter requires a PSBT");
            return {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status: "ok",
              implementation: {
                name,
                version: "test",
                sourceRevision: "test",
                artifactDigest: `sha256:${"c".repeat(64)}`,
              },
              output: { psbt },
            };
          }),
        },
      ]),
    );
    const definition = createScriptProfileRoundtripScenario(fixture(id, scriptType), {
      id,
      title: id,
      adapters: adapterNames,
    });
    const negotiated = new Map(
      adapterNames.map((name) => [
        name,
        {
          implementation: {
            name,
            version: "test",
            sourceRevision: "test",
            artifactDigest: `sha256:${"c".repeat(64)}`,
          },
          capabilities: {
            operations: ["hello" as const, "roundtrip" as const],
            roles: ["parser" as const],
            psbtVersions: [0 as const],
            scriptTypes: [scriptType],
            operationScriptTypes: { roundtrip: [scriptType] },
            features: [],
          },
        },
      ]),
    );
    const context = new ScenarioExecutionContext({
      rpc: {} as never,
      artifacts: {
        checkpoint: vi.fn(async (scenarioId: string, stage: string, psbt: string) => ({
          scenario: scenarioId,
          stage,
          psbtPath: "fixture.psbt",
          factsPath: "fixture.json",
          facts: extractWireFacts(psbt),
        })),
      },
      adapters,
      adapterTimeoutMs: 1_000,
    });

    const [result] = await runScenarioCatalog([definition], context, negotiated);

    expect(result).toMatchObject({ id, outcome: "passed" });
    expect(requests).toEqual(adapterNames);
    expect(definition.requirements).toHaveLength(adapterNames.length);
    expect(
      definition.requirements.every(
        (requirement) => requirement.scriptTypes?.includes(scriptType) === true,
      ),
    ).toBe(true);
  });
});
