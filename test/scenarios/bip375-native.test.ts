import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  JsonValue,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP375_INVALID_VECTORS, BIP375_VALID_VECTORS } from "../../src/psbt/bip375-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { createBip375NativeParserScenario } from "../../src/scenarios/bip375.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const implementation = {
  name: "rust-psbt-v2",
  version: "0.1.0",
  sourceRevision: "psbt-v2-0.3.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

function silentPaymentFieldCounts(encoded: string): Record<string, JsonValue> {
  const counts = {
    globalEcdhShares: 0,
    globalDleqProofs: 0,
    inputEcdhShares: 0,
    inputDleqProofs: 0,
    outputsWithInfo: 0,
    outputsWithLabel: 0,
  };
  for (const map of parsePsbtDocument(encoded).maps) {
    for (const entry of map.entries) {
      if (map.location.kind === "global" && entry.keyType === 0x07) counts.globalEcdhShares += 1;
      if (map.location.kind === "global" && entry.keyType === 0x08) counts.globalDleqProofs += 1;
      if (map.location.kind === "input" && entry.keyType === 0x1d) counts.inputEcdhShares += 1;
      if (map.location.kind === "input" && entry.keyType === 0x1e) counts.inputDleqProofs += 1;
      if (map.location.kind === "output" && entry.keyType === 0x09) counts.outputsWithInfo += 1;
      if (map.location.kind === "output" && entry.keyType === 0x0a) counts.outputsWithLabel += 1;
    }
  }
  return counts;
}

async function executeScenario(
  options: { wrongCountsFor?: string; crashFor?: string; materializeEmptyScriptFor?: string } = {},
) {
  const requests: AdapterRequest[] = [];
  const invalidByBase64 = new Map<string, (typeof BIP375_INVALID_VECTORS)[number]>(
    BIP375_INVALID_VECTORS.map((vector) => [vector.base64, vector]),
  );
  const adapter = {
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      requests.push(request);
      const encoded = request.payload["psbt"];
      if (typeof encoded !== "string") throw new TypeError("missing PSBT");
      const invalid = invalidByBase64.get(encoded);
      if (options.crashFor !== undefined && options.crashFor === invalid?.id) {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "crashed",
          implementation,
          error: { class: "adapter.crashed", message: "native parser crashed" },
        };
      }
      if (
        request.operation === "native-parse" &&
        invalid !== undefined &&
        ["invalid-01", "invalid-02", "invalid-03", "invalid-04", "invalid-06"].includes(invalid.id)
      ) {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: { class: "psbt.native_parse_failed", message: "native parser rejected PSBT" },
        };
      }
      let counts: Record<string, JsonValue>;
      try {
        counts = silentPaymentFieldCounts(encoded);
      } catch {
        if (invalid?.id === "invalid-05") {
          counts = {
            globalEcdhShares: 0,
            globalDleqProofs: 0,
            inputEcdhShares: 0,
            inputDleqProofs: 0,
            outputsWithInfo: 1,
            outputsWithLabel: 0,
          };
        } else {
          return {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "rejected",
            implementation,
            error: { class: "psbt.native_parse_failed", message: "native parser rejected PSBT" },
          };
        }
      }
      if (options.wrongCountsFor === BIP375_VALID_VECTORS.find((v) => v.base64 === encoded)?.id) {
        counts["outputsWithInfo"] = Number(counts["outputsWithInfo"]) + 1;
      }
      return {
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "ok",
        implementation,
        output:
          request.operation === "roundtrip"
            ? {
                psbt:
                  options.materializeEmptyScriptFor ===
                  BIP375_VALID_VECTORS.find((v) => v.base64 === encoded)?.id
                    ? applyPsbtMutations(encoded, [
                        {
                          kind: "set-entry",
                          location: { kind: "output", index: 0 },
                          keyType: 0x04,
                          valueHex: "",
                        },
                      ])
                    : encoded,
                byteIdentical: options.materializeEmptyScriptFor === undefined,
                silentPaymentFields: counts,
              }
            : { nativeParser: implementation.name, silentPaymentFields: counts },
      };
    }),
  };
  const context = new ScenarioExecutionContext({
    rpc: { call: vi.fn() } as never,
    artifacts: {
      checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
        scenario,
        stage,
        psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
        factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
        facts: extractWireFacts(psbt),
      })),
    },
    adapters: new Map([[implementation.name, adapter]]),
    adapterTimeoutMs: 1_000,
  });
  const negotiated: NegotiatedAdapter = {
    implementation,
    capabilities: {
      operations: ["hello", "native-parse", "roundtrip"],
      roles: ["parser"],
      psbtVersions: [2],
      scriptTypes: [],
      features: ["bip375-silent-payments"],
    },
  };
  const [result] = await runScenarioCatalog(
    [createBip375NativeParserScenario(implementation.name)],
    context,
    new Map([[implementation.name, negotiated]]),
  );
  return { requests, result };
}

describe("BIP375 native parser scenario", () => {
  test("classifies all official vectors and roundtrips every valid vector", async () => {
    const { requests, result } = await executeScenario();

    expect(result).toMatchObject({
      id: "bip375-official-vectors-rust-psbt-v2",
      outcome: "passed",
      assertions: [
        { name: "bip375-native-valid-vectors", passed: true },
        { name: "bip375-native-structural-rejections", passed: true },
        { name: "bip375-native-semantic-classification", passed: true },
      ],
    });
    expect(requests.filter(({ operation }) => operation === "native-parse")).toHaveLength(41);
    expect(requests.filter(({ operation }) => operation === "roundtrip")).toHaveLength(19);
    expect(result?.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "bip375-cross-field-invalid-accepted",
          ruleId: "bip375.invalid-vectors.rejected",
        }),
      ]),
    );
  });

  test("fails when the native typed field view disagrees with the PSBT maps", async () => {
    const { result } = await executeScenario({ wrongCountsFor: "valid-01" });
    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "bip375-native-valid-vectors", passed: false }),
      ]),
    );
  });

  test("records explicit empty output-script materialization as a compatibility finding", async () => {
    const { result } = await executeScenario({ materializeEmptyScriptFor: "valid-16" });

    expect(result).toMatchObject({ outcome: "passed" });
    expect(result?.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "bip375-empty-output-script-materialized",
          ruleId: "lab.fields.no-unexpected-addition",
        }),
      ]),
    );
  });

  test("fails when semantic-invalid input crashes instead of producing a bounded classification", async () => {
    const { result } = await executeScenario({ crashFor: "invalid-07" });
    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "bip375-native-semantic-classification",
          passed: false,
        }),
      ]),
    );
  });
});
