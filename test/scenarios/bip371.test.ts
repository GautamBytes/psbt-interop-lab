import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP371_INVALID_VECTORS } from "../../src/psbt/bip371-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { createBip371VectorScenario } from "../../src/scenarios/bip371.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const implementation = {
  name: "rust-bitcoin",
  version: "0.1.0",
  sourceRevision: "bitcoin-crate-0.32.102",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

async function executeScenario(acceptInvalidId?: string) {
  const requests: AdapterRequest[] = [];
  const invalidIds = new Map<string, string>(
    BIP371_INVALID_VECTORS.map(({ base64, id }) => [base64, id]),
  );
  const adapter = {
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      requests.push(request);
      const encoded = request.payload["psbt"];
      const invalidId = typeof encoded === "string" ? invalidIds.get(encoded) : undefined;
      try {
        if (typeof encoded !== "string") throw new Error("missing psbt");
        if (invalidId !== acceptInvalidId) parsePsbtDocument(encoded);
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "ok",
          implementation,
          output:
            request.operation === "roundtrip"
              ? { psbt: encoded, byteIdentical: true }
              : { nativeParser: implementation.name },
        };
      } catch {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: {
            class: "psbt.native_parse_failed",
            message: "Native parser rejected the vector",
          },
        };
      }
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
      psbtVersions: [0],
      scriptTypes: ["p2tr-keypath", "p2tr-scriptpath"],
      operationScriptTypes: {
        roundtrip: ["p2tr-keypath", "p2tr-scriptpath"],
      },
    },
  };
  const [result] = await runScenarioCatalog(
    [createBip371VectorScenario(implementation.name)],
    context,
    new Map([[implementation.name, negotiated]]),
  );
  return { requests, result };
}

describe("BIP371 vector scenario", () => {
  test("runs the complete official corpus through the native adapter", async () => {
    const { requests, result } = await executeScenario();

    expect(result).toMatchObject({
      id: "bip371-official-vectors-rust-bitcoin",
      outcome: "passed",
      assertions: [
        { name: "bip371-valid-vectors", passed: true },
        { name: "bip371-invalid-vectors", passed: true },
      ],
    });
    expect(requests.filter(({ operation }) => operation === "native-parse")).toHaveLength(17);
    expect(requests.filter(({ operation }) => operation === "roundtrip")).toHaveLength(6);
  });

  test("fails when the native parser accepts an invalid vector", async () => {
    const { result } = await executeScenario("invalid-11");

    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "bip371-invalid-vectors",
          passed: false,
        }),
      ]),
    );
  });
});
