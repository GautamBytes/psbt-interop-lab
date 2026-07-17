import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { createBip370VectorScenario } from "../../src/scenarios/bip370.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const implementation = {
  name: "rust-psbt-v2",
  version: "0.1.0",
  sourceRevision: "psbt-v2-0.3.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

describe("BIP370 vector scenario", () => {
  test("runs every official valid and invalid vector through a native adapter", async () => {
    const requests: AdapterRequest[] = [];
    const adapter = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        requests.push(request);
        const encoded = request.payload["psbt"];
        try {
          if (typeof encoded !== "string") throw new Error("missing psbt");
          parsePsbtDocument(encoded);
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
        psbtVersions: [2],
        scriptTypes: [],
      },
    };

    const [result] = await runScenarioCatalog(
      [createBip370VectorScenario(implementation.name)],
      context,
      new Map([[implementation.name, negotiated]]),
    );

    expect(result).toMatchObject({
      id: "bip370-official-vectors-rust-psbt-v2",
      outcome: "passed",
      assertions: [
        { name: "bip370-valid-vectors", passed: true },
        { name: "bip370-invalid-vectors", passed: true },
      ],
    });
    expect(requests.filter(({ operation }) => operation === "native-parse")).toHaveLength(35);
    expect(requests.filter(({ operation }) => operation === "roundtrip")).toHaveLength(14);
  });
});
