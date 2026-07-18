import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP370_VALID_VECTORS } from "../../src/psbt/bip370-vectors.js";
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

interface ValidVectorOverride {
  readonly id: string;
  readonly status: "rejected" | "crashed";
  readonly errorClass: string;
  readonly implementationName?: string;
}

async function executeScenario(
  override?: ValidVectorOverride,
  allowedRejections: readonly string[] = [],
) {
  const requests: AdapterRequest[] = [];
  const validIds = new Map<string, string>(
    BIP370_VALID_VECTORS.map((vector) => [vector.base64, vector.id]),
  );
  const adapter = {
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      requests.push(request);
      const encoded = request.payload["psbt"];
      const validId = typeof encoded === "string" ? validIds.get(encoded) : undefined;
      if (
        request.operation === "native-parse" &&
        override !== undefined &&
        override.id === validId
      ) {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: override.status,
          implementation: {
            ...implementation,
            name: override.implementationName ?? implementation.name,
          },
          error: {
            class: override.errorClass,
            message: "Native parser rejected the vector",
          },
        };
      }
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
    [createBip370VectorScenario(implementation.name, implementation.name, allowedRejections)],
    context,
    new Map([[implementation.name, negotiated]]),
  );
  return { requests, result };
}

describe("BIP370 vector scenario", () => {
  test("runs every official valid and invalid vector through a native adapter", async () => {
    const { requests, result } = await executeScenario();

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

  test("records only the exact allowlisted native rejection as a compatibility finding", async () => {
    const { result } = await executeScenario(
      {
        id: "valid-08",
        status: "rejected",
        errorClass: "psbt.native_parse_failed",
      },
      ["valid-08"],
    );

    expect(result).toMatchObject({ outcome: "passed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "bip370-valid-vectors", passed: true }),
      ]),
    );
    expect(result?.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "bip370-valid-tx-modifiable-flags-rejected" }),
      ]),
    );
  });

  test.each([
    ["adapter crash", "crashed", "psbt.native_parse_failed", implementation.name],
    ["wrong rejection class", "rejected", "adapter.unexpected_failure", implementation.name],
    ["wrong parser identity", "rejected", "psbt.native_parse_failed", "different-parser"],
  ] as const)("does not allowlist %s", async (_label, status, errorClass, implementationName) => {
    const { result } = await executeScenario(
      { id: "valid-08", status, errorClass, implementationName },
      ["valid-08"],
    );

    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "bip370-valid-vectors", passed: false }),
      ]),
    );
    expect(result?.findings).toBeUndefined();
  });
});
