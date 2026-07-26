import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type { UserScenarioSpec } from "../../src/custom/manifest.js";
import { compileUserScenarios } from "../../src/custom/scenarios.js";
import type {
  AdapterImplementation,
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const magic = Buffer.from("70736274ff", "hex");
const publicKey = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([value.length]), value]);
}

function psbt(inputEntries: readonly Buffer[] = []): string {
  const transaction = Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 1),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fcffffff", "hex"),
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("2a000000", "hex"),
  ]);
  return Buffer.concat([
    magic,
    map(entry(0x00, transaction)),
    map(...inputEntries),
    map(),
  ]).toString("base64");
}

const signature = Buffer.concat([
  Buffer.from("30440220", "hex"),
  Buffer.alloc(32, 1),
  Buffer.from("0220", "hex"),
  Buffer.alloc(32, 2),
  Buffer.from([1]),
]);

function customFixture(): PsbtFixture {
  const initialPsbt = psbt();
  return {
    id: "merchant-refund",
    initialPsbt,
    outpoints: [],
    inputCount: 1,
    outputCount: 1,
    feeSats: 1_000,
    scriptTypes: ["p2wpkh"],
    inputDescriptors: ["wpkh(...)#fixture"],
    outputDescriptor: "wpkh(...)#fixture",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: extractWireFacts(initialPsbt).sha256,
    unsignedTxSha256: `sha256:${"b".repeat(64)}`,
    specSha256: `sha256:${"c".repeat(64)}`,
  };
}

function scenario(): UserScenarioSpec {
  return {
    id: "merchant-refund-handoff",
    title: "Merchant refund handoff",
    fixture: "merchant-refund",
    steps: [
      { id: "parsed", adapter: "rust-bitcoin", operation: "roundtrip", input: "fixture" },
      { id: "signed", adapter: "rust-bitcoin", operation: "sign", input: "parsed" },
      { id: "finalized", operation: "core-finalize", input: "signed" },
      { id: "policy", operation: "core-policy-check", input: "finalized" },
    ],
  };
}

describe("custom scenario compiler", () => {
  test("infers capabilities and executes a checked signing pipeline", async () => {
    const fixture = customFixture();
    const [definition] = compileUserScenarios([scenario()], new Map([[fixture.id, fixture]]));
    expect(definition?.requirements).toEqual([
      {
        adapter: "rust-bitcoin",
        operations: ["roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
        features: ["fixture-commitment-sha256", "user-fixture-template-v1"],
      },
    ]);

    const implementation: AdapterImplementation = {
      name: "rust-bitcoin",
      version: "0.1.0",
      sourceRevision: "bitcoin-crate-0.32.102",
      artifactDigest: `sha256:${"d".repeat(64)}`,
    };
    const requests: AdapterRequest[] = [];
    const adapter = {
      request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
        requests.push(request);
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "ok",
          implementation,
          output: {
            psbt: request.operation === "sign" ? psbt([entry(0x02, signature, publicKey)]) : psbt(),
          },
        };
      }),
    };
    const context = new ScenarioExecutionContext({
      rpc: {
        call: vi.fn(async (method: string) =>
          method === "finalizepsbt"
            ? { complete: true, hex: "02000000" }
            : [{ allowed: true, txid: "e".repeat(64) }],
        ),
      } as never,
      artifacts: {
        checkpoint: vi.fn(async (scenarioId: string, stage: string, encoded: string) => ({
          scenario: scenarioId,
          stage,
          psbtPath: `checkpoints/${scenarioId}/${stage}.psbt`,
          factsPath: `checkpoints/${scenarioId}/${stage}.facts.json`,
          facts: extractWireFacts(encoded),
        })),
      },
      adapters: new Map([["rust-bitcoin", adapter]]),
      adapterTimeoutMs: 1_000,
    });
    const negotiated: NegotiatedAdapter = {
      implementation,
      capabilities: {
        operations: ["hello", "native-parse", "roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
        operationScriptTypes: { roundtrip: ["p2wpkh"], sign: ["p2wpkh"] },
        features: ["fixture-commitment-sha256", "user-fixture-template-v1"],
      },
    };

    const [result] = await runScenarioCatalog(
      definition ? [definition] : [],
      context,
      new Map([["rust-bitcoin", negotiated]]),
    );

    expect(result).toMatchObject({
      id: "merchant-refund-handoff",
      outcome: "passed",
      policyAccepted: true,
    });
    expect(requests.map(({ operation }) => operation)).toEqual(["roundtrip", "sign"]);
    expect(requests[1]?.payload).toMatchObject({
      fixtureId: "merchant-refund",
      fixtureSpecSha256: fixture.specSha256,
    });
  });

  test("rejects unknown fixtures and invalid typed dataflow", () => {
    expect(() => compileUserScenarios([scenario()], new Map())).toThrow(/unknown fixture/i);
    const valid = scenario();
    const invalid: UserScenarioSpec = {
      ...valid,
      steps: valid.steps.map((step, index) =>
        index === 3
          ? { id: "policy", operation: "core-policy-check" as const, input: "signed" }
          : step,
      ),
    };
    expect(() =>
      compileUserScenarios([invalid], new Map([["merchant-refund", customFixture()]])),
    ).toThrow(/core-finalize/i);
  });

  test("replays promoted mutation and parser-classification steps", async () => {
    const fixture = customFixture();
    const regression: UserScenarioSpec = {
      id: "parser-regression",
      title: "Parser regression",
      fixture: fixture.id,
      steps: [
        {
          id: "mutated",
          operation: "mutate",
          input: "fixture",
          recipes: [{ kind: "truncate", byteLength: 10 }],
        },
        {
          id: "compare",
          operation: "compare-parsers",
          input: "mutated",
          adapters: ["rust-bitcoin"],
          expected: { lab: "rejected", "rust-bitcoin": "rejected" },
        },
      ],
    };
    const [definition] = compileUserScenarios([regression], new Map([[fixture.id, fixture]]));
    expect(definition?.requirements).toEqual([
      {
        adapter: "rust-bitcoin",
        operations: ["native-parse"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
      },
    ]);

    const implementation: AdapterImplementation = {
      name: "rust-bitcoin",
      version: "0.1.0",
      sourceRevision: "bitcoin-crate-0.32.102",
      artifactDigest: `sha256:${"d".repeat(64)}`,
    };
    const context = new ScenarioExecutionContext({
      rpc: { call: vi.fn() } as never,
      artifacts: {
        checkpoint: vi.fn(async (scenarioId: string, stage: string, encoded: string) => ({
          scenario: scenarioId,
          stage,
          psbtPath: `checkpoints/${scenarioId}/${stage}.psbt`,
          factsPath: `checkpoints/${scenarioId}/${stage}.facts.json`,
          facts: { sha256: encoded },
        })) as never,
      },
      adapters: new Map([
        [
          "rust-bitcoin",
          {
            request: vi.fn(
              async (request: AdapterRequest): Promise<AdapterResponse> => ({
                protocol: "psbt-lab.adapter/0.2",
                id: request.id,
                status: "rejected",
                implementation,
                error: { class: "psbt.parse_failed", message: "truncated map" },
              }),
            ),
          },
        ],
      ]),
      adapterTimeoutMs: 1_000,
    });
    const negotiated: NegotiatedAdapter = {
      implementation,
      capabilities: {
        operations: ["hello", "native-parse"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh"],
      },
    };

    const [result] = await runScenarioCatalog(
      definition ? [definition] : [],
      context,
      new Map([["rust-bitcoin", negotiated]]),
    );

    expect(result).toMatchObject({
      id: "parser-regression",
      outcome: "passed",
      assertions: [
        { name: "mutated", passed: true },
        { name: "compare-lab", passed: true },
        { name: "compare-rust-bitcoin", passed: true },
      ],
    });
  });
});
