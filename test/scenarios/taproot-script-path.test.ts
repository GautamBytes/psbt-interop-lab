import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type {
  AdapterImplementation,
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";
import {
  createTaprootScriptPathCanaryScenario,
  createTaprootScriptPathHandoffScenarios,
} from "../../src/scenarios/taproot-script-path.js";

const scalar1 = Buffer.from(
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
const scalar2 = Buffer.from(
  "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "hex",
);
const leafScript = Buffer.concat([Buffer.from([0x20]), scalar2, Buffer.from([0xac])]);
const controlBlock = Buffer.concat([Buffer.from([0xc0]), scalar1]);
const signature = Buffer.alloc(64, 0x41);

function compactSize(value: number): Buffer {
  if (value < 0xfd) return Buffer.from([value]);
  throw new Error("Test fixture only uses compact sizes below 253");
}

function entry(keyType: number, value: Uint8Array, keyData: Uint8Array = Buffer.alloc(0)): Buffer {
  const valueBytes = Buffer.from(value);
  const key = Buffer.concat([Buffer.from([keyType]), Buffer.from(keyData)]);
  return Buffer.concat([compactSize(key.length), key, compactSize(valueBytes.length), valueBytes]);
}

function map(entries: readonly Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(): Buffer {
  return Buffer.concat([
    Buffer.from("0200000001", "hex"),
    Buffer.alloc(32, 1),
    Buffer.from("0000000000fdffffff01", "hex"),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([0x22, 0x51, 0x20]),
    scalar1,
    Buffer.from("00000000", "hex"),
  ]);
}

function witnessUtxo(): Buffer {
  return Buffer.concat([
    Buffer.from("50c3000000000000", "hex"),
    Buffer.from([0x22, 0x51, 0x20]),
    scalar1,
  ]);
}

function initialPsbt(): string {
  return Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    map([entry(0x00, unsignedTransaction())]),
    map([
      entry(0x01, witnessUtxo()),
      entry(0x15, Buffer.concat([leafScript, Buffer.from([0xc0])]), controlBlock),
      entry(0x17, scalar1),
    ]),
    map([]),
  ]).toString("base64");
}

function serializePsbt(
  psbt: string,
  transform: (entry: {
    keyType: number;
    keyData: Buffer;
    value: Buffer;
  }) => { keyType: number; keyData: Buffer; value: Buffer } | undefined,
): string {
  const document = parsePsbtDocument(psbt);
  const maps = document.maps.map((item) =>
    map(
      item.entries.flatMap((original) => {
        const changed = transform({
          keyType: original.keyType,
          keyData: Buffer.from(original.keyData),
          value: Buffer.from(original.value),
        });
        return changed ? [entry(changed.keyType, changed.value, changed.keyData)] : [];
      }),
    ),
  );
  return Buffer.concat([Buffer.from("70736274ff", "hex"), ...maps]).toString("base64");
}

function signedPsbt(psbt: string): string {
  const document = parsePsbtDocument(psbt);
  const maps = document.maps.map((item) => {
    const entries = item.entries.map((field) =>
      entry(field.keyType, Buffer.from(field.value), Buffer.from(field.keyData)),
    );
    if (item.location.kind === "input" && item.location.index === 0) {
      entries.push(entry(0x14, signature, Buffer.concat([scalar2, Buffer.alloc(32, 0x22)])));
    }
    return map(entries);
  });
  return Buffer.concat([Buffer.from("70736274ff", "hex"), ...maps]).toString("base64");
}

function finalizedPsbt(psbt: string): string {
  const finalWitness = Buffer.concat([
    Buffer.from([3, signature.length]),
    signature,
    Buffer.from([leafScript.length]),
    leafScript,
    Buffer.from([controlBlock.length]),
    controlBlock,
  ]);
  return serializePsbt(psbt, (field) =>
    [0x14, 0x15, 0x16, 0x17, 0x18].includes(field.keyType)
      ? field.keyType === 0x14
        ? { keyType: 0x08, keyData: Buffer.alloc(0), value: finalWitness }
        : undefined
      : field,
  );
}

function keyPathFinalizedPsbt(psbt: string): string {
  const finalWitness = Buffer.concat([Buffer.from([1, signature.length]), signature]);
  return serializePsbt(psbt, (field) =>
    [0x14, 0x15, 0x16, 0x17, 0x18].includes(field.keyType)
      ? field.keyType === 0x14
        ? { keyType: 0x08, keyData: Buffer.alloc(0), value: finalWitness }
        : undefined
      : field,
  );
}

function fixture(): PsbtFixture {
  const initial = initialPsbt();
  return {
    id: "p2tr-scriptpath",
    initialPsbt: initial,
    outpoints: [{ txid: "1".repeat(64), vout: 0, amountSats: 50_000, height: 1 }],
    inputCount: 1,
    outputCount: 1,
    feeSats: 10_000,
    scriptTypes: ["p2tr-scriptpath"],
    inputDescriptors: ["tr(scalar1,pk(scalar2))"],
    outputDescriptor: "tr(scalar1,pk(scalar2))",
    psbtVersion: 0,
    transactionId: "2".repeat(64),
    psbtSha256: extractWireFacts(initial).sha256,
    unsignedTxSha256: `sha256:${"3".repeat(64)}`,
  };
}

const implementations = {
  "rust-bitcoin": {
    name: "rust-bitcoin",
    version: "0.1.0",
    artifactDigest: `sha256:${"a".repeat(64)}`,
  },
  "bdk-wallet-current": {
    name: "bdk-wallet-current",
    version: "3.1.0",
    artifactDigest: `sha256:${"b".repeat(64)}`,
  },
} as const satisfies Record<string, AdapterImplementation>;

function negotiated(): Map<string, NegotiatedAdapter> {
  return new Map(
    Object.entries(implementations).map(([name, implementation]) => [
      name,
      {
        implementation,
        capabilities: {
          operations:
            name === "rust-bitcoin"
              ? (["hello", "roundtrip", "sign", "finalize-inputs"] as const)
              : (["hello", "roundtrip", "sign", "finalize"] as const),
          roles: ["parser", "signer", "finalizer"] as const,
          psbtVersions: [0] as const,
          scriptTypes: ["p2tr-scriptpath"] as const,
          operationScriptTypes:
            name === "rust-bitcoin"
              ? {
                  roundtrip: ["p2tr-scriptpath"] as const,
                  sign: ["p2tr-scriptpath"] as const,
                  "finalize-inputs": ["p2tr-scriptpath"] as const,
                }
              : {
                  roundtrip: ["p2tr-scriptpath"] as const,
                  sign: ["p2tr-scriptpath"] as const,
                  finalize: ["p2tr-scriptpath"] as const,
                },
          features: ["fixture-commitment-sha256"],
        },
      },
    ]),
  );
}

function success(
  request: AdapterRequest,
  implementation: AdapterImplementation,
  psbt: string,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation,
    output: { psbt },
  };
}

function context(
  handle: (name: keyof typeof implementations, request: AdapterRequest) => AdapterResponse,
): ScenarioExecutionContext {
  const call = async <T>(method: string): Promise<T> =>
    (method === "finalizepsbt"
      ? { complete: true, hex: "00" }
      : [{ allowed: true, txid: "4".repeat(64) }]) as T;
  return new ScenarioExecutionContext({
    rpc: { call },
    artifacts: {
      checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
        scenario,
        stage,
        psbtPath: "fixture.psbt",
        factsPath: "fixture.json",
        facts: extractWireFacts(psbt),
      })),
    },
    adapters: new Map(
      Object.keys(implementations).map((name) => [
        name,
        {
          request: vi.fn(async (request: AdapterRequest) =>
            handle(name as keyof typeof implementations, request),
          ),
        },
      ]),
    ),
    adapterTimeoutMs: 1_000,
  });
}

describe("Taproot script-path handoff scenarios", () => {
  test("runs rust-to-BDK and BDK-to-rust signing/finalization handoffs", async () => {
    const input = fixture();
    const signed = signedPsbt(input.initialPsbt);
    const finalized = finalizedPsbt(signed);
    const requests: string[] = [];
    const execution = context((name, request) => {
      requests.push(`${name}:${request.operation}`);
      return success(
        request,
        implementations[name],
        request.operation === "sign" ? signed : finalized,
      );
    });

    const results = await runScenarioCatalog(
      createTaprootScriptPathHandoffScenarios(input),
      execution,
      negotiated(),
    );

    expect(results.map(({ id, outcome }) => [id, outcome])).toEqual([
      ["taproot-scriptpath-rust-to-bdk", "passed"],
      ["taproot-scriptpath-bdk-to-rust", "passed"],
    ]);
    expect(requests).toEqual([
      "rust-bitcoin:sign",
      "bdk-wallet-current:finalize",
      "bdk-wallet-current:sign",
      "rust-bitcoin:finalize-inputs",
    ]);
    expect(results[0]?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "rust-bitcoin-preserved-bip371-while-signing" }),
        expect.objectContaining({ name: "bdk-wallet-current-returned-final-witness" }),
        expect.objectContaining({ name: "core-policy-accepted", passed: true }),
      ]),
    );
  });

  test.each([
    [
      "wrong leaf",
      (field: { keyType: number; keyData: Buffer; value: Buffer }) =>
        field.keyType === 0x15
          ? {
              ...field,
              value: Buffer.concat([field.value.subarray(0, -2), Buffer.from([0xad, 0xc0])]),
            }
          : field,
    ],
    [
      "wrong control block",
      (field: { keyType: number; keyData: Buffer; value: Buffer }) =>
        field.keyType === 0x15
          ? { ...field, keyData: Buffer.concat([Buffer.from([0xc0]), scalar2]) }
          : field,
    ],
    [
      "dropped metadata",
      (field: { keyType: number; keyData: Buffer; value: Buffer }) =>
        field.keyType === 0x15 ? undefined : field,
    ],
  ] as const)("fails the handoff when a signer returns %s", async (_label, mutate) => {
    const input = fixture();
    const contaminated = serializePsbt(signedPsbt(input.initialPsbt), mutate);
    const execution = context((name, request) =>
      success(request, implementations[name], contaminated),
    );
    const definition = createTaprootScriptPathHandoffScenarios(input)[0];
    if (!definition) throw new Error("Missing rust-to-BDK handoff scenario");

    const [result] = await runScenarioCatalog([definition], execution, negotiated());

    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions[0]?.failures).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: expect.stringMatching(/^ENTRY_(?:REMOVED|CHANGED)$/),
          keyType: 0x15,
        }),
      ]),
    );
  });

  test("rejects a Core-valid key-path witness in the script-path scenario", async () => {
    const input = fixture();
    const signed = signedPsbt(input.initialPsbt);
    const keyPathFinalized = keyPathFinalizedPsbt(signed);
    const execution = context((name, request) =>
      success(
        request,
        implementations[name],
        request.operation === "sign" ? signed : keyPathFinalized,
      ),
    );
    const definition = createTaprootScriptPathHandoffScenarios(input)[0];
    if (!definition) throw new Error("Missing rust-to-BDK handoff scenario");

    const [result] = await runScenarioCatalog([definition], execution, negotiated());

    expect(result).toMatchObject({ outcome: "failed" });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "bdk-wallet-current-returned-exact-script-path-witness",
          passed: false,
        }),
      ]),
    );
  });

  test("requires both native adapters to reject wrong leaf, control block, and dropped metadata", async () => {
    const requests: string[] = [];
    const execution = context((name, request) => {
      requests.push(`${name}:${request.operation}`);
      return {
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "rejected",
        implementation: implementations[name],
        error: {
          class: "policy.psbt_not_authorized",
          message: "fixture metadata mismatch",
        },
      };
    });

    const [result] = await runScenarioCatalog(
      [createTaprootScriptPathCanaryScenario(fixture())],
      execution,
      negotiated(),
    );

    expect(result).toMatchObject({
      id: "taproot-scriptpath-negative-canaries",
      outcome: "passed",
    });
    expect(result?.assertions).toHaveLength(6);
    expect(requests).toHaveLength(6);
  });
});
