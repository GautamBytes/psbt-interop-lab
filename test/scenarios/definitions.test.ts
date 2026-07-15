import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type {
  AdapterImplementation,
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { createBdkRegressionScenario } from "../../src/scenarios/bdk-regression.js";
import {
  type AdapterRequestClient,
  ScenarioExecutionContext,
} from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";
import { createHappyPathScenario } from "../../src/scenarios/happy-path.js";
import {
  createParallelCombineScenario,
  createRoundtripChainScenario,
} from "../../src/scenarios/interop-matrix.js";

const magic = Buffer.from("70736274ff", "hex");
const fixturePublicKey = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
const partialSignature = Buffer.concat([
  Buffer.from("30440220", "hex"),
  Buffer.alloc(32, 0x01),
  Buffer.from("0220", "hex"),
  Buffer.alloc(32, 0x02),
  Buffer.from([0x01]),
]);
const proprietaryEntry = entry(
  0xfc,
  Buffer.from("opaque metadata"),
  Buffer.from("036c616201", "hex"),
);

function entry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([
    Buffer.from([key.byteLength]),
    key,
    Buffer.from([value.byteLength]),
    value,
  ]);
}

function map(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function unsignedTransaction(inputCount: number): Buffer {
  const inputs = Array.from({ length: inputCount }, (_, index) =>
    Buffer.concat([
      Buffer.alloc(32, index + 1),
      Buffer.from("00000000", "hex"),
      Buffer.from([0]),
      Buffer.from("fdffffff", "hex"),
    ]),
  );
  return Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([inputCount]),
    ...inputs,
    Buffer.from([1]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("00000000", "hex"),
  ]);
}

function encodedPsbt(inputMaps: readonly (readonly Buffer[])[], transactionFirst = true): string {
  const transaction = entry(0x00, unsignedTransaction(inputMaps.length));
  const globalEntries = transactionFirst
    ? [transaction, proprietaryEntry]
    : [proprietaryEntry, transaction];
  return Buffer.concat([
    magic,
    map(...globalEntries),
    ...inputMaps.map((entries) => map(...entries)),
    map(),
  ]).toString("base64");
}

function signedInput(): Buffer {
  return entry(0x02, partialSignature, fixturePublicKey);
}

function finalizedInput(): Buffer {
  const witness = Buffer.concat([
    Buffer.from([2, partialSignature.byteLength]),
    partialSignature,
    Buffer.from([1, 0x51]),
  ]);
  return entry(0x08, witness);
}

function fixture(id: PsbtFixture["id"], initialPsbt: string, inputCount: number): PsbtFixture {
  return {
    id,
    initialPsbt,
    outpoints: Array.from({ length: inputCount }, (_, index) => ({
      txid: String(index + 1).padStart(64, "0"),
      vout: 0,
      amountSats: 20_000,
      height: 1,
    })),
    inputCount,
    outputCount: 1,
    feeSats: 1_000,
    scriptTypes: Array.from({ length: inputCount }, () => "p2wsh" as const),
    inputDescriptors: ["wsh(pk(...))#checksum"],
    outputDescriptor: "wsh(pk(...))#checksum",
    psbtVersion: 0,
    transactionId: "e".repeat(64),
    psbtSha256: extractWireFacts(initialPsbt).sha256,
    unsignedTxSha256: `sha256:${"f".repeat(64)}`,
  };
}

interface FakeAdapter extends AdapterRequestClient {
  requests: AdapterRequest[];
}

function adapter(handle: (request: AdapterRequest) => AdapterResponse): FakeAdapter {
  const requests: AdapterRequest[] = [];
  return {
    requests,
    request: vi.fn(async (request: AdapterRequest) => {
      requests.push(request);
      return handle(request);
    }),
  };
}

function success(
  request: AdapterRequest,
  implementation: AdapterImplementation,
  output: Record<string, string | number | boolean | number[]>,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: request.id,
    status: "ok",
    implementation,
    output,
  };
}

const rustImplementation: AdapterImplementation = {
  name: "rust-bitcoin",
  version: "0.1.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
  sourceRevision: "bitcoin-crate-0.32.102",
};
const bdkImplementation: AdapterImplementation = {
  name: "bdkpython",
  version: "2.3.1",
  artifactDigest: `sha256:${"b".repeat(64)}`,
  sourceRevision: "bdk-ffi-v2.3.1",
};
const goImplementation: AdapterImplementation = {
  name: "btcsuite-go",
  version: "v1.2.0",
  artifactDigest: `sha256:${"d".repeat(64)}`,
  sourceRevision: "github.com/btcsuite/btcd/btcutil/psbt@v1.2.0",
};

const rustNegotiated: NegotiatedAdapter = {
  implementation: rustImplementation,
  capabilities: {
    operations: ["hello", "roundtrip", "sign", "finalize-inputs"],
    roles: ["parser", "signer", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["fixture-commitment-sha256"],
  },
};
const bdkNegotiated: NegotiatedAdapter = {
  implementation: bdkImplementation,
  capabilities: {
    operations: ["hello", "inspect", "roundtrip", "finalize"],
    roles: ["parser", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["historical-regression.bdk-wallet-488"],
  },
};
const goNegotiated: NegotiatedAdapter = {
  implementation: goImplementation,
  capabilities: {
    operations: ["hello", "inspect", "roundtrip", "sign", "finalize", "finalize-inputs"],
    roles: ["parser", "signer", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["fixture-commitment-sha256"],
  },
};
const bitcoinjsImplementation: AdapterImplementation = {
  name: "bitcoinjs-lib",
  version: "1.0.0",
  artifactDigest: `sha256:${"f".repeat(64)}`,
  sourceRevision: "bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4",
};
const bitcoinjsNegotiated: NegotiatedAdapter = {
  implementation: bitcoinjsImplementation,
  capabilities: {
    operations: ["hello", "inspect", "roundtrip", "sign", "combine", "finalize", "finalize-inputs"],
    roles: ["parser", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["fixture-commitment-sha256"],
  },
};

function executionContext(
  adapters: ReadonlyMap<string, AdapterRequestClient>,
): ScenarioExecutionContext {
  const call = vi
    .fn()
    .mockResolvedValueOnce({ complete: true, hex: "02000000" })
    .mockResolvedValueOnce([{ allowed: true, txid: "c".repeat(64) }]);
  return new ScenarioExecutionContext({
    rpc: { call } as never,
    artifacts: {
      checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
        scenario,
        stage,
        psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
        factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
        facts: extractWireFacts(psbt),
      })),
    },
    adapters,
    adapterTimeoutMs: 1_000,
  });
}

describe("happy path scenario", () => {
  test("requires semantic preservation, an observable signature, and Core policy acceptance", async () => {
    const initial = encodedPsbt([[]]);
    const reordered = encodedPsbt([[]], false);
    const signed = encodedPsbt([[signedInput()]], false);
    const rust = adapter((request) =>
      success(request, rustImplementation, {
        psbt: request.operation === "sign" ? signed : reordered,
        ...(request.operation === "sign" ? { signedInputs: 1 } : {}),
      }),
    );
    const context = executionContext(new Map([["rust-bitcoin", rust]]));

    const [result] = await runScenarioCatalog(
      [createHappyPathScenario(fixture("happy-path", initial, 1))],
      context,
      new Map([["rust-bitcoin", rustNegotiated]]),
    );

    expect(result).toMatchObject({
      id: "happy-path",
      outcome: "passed",
      policyAccepted: true,
      assertions: [
        { name: "rust-roundtrip", passed: true, exactBytesEqual: false },
        { name: "rust-signing-transition", passed: true },
        { name: "rust-added-signature", passed: true },
        { name: "core-finalized", passed: true },
        { name: "core-policy-accepted", passed: true },
      ],
    });
    expect(rust.requests.map(({ operation }) => operation)).toEqual(["roundtrip", "sign"]);
  });

  test("fails when a signer returns the unchanged PSBT", async () => {
    const initial = encodedPsbt([[]]);
    const rust = adapter((request) =>
      success(request, rustImplementation, { psbt: initial, signedInputs: 1 }),
    );
    const context = executionContext(new Map([["rust-bitcoin", rust]]));

    const [result] = await runScenarioCatalog(
      [createHappyPathScenario(fixture("happy-path", initial, 1))],
      context,
      new Map([["rust-bitcoin", rustNegotiated]]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [{ name: "rust-added-signature", passed: false }],
    });
  });

  test("uses the selected active implementation for a matrix handoff", async () => {
    const initial = encodedPsbt([[]]);
    const signed = encodedPsbt([[signedInput()]]);
    const go = adapter((request) =>
      success(request, goImplementation, {
        psbt: request.operation === "sign" ? signed : initial,
        ...(request.operation === "sign" ? { signedInputs: 1 } : {}),
      }),
    );
    const context = executionContext(new Map([["btcsuite-go", go]]));

    const [result] = await runScenarioCatalog(
      [
        createHappyPathScenario(fixture("happy-path", initial, 1), {
          adapter: "btcsuite-go",
          id: "p2wsh-sign-btcsuite-go",
          title: "Core to btcsuite signing handoff",
        }),
      ],
      context,
      new Map([["btcsuite-go", goNegotiated]]),
    );

    expect(result).toMatchObject({ id: "p2wsh-sign-btcsuite-go", outcome: "passed" });
    expect(go.requests.map(({ operation }) => operation)).toEqual(["roundtrip", "sign"]);
  });
});

describe("BDK regression scenario", () => {
  test("reproduces the frozen BDK rejection while Core accepts the same mixed-state PSBT", async () => {
    const initial = encodedPsbt([[], []]);
    const signed = encodedPsbt([[signedInput()], [signedInput()]]);
    const mixed = encodedPsbt([[finalizedInput()], [signedInput()]]);
    const rust = adapter((request) =>
      success(request, rustImplementation, {
        psbt: request.operation === "finalize-inputs" ? mixed : signed,
        ...(request.operation === "finalize-inputs"
          ? { finalizedInputs: [0], remainingPartialInputs: 1 }
          : { signedInputs: 2 }),
      }),
    );
    const bdk = adapter((request) => {
      if (request.operation === "finalize") {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation: bdkImplementation,
          error: {
            class: "finalize.missing_witness_script",
            message: "Expected historical failure",
          },
        };
      }
      return success(request, bdkImplementation, { psbt: initial, byteIdentical: true });
    });
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["bdkpython", bdk],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createBdkRegressionScenario(fixture("bdk-finalize-regression", initial, 2))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      id: "bdk-finalize-regression",
      outcome: "passed",
      expectedFailure: {
        implementation: "bdkpython@2.3.1",
        errorClass: "finalize.missing_witness_script",
      },
      assertions: expect.arrayContaining([
        expect.objectContaining({ name: "rust-finalized-input-0", passed: true }),
        expect.objectContaining({ name: "bdk-regression-reproduced", passed: true }),
        expect.objectContaining({ name: "core-policy-accepted", passed: true }),
      ]),
    });
    expect(rust.requests.find(({ operation }) => operation === "finalize-inputs")?.payload).toEqual(
      {
        psbt: signed,
        network: "regtest",
        fixtureId: "bdk-finalize-regression",
        inputIndexes: [0],
      },
    );
  });

  test("can replay the regression through the selected Go finalizer", async () => {
    const initial = encodedPsbt([[], []]);
    const signed = encodedPsbt([[signedInput()], [signedInput()]]);
    const mixed = encodedPsbt([[finalizedInput()], [signedInput()]]);
    const go = adapter((request) =>
      success(request, goImplementation, {
        psbt: request.operation === "finalize-inputs" ? mixed : signed,
      }),
    );
    const bdk = adapter((request) =>
      request.operation === "finalize"
        ? {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "rejected",
            implementation: bdkImplementation,
            error: {
              class: "finalize.missing_witness_script",
              message: "Expected historical failure",
            },
          }
        : success(request, bdkImplementation, { psbt: initial }),
    );
    const context = executionContext(
      new Map([
        ["btcsuite-go", go],
        ["bdkpython", bdk],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [
        createBdkRegressionScenario(fixture("bdk-finalize-regression", initial, 2), {
          adapter: "btcsuite-go",
          id: "bdk-regression-btcsuite-go",
          title: "BDK regression through btcsuite",
        }),
      ],
      context,
      new Map([
        ["btcsuite-go", goNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({ id: "bdk-regression-btcsuite-go", outcome: "passed" });
    expect(go.requests.map(({ operation }) => operation)).toEqual(["sign", "finalize-inputs"]);
  });

  test("fails if the selected finalizer also finalizes the second input", async () => {
    const initial = encodedPsbt([[], []]);
    const signed = encodedPsbt([[signedInput()], [signedInput()]]);
    const fullyFinalized = encodedPsbt([[finalizedInput()], [finalizedInput()]]);
    const rust = adapter((request) =>
      success(request, rustImplementation, {
        psbt: request.operation === "finalize-inputs" ? fullyFinalized : signed,
      }),
    );
    const bdk = adapter((request) => success(request, bdkImplementation, { psbt: initial }));
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["bdkpython", bdk],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createBdkRegressionScenario(fixture("bdk-finalize-regression", initial, 2))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [{ name: "input-1-remains-partially-signed", passed: false }],
    });
  });
});

describe("active implementation matrix scenarios", () => {
  test("roundtrips through four implementations before signing", async () => {
    const initial = encodedPsbt([[]]);
    const signed = encodedPsbt([[signedInput()]]);
    const requestOrder: string[] = [];
    const makeRoundtripper = (implementation: AdapterImplementation) =>
      adapter((request) => {
        requestOrder.push(`${implementation.name}:${request.operation}`);
        return success(request, implementation, {
          psbt:
            implementation.name === "bitcoinjs-lib" && request.operation === "sign"
              ? signed
              : initial,
        });
      });
    const rust = makeRoundtripper(rustImplementation);
    const go = makeRoundtripper(goImplementation);
    const bitcoinjs = makeRoundtripper(bitcoinjsImplementation);
    const bdk = makeRoundtripper(bdkImplementation);
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", bitcoinjs],
        ["bdkpython", bdk],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createRoundtripChainScenario(fixture("happy-path", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({ id: "four-library-roundtrip-chain", outcome: "passed" });
    expect(requestOrder).toEqual([
      "bdkpython:roundtrip",
      "rust-bitcoin:roundtrip",
      "btcsuite-go:roundtrip",
      "bitcoinjs-lib:roundtrip",
      "bitcoinjs-lib:sign",
    ]);
  });

  test("combines independently signed copies and rejects a false-green empty combine", async () => {
    const initial = encodedPsbt([[]]);
    const signed = encodedPsbt([[signedInput()]]);
    const rust = adapter((request) => success(request, rustImplementation, { psbt: signed }));
    const go = adapter((request) => success(request, goImplementation, { psbt: signed }));
    const bitcoinjs = adapter((request) =>
      success(request, bitcoinjsImplementation, {
        psbt: request.operation === "combine" ? signed : initial,
      }),
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", bitcoinjs],
      ]),
    );
    const negotiated = new Map([
      ["rust-bitcoin", rustNegotiated],
      ["btcsuite-go", goNegotiated],
      ["bitcoinjs-lib", bitcoinjsNegotiated],
    ]);

    const [passed] = await runScenarioCatalog(
      [createParallelCombineScenario(fixture("happy-path", initial, 1))],
      context,
      negotiated,
    );
    expect(passed).toMatchObject({ id: "parallel-sign-and-combine", outcome: "passed" });
    expect(bitcoinjs.requests[0]?.payload).toEqual({ psbts: [signed, signed] });

    const emptyCombiner = adapter((request) =>
      success(request, bitcoinjsImplementation, { psbt: initial }),
    );
    const failedContext = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", emptyCombiner],
      ]),
    );
    const [failed] = await runScenarioCatalog(
      [createParallelCombineScenario(fixture("happy-path", initial, 1))],
      failedContext,
      negotiated,
    );
    expect(failed).toMatchObject({ outcome: "failed" });
  });
});
