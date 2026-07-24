import { describe, expect, test, vi } from "vitest";
import type { PsbtFixture } from "../../src/core/fixtures.js";
import type {
  AdapterImplementation,
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { extractTransactionIdentity } from "../../src/psbt/diff.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { createBdkRegressionScenario } from "../../src/scenarios/bdk-regression.js";
import {
  type AdapterRequestClient,
  ScenarioExecutionContext,
} from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";
import { createHappyPathScenario } from "../../src/scenarios/happy-path.js";
import * as interopMatrix from "../../src/scenarios/interop-matrix.js";
import {
  createParallelCombineScenario,
  createRoundtripChainScenario,
} from "../../src/scenarios/interop-matrix.js";
import {
  createInvalidInputScenario,
  invalidPsbtCases,
} from "../../src/scenarios/invalid-inputs.js";
import {
  createMetadataPreservationScenario,
  enrichPsbtWithExtensionFields,
  verifyInjectedExtensionFields,
  verifyInjectedProprietaryFields,
} from "../../src/scenarios/metadata-preservation.js";

const magic = Buffer.from("70736274ff", "hex");
const fixturePublicKey = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
const fixturePublicKey2 = Buffer.from(
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
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

function intentPsbt(inputEntries: readonly Buffer[] = []): string {
  const unsigned = Buffer.concat([
    Buffer.from("02000000", "hex"),
    Buffer.from([1]),
    Buffer.alloc(32, 0x01),
    Buffer.from("00000000", "hex"),
    Buffer.from([0]),
    Buffer.from("fcffffff", "hex"),
    Buffer.from([2]),
    Buffer.from("1027000000000000", "hex"),
    Buffer.from([1, 0x51]),
    Buffer.from("2823000000000000", "hex"),
    Buffer.from([1, 0x00]),
    Buffer.from("2a000000", "hex"),
  ]);
  return Buffer.concat([
    magic,
    map(entry(0x00, unsigned)),
    map(...inputEntries),
    map(),
    map(),
  ]).toString("base64");
}

function appendFirstInputEntry(psbt: string, added: Buffer): string {
  const document = parsePsbtDocument(psbt);
  const maps = document.maps.map((documentMap) => {
    const entries = documentMap.entries.map((item) =>
      entry(item.keyType, Buffer.from(item.value), Buffer.from(item.keyData)),
    );
    return documentMap.location.kind === "input" && documentMap.location.index === 0
      ? map(...entries, added)
      : map(...entries);
  });
  return Buffer.concat([magic, ...maps]).toString("base64");
}

function signedInput(): Buffer {
  return entry(0x02, partialSignature, fixturePublicKey);
}

function signedInput2(): Buffer {
  const signature = Buffer.from(partialSignature);
  signature[5] = 0x03;
  return entry(0x02, signature, fixturePublicKey2);
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
    operations: ["hello", "native-parse", "roundtrip", "sign", "finalize-inputs"],
    roles: ["parser", "signer", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    operationScriptTypes: {
      roundtrip: ["p2wsh"],
      sign: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
    features: ["fixture-commitment-sha256"],
  },
};
const bdkNegotiated: NegotiatedAdapter = {
  implementation: bdkImplementation,
  capabilities: {
    operations: ["hello", "native-parse", "inspect", "roundtrip", "finalize"],
    roles: ["parser", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    operationScriptTypes: {
      inspect: ["p2wsh"],
      roundtrip: ["p2wsh"],
      finalize: ["p2wsh"],
    },
    features: ["historical-regression.bdk-wallet-488"],
  },
};
const goNegotiated: NegotiatedAdapter = {
  implementation: goImplementation,
  capabilities: {
    operations: [
      "hello",
      "native-parse",
      "inspect",
      "roundtrip",
      "sign",
      "finalize",
      "finalize-inputs",
    ],
    roles: ["parser", "signer", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    operationScriptTypes: {
      inspect: ["p2wsh"],
      roundtrip: ["p2wsh"],
      sign: ["p2wsh"],
      finalize: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
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
    operations: [
      "hello",
      "native-parse",
      "inspect",
      "roundtrip",
      "sign",
      "combine",
      "finalize",
      "finalize-inputs",
    ],
    roles: ["parser", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    operationScriptTypes: {
      inspect: ["p2wsh"],
      roundtrip: ["p2wsh"],
      sign: ["p2wsh"],
      combine: ["p2wsh"],
      finalize: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
    features: ["fixture-commitment-sha256"],
  },
};

function executionContext(
  adapters: ReadonlyMap<string, AdapterRequestClient>,
  rpcCall = vi.fn(async (method: string, params: Record<string, unknown>) => {
    if (method === "finalizepsbt" && params["extract"] === false) {
      return { complete: true, psbt: params["psbt"] };
    }
    if (method === "finalizepsbt") return { complete: true, hex: "02000000" };
    if (method === "testmempoolaccept") return [{ allowed: true, txid: "c".repeat(64) }];
    throw new Error(`Unexpected RPC method ${method}`);
  }),
): ScenarioExecutionContext {
  return new ScenarioExecutionContext({
    rpc: { call: rpcCall } as never,
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

  test("declares and executes a P2WPKH profile handoff without pretending it is P2WSH", async () => {
    const initial = encodedPsbt([[]]);
    const signed = encodedPsbt([[signedInput()]]);
    const rust = adapter((request) =>
      success(request, rustImplementation, {
        psbt: request.operation === "sign" ? signed : initial,
        ...(request.operation === "sign" ? { signedInputs: 1 } : {}),
      }),
    );
    const context = executionContext(new Map([["rust-bitcoin", rust]]));
    const p2wpkhFixture = {
      ...fixture("p2wpkh", initial, 1),
      scriptTypes: ["p2wpkh" as const],
    };
    const p2wpkhRust = {
      ...rustNegotiated,
      capabilities: {
        ...rustNegotiated.capabilities,
        scriptTypes: ["p2wpkh" as const, "p2wsh" as const],
        operationScriptTypes: {
          ...rustNegotiated.capabilities.operationScriptTypes,
          roundtrip: ["p2wpkh" as const, "p2wsh" as const],
          sign: ["p2wpkh" as const, "p2wsh" as const],
        },
      },
    };

    const scenario = createHappyPathScenario(p2wpkhFixture, {
      adapter: "rust-bitcoin",
      id: "p2wpkh-sign-rust-bitcoin",
      title: "P2WPKH signing through rust-bitcoin",
      scriptType: "p2wpkh",
      signatureKeyTypes: [0x02],
    });
    expect(scenario.requirements).toMatchObject([{ scriptTypes: ["p2wpkh"] }]);

    const [result] = await runScenarioCatalog(
      [scenario],
      context,
      new Map([["rust-bitcoin", p2wpkhRust]]),
    );

    expect(result).toMatchObject({
      id: "p2wpkh-sign-rust-bitcoin",
      outcome: "passed",
    });
    expect(rust.requests.map(({ operation }) => operation)).toEqual(["roundtrip", "sign"]);
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

  test.each(["crashed", "timeout"] as const)(
    "keeps BDK adapter %s as scenario evidence instead of infrastructure failures",
    async (status) => {
      const initial = encodedPsbt([[], []]);
      const signed = encodedPsbt([[signedInput()], [signedInput()]]);
      const mixed = encodedPsbt([[finalizedInput()], [signedInput()]]);
      const rust = adapter((request) =>
        success(request, rustImplementation, {
          psbt: request.operation === "finalize-inputs" ? mixed : signed,
        }),
      );
      const bdk = adapter((request) =>
        request.operation === "finalize"
          ? {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status,
              implementation: bdkImplementation,
              error: {
                class: status === "timeout" ? "AdapterTimeoutError" : "adapter.process_exit",
                message: status === "timeout" ? "adapter timed out" : "adapter exited",
              },
            }
          : success(request, bdkImplementation, { psbt: initial }),
      );
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
        assertions: expect.arrayContaining([
          expect.objectContaining({
            name: "bdk-regression-reproduced",
            passed: false,
            likelyImplementation: "bdkpython",
          }),
        ]),
        adapterCells: expect.arrayContaining([
          expect.objectContaining({
            adapter: "bdkpython",
            operation: "finalize",
            status: "failed",
            errorClass: status === "timeout" ? "AdapterTimeoutError" : "adapter.process_exit",
          }),
        ]),
      });
      expect(result).not.toHaveProperty("infrastructureError");
    },
  );

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
  test("exports a same-input 2-of-3 multisig interoperability scenario", () => {
    expect(interopMatrix).toHaveProperty("createSameInputMultisigScenario");
  });

  test("exports the transaction-intent enrichment and executable scenario", () => {
    expect(interopMatrix).toHaveProperty("enrichPsbtWithIntentMetadata");
    expect(interopMatrix).toHaveProperty("createTransactionIntentScenario");
  });

  test("adds explicit sighash and derivation metadata without changing transaction intent", () => {
    const initial = intentPsbt([entry(0x06, Buffer.from("751e76e8", "hex"), fixturePublicKey)]);
    const intentFixture = {
      ...fixture("intent-rich-p2wpkh", initial, 1),
      outputCount: 2,
      scriptTypes: ["p2wpkh" as const],
    };

    const enriched = interopMatrix.enrichPsbtWithIntentMetadata(intentFixture);
    const before = parsePsbtDocument(initial);
    const after = parsePsbtDocument(enriched);
    const input = after.maps.find(
      (candidate) => candidate.location.kind === "input" && candidate.location.index === 0,
    );
    const sighash = input?.entries.find(
      (candidate) => candidate.keyType === 0x03 && candidate.keyData.length === 0,
    );
    const derivation = input?.entries.find(
      (candidate) => candidate.keyType === 0x06 && candidate.keyData.equals(fixturePublicKey),
    );

    expect(sighash?.value.toString("hex")).toBe("01000000");
    expect(derivation?.value.toString("hex")).toBe("751e76e8");
    expect(extractTransactionIdentity(after)).toEqual(extractTransactionIdentity(before));
  });

  test("preserves rich transaction intent through three parsers, signing, and Core policy", async () => {
    const initial = intentPsbt([entry(0x06, Buffer.from("751e76e8", "hex"), fixturePublicKey)]);
    const intentFixture = {
      ...fixture("intent-rich-p2wpkh", initial, 1),
      outputCount: 2,
      scriptTypes: ["p2wpkh" as const],
    };
    const enriched = interopMatrix.enrichPsbtWithIntentMetadata(intentFixture);
    const signed = appendFirstInputEntry(enriched, signedInput());
    const passthrough = (implementation: AdapterImplementation) =>
      adapter((request) =>
        success(request, implementation, {
          psbt: request.operation === "sign" ? signed : (request.payload["psbt"] as string),
          ...(request.operation === "sign" ? { signedInputs: 1 } : { byteIdentical: true }),
        }),
      );
    const rust = passthrough(rustImplementation);
    const go = passthrough(goImplementation);
    const bitcoinjs = passthrough(bitcoinjsImplementation);
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", bitcoinjs],
      ]),
    );
    const withP2wpkh = (negotiated: NegotiatedAdapter): NegotiatedAdapter => ({
      ...negotiated,
      capabilities: {
        ...negotiated.capabilities,
        scriptTypes: ["p2wpkh", "p2wsh"],
        operationScriptTypes: Object.fromEntries(
          Object.entries(negotiated.capabilities.operationScriptTypes ?? {}).map(
            ([operation, scriptTypes]) => [
              operation,
              operation === "roundtrip" || operation === "sign"
                ? ["p2wpkh", ...scriptTypes]
                : scriptTypes,
            ],
          ),
        ),
      },
    });

    const [result] = await runScenarioCatalog(
      [interopMatrix.createTransactionIntentScenario(intentFixture)],
      context,
      new Map([
        ["rust-bitcoin", withP2wpkh(rustNegotiated)],
        ["btcsuite-go", withP2wpkh(goNegotiated)],
        ["bitcoinjs-lib", withP2wpkh(bitcoinjsNegotiated)],
      ]),
    );

    expect(result).toMatchObject({
      id: "transaction-intent-preservation",
      outcome: "passed",
      policyAccepted: true,
      assertions: expect.arrayContaining([
        expect.objectContaining({
          name: "expected-version-locktime-sequence-outputs",
          passed: true,
        }),
        expect.objectContaining({ name: "explicit-sighash-and-derivation", passed: true }),
        expect.objectContaining({ name: "rust-bitcoin-signing-transition", passed: true }),
        expect.objectContaining({ name: "core-policy-accepted", passed: true }),
      ]),
    });
    expect(rust.requests.map(({ operation }) => operation)).toEqual(["roundtrip", "sign"]);
    expect(go.requests.map(({ operation }) => operation)).toEqual(["roundtrip"]);
    expect(bitcoinjs.requests.map(({ operation }) => operation)).toEqual(["roundtrip"]);
  });

  test("combines two independent signatures on the same multisig input", async () => {
    const initial = encodedPsbt([[]]);
    const rustSigned = encodedPsbt([[signedInput()]]);
    const bitcoinjsSigned = encodedPsbt([[signedInput2()]]);
    const combined = encodedPsbt([[signedInput(), signedInput2()]]);
    const rust = adapter((request) =>
      success(request, rustImplementation, { psbt: rustSigned, signedInputs: 1 }),
    );
    const bitcoinjs = adapter((request) =>
      success(request, bitcoinjsImplementation, {
        psbt: request.operation === "combine" ? combined : bitcoinjsSigned,
        ...(request.operation === "combine" ? { combinedCount: 2 } : { signedInputs: 1 }),
      }),
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["bitcoinjs-lib", bitcoinjs],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [interopMatrix.createSameInputMultisigScenario(fixture("p2wsh-2-of-3", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      id: "same-input-2-of-3-multisig",
      outcome: "passed",
      policyAccepted: true,
      assertions: expect.arrayContaining([
        expect.objectContaining({ name: "rust-bitcoin-added-scalar-1", passed: true }),
        expect.objectContaining({ name: "bitcoinjs-lib-added-scalar-2", passed: true }),
        expect.objectContaining({ name: "combined-two-distinct-signatures", passed: true }),
        expect.objectContaining({ name: "core-policy-accepted", passed: true }),
      ]),
    });
    expect(rust.requests.map(({ operation }) => operation)).toEqual(["sign"]);
    expect(bitcoinjs.requests.map(({ operation }) => operation)).toEqual(["sign", "combine"]);
  });

  test("fails same-input multisig when the combiner adds a field outside the exact union", async () => {
    const initial = encodedPsbt([[]]);
    const rustSigned = encodedPsbt([[signedInput()]]);
    const bitcoinjsSigned = encodedPsbt([[signedInput2()]]);
    const combined = encodedPsbt([[signedInput(), signedInput2()]]);
    const contaminated = appendFirstInputEntry(combined, proprietaryEntry);
    const rust = adapter((request) =>
      success(request, rustImplementation, { psbt: rustSigned, signedInputs: 1 }),
    );
    const bitcoinjs = adapter((request) =>
      success(request, bitcoinjsImplementation, {
        psbt: request.operation === "combine" ? contaminated : bitcoinjsSigned,
        ...(request.operation === "combine" ? { combinedCount: 2 } : { signedInputs: 1 }),
      }),
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rust],
        ["bitcoinjs-lib", bitcoinjs],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [interopMatrix.createSameInputMultisigScenario(fixture("p2wsh-2-of-3", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: expect.arrayContaining([
        expect.objectContaining({ name: "combined-exact-field-union", passed: false }),
      ]),
    });
  });

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
    const initial = encodedPsbt([[], []]);
    const rustSigned = encodedPsbt([[signedInput()], []]);
    const goSigned = encodedPsbt([[], [signedInput()]]);
    const combined = encodedPsbt([[signedInput()], [signedInput()]]);
    const rust = adapter((request) => success(request, rustImplementation, { psbt: rustSigned }));
    const go = adapter((request) => success(request, goImplementation, { psbt: goSigned }));
    const bitcoinjs = adapter((request) =>
      success(request, bitcoinjsImplementation, {
        psbt: request.operation === "combine" ? combined : initial,
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
      [createParallelCombineScenario(fixture("bdk-finalize-regression", initial, 2))],
      context,
      negotiated,
    );
    expect(passed).toMatchObject({ id: "parallel-sign-and-combine", outcome: "passed" });
    expect(rust.requests[0]?.payload).toMatchObject({ inputIndexes: [0] });
    expect(go.requests[0]?.payload).toMatchObject({ inputIndexes: [1] });
    expect(bitcoinjs.requests[0]?.payload).toEqual({ psbts: [rustSigned, goSigned] });

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
      [createParallelCombineScenario(fixture("bdk-finalize-regression", initial, 2))],
      failedContext,
      negotiated,
    );
    expect(failed).toMatchObject({ outcome: "failed" });
  });
});

describe("invalid input matrix", () => {
  test("requires every parser to reject every malformed or unsupported PSBT cleanly", async () => {
    const initial = encodedPsbt([[]]);
    const implementations = [
      rustImplementation,
      goImplementation,
      bitcoinjsImplementation,
      bdkImplementation,
    ];
    const adapters = new Map(
      implementations.map((implementation) => [
        implementation.name,
        adapter((request) => ({
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
        })),
      ]),
    );
    const context = executionContext(adapters);

    const [result] = await runScenarioCatalog(
      [createInvalidInputScenario(fixture("happy-path", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({ id: "invalid-and-unsupported-inputs", outcome: "passed" });
    expect(result?.assertions).toHaveLength(20);
    for (const parser of adapters.values()) {
      expect(parser.requests.every(({ operation }) => operation === "native-parse")).toBe(true);
    }
  });

  test("fails if an adapter accepts malformed input", async () => {
    const initial = encodedPsbt([[]]);
    const rejecting = (implementation: AdapterImplementation) =>
      adapter((request) => ({
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "rejected",
        implementation,
        error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
      }));
    const lyingGo = adapter((request) =>
      success(request, goImplementation, { psbt: String(request.payload["psbt"]) }),
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rejecting(rustImplementation)],
        ["btcsuite-go", lyingGo],
        ["bitcoinjs-lib", rejecting(bitcoinjsImplementation)],
        ["bdkpython", rejecting(bdkImplementation)],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createInvalidInputScenario(fixture("happy-path", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({ outcome: "failed" });
  });

  test("records btcsuite duplicate-global-key acceptance as a known compatibility finding", async () => {
    const initial = encodedPsbt([[]]);
    const inputFixture = fixture("happy-path", initial, 1);
    const duplicate = invalidPsbtCases(inputFixture).find(
      (testCase) => testCase.id === "duplicate-global-key",
    )?.psbt;
    expect(duplicate).toBeDefined();
    const rejecting = (implementation: AdapterImplementation) =>
      adapter((request) => ({
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "rejected",
        implementation,
        error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
      }));
    const go = adapter((request) =>
      request.payload["psbt"] === duplicate
        ? success(request, goImplementation, {
            nativeParser: "btcsuite-go",
            psbtVersion: 0,
          })
        : {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "rejected",
            implementation: goImplementation,
            error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
          },
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rejecting(rustImplementation)],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", rejecting(bitcoinjsImplementation)],
        ["bdkpython", rejecting(bdkImplementation)],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createInvalidInputScenario(inputFixture)],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "passed",
      findings: [
        {
          id: "btcsuite-go-duplicate-global-key-accepted",
          implementation: "btcsuite-go",
        },
      ],
    });
  });

  test("fails if a parser accepts undeclared PSBTv2", async () => {
    const initial = encodedPsbt([[]]);
    const inputFixture = fixture("happy-path", initial, 1);
    const psbtV2 = invalidPsbtCases(inputFixture).find(
      (testCase) => testCase.id === "unsupported-psbt-v2",
    )?.psbt;
    expect(psbtV2).toBeDefined();
    const rejecting = (implementation: AdapterImplementation) =>
      adapter((request) => ({
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "rejected",
        implementation,
        error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
      }));
    const go = adapter((request) =>
      request.payload["psbt"] === psbtV2
        ? success(request, goImplementation, { nativeParser: "btcsuite-go", psbtVersion: 2 })
        : {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "rejected",
            implementation: goImplementation,
            error: { class: "psbt.parse_failed", message: "Invalid PSBT" },
          },
    );
    const context = executionContext(
      new Map([
        ["rust-bitcoin", rejecting(rustImplementation)],
        ["btcsuite-go", go],
        ["bitcoinjs-lib", rejecting(bitcoinjsImplementation)],
        ["bdkpython", rejecting(bdkImplementation)],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createInvalidInputScenario(inputFixture)],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: expect.arrayContaining([
        expect.objectContaining({ name: "btcsuite-go-unsupported-psbt-v2", passed: false }),
      ]),
    });
  });
});

describe("unknown and proprietary metadata preservation", () => {
  test("preserves global, input, and output extension fields through parsing, signing, and combining", async () => {
    const initial = encodedPsbt([[]]);
    const metadataFixture = fixture("p2wsh-2-of-3", initial, 1);
    const enriched = enrichPsbtWithExtensionFields(metadataFixture);
    const scalar1Signed = appendFirstInputEntry(enriched, signedInput());
    const scalar2Signed = appendFirstInputEntry(enriched, signedInput2());
    const combined = appendFirstInputEntry(scalar1Signed, signedInput2());
    const implementations = [
      rustImplementation,
      goImplementation,
      bitcoinjsImplementation,
      bdkImplementation,
    ];
    const adapters = new Map(
      implementations.map((implementation) => [
        implementation.name,
        adapter((request) => {
          if (request.operation === "sign") {
            return success(request, implementation, {
              psbt: implementation.name === "bitcoinjs-lib" ? scalar2Signed : scalar1Signed,
              signedInputs: 1,
            });
          }
          if (request.operation === "combine") {
            return success(request, implementation, { psbt: combined, combinedCount: 2 });
          }
          return success(request, implementation, { psbt: String(request.payload["psbt"]) });
        }),
      ]),
    );
    const context = executionContext(adapters);

    const [result] = await runScenarioCatalog(
      [createMetadataPreservationScenario(metadataFixture)],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({ id: "proprietary-metadata-preservation", outcome: "passed" });
    expect(enriched).not.toBe(initial);
    expect(verifyInjectedExtensionFields(enriched, metadataFixture)).toMatchObject({
      name: "valid-extension-fields-in-every-map",
      passed: true,
    });
    expect(verifyInjectedProprietaryFields(enriched, metadataFixture)).toMatchObject({
      name: "valid-proprietary-field-in-every-map",
      passed: true,
    });
    expect(result?.assertions[0]).toMatchObject({
      name: "valid-extension-fields-in-every-map",
      passed: true,
    });
    expect(result?.assertions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "rust-bitcoin-preserved-metadata-while-signing" }),
        expect.objectContaining({ name: "btcsuite-go-preserved-metadata-while-signing" }),
        expect.objectContaining({ name: "bitcoinjs-lib-preserved-metadata-while-signing" }),
        expect.objectContaining({ name: "combined-exact-field-union", passed: true }),
        expect.objectContaining({ name: "combined-preserved-extension-fields", passed: true }),
        expect.objectContaining({ name: "core-policy-accepted", passed: true }),
      ]),
    );
  });

  test("fails at the exact adapter that drops extension fields", async () => {
    const initial = encodedPsbt([[]]);
    const preserve = (implementation: AdapterImplementation) =>
      adapter((request) =>
        success(request, implementation, { psbt: String(request.payload["psbt"]) }),
      );
    const droppingGo = adapter((request) => success(request, goImplementation, { psbt: initial }));
    const context = executionContext(
      new Map([
        ["rust-bitcoin", preserve(rustImplementation)],
        ["btcsuite-go", droppingGo],
        ["bitcoinjs-lib", preserve(bitcoinjsImplementation)],
        ["bdkpython", preserve(bdkImplementation)],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createMetadataPreservationScenario(fixture("p2wsh-2-of-3", initial, 1))],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [
        {
          name: "btcsuite-go-preserved-extension-fields",
          passed: false,
          failures: expect.arrayContaining([expect.objectContaining({ code: "ENTRY_REMOVED" })]),
        },
      ],
    });
  });

  test("fails when a signer drops unknown and proprietary metadata", async () => {
    const initial = encodedPsbt([[]]);
    const metadataFixture = fixture("p2wsh-2-of-3", initial, 1);
    const enriched = enrichPsbtWithExtensionFields(metadataFixture);
    const preservedSigned = appendFirstInputEntry(enriched, signedInput2());
    const droppedSigned = encodedPsbt([[signedInput()]]);
    const preserve = (implementation: AdapterImplementation) =>
      adapter((request) => {
        if (request.operation === "sign") {
          return success(request, implementation, {
            psbt: implementation.name === "rust-bitcoin" ? droppedSigned : preservedSigned,
          });
        }
        return success(request, implementation, { psbt: String(request.payload["psbt"]) });
      });
    const context = executionContext(
      new Map([
        ["rust-bitcoin", preserve(rustImplementation)],
        ["btcsuite-go", preserve(goImplementation)],
        ["bitcoinjs-lib", preserve(bitcoinjsImplementation)],
        ["bdkpython", preserve(bdkImplementation)],
      ]),
    );

    const [result] = await runScenarioCatalog(
      [createMetadataPreservationScenario(metadataFixture)],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [
        {
          name: "rust-bitcoin-preserved-metadata-while-signing",
          passed: false,
          failures: expect.arrayContaining([
            expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0x50 }),
            expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0xfc }),
          ]),
        },
      ],
    });
  });

  test("fails when Core finalization drops unknown and proprietary metadata", async () => {
    const initial = encodedPsbt([[]]);
    const metadataFixture = fixture("p2wsh-2-of-3", initial, 1);
    const enriched = enrichPsbtWithExtensionFields(metadataFixture);
    const scalar1Signed = appendFirstInputEntry(enriched, signedInput());
    const scalar2Signed = appendFirstInputEntry(enriched, signedInput2());
    const combined = appendFirstInputEntry(scalar1Signed, signedInput2());
    const droppedByCore = encodedPsbt([[signedInput(), signedInput2()]]);
    const adapters = new Map(
      [rustImplementation, goImplementation, bitcoinjsImplementation, bdkImplementation].map(
        (implementation) => [
          implementation.name,
          adapter((request) => {
            if (request.operation === "sign") {
              return success(request, implementation, {
                psbt: implementation.name === "bitcoinjs-lib" ? scalar2Signed : scalar1Signed,
              });
            }
            if (request.operation === "combine") {
              return success(request, implementation, { psbt: combined, combinedCount: 2 });
            }
            return success(request, implementation, { psbt: String(request.payload["psbt"]) });
          }),
        ],
      ),
    );
    const rpcCall = vi.fn().mockResolvedValue({ complete: true, psbt: droppedByCore });
    const context = executionContext(adapters, rpcCall);

    const [result] = await runScenarioCatalog(
      [createMetadataPreservationScenario(metadataFixture)],
      context,
      new Map([
        ["rust-bitcoin", rustNegotiated],
        ["btcsuite-go", goNegotiated],
        ["bitcoinjs-lib", bitcoinjsNegotiated],
        ["bdkpython", bdkNegotiated],
      ]),
    );

    expect(result).toMatchObject({
      outcome: "failed",
      assertions: [
        {
          name: "core-preserved-metadata-during-finalization",
          passed: false,
          failures: expect.arrayContaining([
            expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0x50 }),
            expect.objectContaining({ code: "ENTRY_REMOVED", keyType: 0xfc }),
          ]),
        },
      ],
    });
  });
});
