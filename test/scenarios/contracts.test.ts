import { describe, expect, test } from "vitest";
import type {
  AdapterImplementation,
  AdapterResponse,
  JsonValue,
} from "../../src/protocol/types.js";
import * as adapterContracts from "../../src/scenarios/contracts.js";
import {
  assertAdapterHello,
  assertByteIdenticalRoundtrip,
  BDK_CURRENT_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  type ExpectedAdapterContract,
  GO_ADAPTER_CONTRACT,
  HWI_SIMULATOR_ADAPTER_CONTRACT,
  MUSIG2_SIGNER_ONE_ADAPTER_CONTRACT,
  MUSIG2_SIGNER_TWO_ADAPTER_CONTRACT,
  PSBTV2_ADAPTER_CONTRACT,
  RUST_ADAPTER_CONTRACT,
} from "../../src/scenarios/contracts.js";

function operationScriptTypes(contract: ExpectedAdapterContract): Record<string, JsonValue> {
  return Object.fromEntries(
    Object.entries(contract.operationScriptTypes).map(([operation, scriptTypes]) => [
      operation,
      [...scriptTypes],
    ]),
  );
}

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const IMPLEMENTATION: AdapterImplementation = {
  name: "rust-bitcoin",
  version: "0.1.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
  sourceRevision: "bitcoin-crate-0.32.102",
};

function success(
  output: Record<string, JsonValue>,
  implementation: AdapterImplementation = IMPLEMENTATION,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.2",
    id: "request-1",
    status: "ok",
    implementation,
    output,
  };
}

function hello(
  implementation: Partial<AdapterImplementation> = {},
  output: Record<string, JsonValue> = {
    operations: [...RUST_ADAPTER_CONTRACT.operations],
    roles: [...RUST_ADAPTER_CONTRACT.roles],
    psbtVersions: [0],
    scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
    operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
    features: [...RUST_ADAPTER_CONTRACT.features],
  },
): AdapterResponse {
  return success(output, { ...IMPLEMENTATION, ...implementation });
}

describe("adapter contracts", () => {
  test.each([RUST_ADAPTER_CONTRACT, GO_ADAPTER_CONTRACT, BITCOINJS_ADAPTER_CONTRACT])(
    "$name declares modern SegWit and Taproot profile support",
    (contract) => {
      expect(contract.scriptTypes).toEqual(
        expect.arrayContaining([
          "p2wpkh",
          "p2sh-p2wpkh",
          "p2wsh",
          "p2tr-keypath",
          "p2tr-scriptpath",
        ]),
      );
    },
  );

  test("pins the native PSBTv2 workflow adapter without claiming unavailable conversion", () => {
    expect(PSBTV2_ADAPTER_CONTRACT).toMatchObject({
      name: "rust-psbt-v2",
      psbtVersions: [2],
      operations: [
        "hello",
        "native-parse",
        "inspect",
        "roundtrip",
        "sign",
        "combine",
        "finalize",
        "extract",
        "construct",
      ],
      roles: ["parser", "updater", "signer", "combiner", "finalizer", "extractor", "constructor"],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      },
    });
    expect(PSBTV2_ADAPTER_CONTRACT.operations).not.toContain("convert");
  });

  test("pins libwally 1.5.4 as the independent converting PSBTv2 implementation", () => {
    const contract = Reflect.get(adapterContracts, "LIBWALLY_ADAPTER_CONTRACT");

    expect(contract).toMatchObject({
      name: "libwally-core",
      version: "1.5.4",
      sourceRevision: "libwally-core-release_1.5.4@c5591834b3ae4ee4c7db9e537a9c19104ab4bf0c",
      psbtVersions: [0, 2],
      operations: [
        "hello",
        "native-parse",
        "inspect",
        "roundtrip",
        "sign",
        "combine",
        "finalize",
        "extract",
        "convert",
      ],
      roles: ["parser", "signer", "combiner", "finalizer", "extractor"],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      operationScriptTypes: {
        convert: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      },
    });
  });

  test("pins the current BDK wallet implementation independently of the regression specimen", () => {
    expect(BDK_CURRENT_ADAPTER_CONTRACT).toMatchObject({
      name: "bdk-wallet-current",
      version: "3.1.0",
      psbtVersions: [0],
      scriptTypes: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      operationScriptTypes: {
        sign: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
        finalize: ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      },
    });
  });

  test("declares native Taproot script-path signing and finalization in rust-bitcoin", () => {
    expect(RUST_ADAPTER_CONTRACT.operationScriptTypes).toMatchObject({
      sign: ["p2pkh", "p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      "finalize-inputs": ["p2wsh", "p2tr-scriptpath"],
    });
  });

  test.each([
    [MUSIG2_SIGNER_ONE_ADAPTER_CONTRACT, "musig2-crate-0.4.1+bitcoin-0.32.102"],
    [MUSIG2_SIGNER_TWO_ADAPTER_CONTRACT, "@scure/btc-signer@2.2.0+bitcoinjs-lib@7.0.1"],
  ] as const)("$name pins the explicit BIP373 signing phases", (contract, sourceRevision) => {
    expect(contract).toMatchObject({
      version: "0.1.0",
      sourceRevision,
      operations: [
        "hello",
        "native-parse",
        "roundtrip",
        "musig2-nonce",
        "musig2-partial-sign",
        "musig2-aggregate",
      ],
      roles: ["parser", "updater", "signer", "combiner", "finalizer"],
      scriptTypes: ["p2tr-keypath"],
    });
    expect(contract.features).toContain("bip327-csprng-nonce-v1");
  });

  test("uses independent MuSig2 libraries for the two signer contracts", () => {
    expect(MUSIG2_SIGNER_ONE_ADAPTER_CONTRACT.name).toBe("musig2-rust-signer-1");
    expect(MUSIG2_SIGNER_TWO_ADAPTER_CONTRACT.name).toBe("musig2-scure-signer-2");
    expect(MUSIG2_SIGNER_TWO_ADAPTER_CONTRACT.sourceRevision).not.toBe(
      MUSIG2_SIGNER_ONE_ADAPTER_CONTRACT.sourceRevision,
    );
  });

  test("pins the HWI-compatible simulator without claiming physical hardware", () => {
    expect(HWI_SIMULATOR_ADAPTER_CONTRACT).toMatchObject({
      name: "hwi-simulator",
      version: "0.1.0",
      sourceRevision: "hwi-json-contract-v1+bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4",
      operations: ["hello", "native-parse", "roundtrip", "sign"],
      roles: ["parser", "signer"],
      psbtVersions: [0],
      scriptTypes: ["p2wpkh"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh"],
        sign: ["p2wpkh"],
      },
    });
    expect(HWI_SIMULATOR_ADAPTER_CONTRACT.features).toEqual(
      expect.arrayContaining([
        "hwi-json-process-v1",
        "hwi-simulator-v1",
        "simulated-user-confirmation-v1",
      ]),
    );
  });

  test("rejects a lying byte-identical response", () => {
    const source = MINIMAL_PSBT;
    const changedBytes = Buffer.from(source, "base64");
    changedBytes[8] = changedBytes[8] === 1 ? 2 : 1;
    const changed = changedBytes.toString("base64");
    const response = success({ psbt: changed, byteIdentical: true });

    expect(() => assertByteIdenticalRoundtrip(response, source, "rust-bitcoin")).toThrow(
      /changed/i,
    );
  });

  test("returns a genuinely identical PSBT", () => {
    const response = success({ psbt: MINIMAL_PSBT, byteIdentical: true });
    expect(assertByteIdenticalRoundtrip(response, MINIMAL_PSBT, "rust-bitcoin")).toBe(MINIMAL_PSBT);
  });

  test("rejects a wrong adapter source revision", () => {
    const response = hello({ sourceRevision: "bitcoin-crate-0.32.100" });
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/source revision/i);
  });

  test("rejects a missing required operation", () => {
    const response = hello(
      {},
      {
        operations: ["hello", "roundtrip"],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [0],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
        features: [...RUST_ADAPTER_CONTRACT.features],
      },
    );
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/operation sign/i);
  });

  test("rejects an adapter without PSBTv0 support", () => {
    const response = hello(
      {},
      {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [2],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
        features: [...RUST_ADAPTER_CONTRACT.features],
      },
    );
    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/PSBTv0/i);
  });

  test.each([
    ["role", "roles", ["parser", "signer"]],
    ["script type", "scriptTypes", ["p2wpkh"]],
  ] as const)("rejects falsely declared required %s support", (_label, key, value) => {
    const response = hello(
      {},
      {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [...RUST_ADAPTER_CONTRACT.psbtVersions],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
        features: [...RUST_ADAPTER_CONTRACT.features],
        [key]: [...value],
      },
    );

    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(
      /omitted|does not support|undeclared/i,
    );
  });

  test("returns typed negotiated capabilities", () => {
    const negotiated = assertAdapterHello(hello(), RUST_ADAPTER_CONTRACT);

    expect(negotiated).toEqual({
      implementation: IMPLEMENTATION,
      capabilities: {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [...RUST_ADAPTER_CONTRACT.psbtVersions],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
        features: [...RUST_ADAPTER_CONTRACT.features],
      },
    });
  });

  test("rejects an adapter without the fixture commitment feature", () => {
    const response = hello(
      {},
      {
        operations: [...RUST_ADAPTER_CONTRACT.operations],
        roles: [...RUST_ADAPTER_CONTRACT.roles],
        psbtVersions: [...RUST_ADAPTER_CONTRACT.psbtVersions],
        scriptTypes: [...RUST_ADAPTER_CONTRACT.scriptTypes],
        operationScriptTypes: operationScriptTypes(RUST_ADAPTER_CONTRACT),
        features: [],
      },
    );

    expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(
      /feature fixture-commitment-sha256/i,
    );
  });

  test.each([GO_ADAPTER_CONTRACT, BITCOINJS_ADAPTER_CONTRACT])(
    "accepts the declared $name adapter contract",
    (contract) => {
      const implementation: AdapterImplementation = {
        name: contract.name,
        version: contract.version,
        artifactDigest: `sha256:${"b".repeat(64)}`,
        sourceRevision: contract.sourceRevision,
      };
      const response = success(
        {
          operations: [...contract.operations],
          roles: [...contract.roles],
          psbtVersions: [...contract.psbtVersions],
          scriptTypes: [...contract.scriptTypes],
          operationScriptTypes: operationScriptTypes(contract),
          features: [...contract.features],
        },
        implementation,
      );

      expect(assertAdapterHello(response, contract)).toEqual({
        implementation,
        capabilities: response.status === "ok" ? response.output : undefined,
      });
    },
  );
});
