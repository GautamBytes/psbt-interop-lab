import { describe, expect, test } from "vitest";
import { FIXTURE_DESCRIPTORS, FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import {
  btcToSats,
  prepareFixtures,
  type RpcCaller,
  satsToBtcString,
} from "../../src/core/fixtures.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";

const COINBASE_SATS = 5_000_000_000;
const TXIDS = {
  single1: "11".repeat(32),
  single2: "22".repeat(32),
  single3: "33".repeat(32),
  single4: "44".repeat(32),
  wpkh1: "55".repeat(32),
  wpkh2: "66".repeat(32),
  multisig: "77".repeat(32),
  tr1: "88".repeat(32),
  tr2: "99".repeat(32),
} as const;

const SINGLE_KEY_WITNESS_SCRIPT = `21${FIXTURE_PUBLIC_KEYS.scalar1}ac`;
const MULTISIG_WITNESS_SCRIPT =
  `5221${FIXTURE_PUBLIC_KEYS.scalar1}21${FIXTURE_PUBLIC_KEYS.scalar2}` +
  `21${FIXTURE_PUBLIC_KEYS.scalar3}53ae`;
const FIXTURE_ADDRESSES = {
  [FIXTURE_DESCRIPTORS.p2wpkh]: "bcrt1qfixturep2wpkh",
  [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]: "bcrt1qfixturesingle",
  [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]: "bcrt1qfixturemultisig",
  [FIXTURE_DESCRIPTORS["p2tr-keypath"]]: "bcrt1pfixturetaproot",
} as const;
const FIXTURE_SCRIPT_PUBKEYS = {
  [FIXTURE_DESCRIPTORS.p2wpkh]: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
  [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]:
    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
  [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]:
    "002012c2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c572",
  [FIXTURE_DESCRIPTORS["p2tr-keypath"]]:
    "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
} as const;

function fixtureScriptPubKey(descriptor: string): string {
  const scriptPubKey = FIXTURE_SCRIPT_PUBKEYS[descriptor as keyof typeof FIXTURE_SCRIPT_PUBKEYS];
  if (!scriptPubKey) throw new Error("Unknown fixture script descriptor");
  return scriptPubKey;
}

interface CreatedPsbt {
  inputs: Array<{ txid: string; vout: number }>;
  outputSats: number;
  outputScriptPubKey: string;
  descriptors: string[];
}

interface FakeRpcOptions {
  chain?: string;
  connections?: number;
  malformedScan?: boolean;
  malformedUpdatedPsbt?: boolean;
  emptyUtxos?: boolean;
  guardConcurrentScans?: boolean;
  wrongWitnessUtxoScript?: boolean;
  wrongOutputScript?: boolean;
  wrongWitnessScript?: "single-key" | "multisig";
}

function paramObject(
  params: Record<string, unknown> | unknown[] | undefined,
): Record<string, unknown> {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("Expected object RPC parameters");
  }
  return params;
}

function encodeCompactSize(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value >= 253) {
    throw new Error("Test compact size is out of range");
  }
  return Buffer.from([value]);
}

function encodeUint32(value: number): Buffer {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32LE(value);
  return encoded;
}

function encodeUint64(value: number): Buffer {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64LE(BigInt(value));
  return encoded;
}

function mutateHex(value: string): string {
  return `${value.slice(0, -2)}${value.endsWith("00") ? "01" : "00"}`;
}

function semanticUnsignedTxSha256(psbt: string): string {
  const document = parsePsbtDocument(psbt);
  const globalMap = document.maps.find((map) => map.location.kind === "global");
  const unsignedTransaction = globalMap?.entries.find(
    (entry) => entry.keyType === 0 && entry.keyData.byteLength === 0,
  );
  if (!unsignedTransaction) throw new Error("Test PSBT has no global unsigned transaction");
  return `sha256:${unsignedTransaction.valueSha256}`;
}

function makePsbt(
  inputs: Array<{ txid: string; vout: number }>,
  outputSats: number,
  outputScriptPubKey: string,
): string {
  const outputScript = Buffer.from(outputScriptPubKey, "hex");
  const unsignedTransaction = Buffer.concat([
    encodeUint32(2),
    encodeCompactSize(inputs.length),
    ...inputs.flatMap((input) => [
      Buffer.from(input.txid, "hex").reverse(),
      encodeUint32(input.vout),
      Buffer.from([0]),
      encodeUint32(0xffff_fffd),
    ]),
    Buffer.from([1]),
    encodeUint64(outputSats),
    encodeCompactSize(outputScript.byteLength),
    outputScript,
    Buffer.alloc(4),
  ]);
  return Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    Buffer.from([1, 0]),
    encodeCompactSize(unsignedTransaction.length),
    unsignedTransaction,
    Buffer.from([0]),
    ...inputs.map(() => Buffer.from([0])),
    Buffer.from([0]),
  ]).toString("base64");
}

function createFixtureRpc(options: FakeRpcOptions = {}): {
  rpc: RpcCaller;
  calls: Array<{ method: string; params: Record<string, unknown> | unknown[] | undefined }>;
  maxConcurrentScans: () => number;
} {
  const calls: Array<{ method: string; params: Record<string, unknown> | unknown[] | undefined }> =
    [];
  let blocks = 500;
  let generatedCounter = 1;
  let activeScans = 0;
  let maxConcurrentScans = 0;
  const addresses = FIXTURE_ADDRESSES;
  const unspents = {
    [FIXTURE_DESCRIPTORS.p2wpkh]: [
      { txid: TXIDS.wpkh2, vout: 0, amount: "50.00000000", height: 6 },
      { txid: TXIDS.wpkh1, vout: 0, amount: "50.00000000", height: 5 },
    ],
    [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]: [
      { txid: TXIDS.single4, vout: 0, amount: "50.00000000", height: 4 },
      { txid: TXIDS.single2, vout: 0, amount: "50.00000000", height: 2 },
      { txid: TXIDS.single1, vout: 0, amount: "50.00000000", height: 1 },
      { txid: TXIDS.single3, vout: 0, amount: "50.00000000", height: 3 },
    ],
    [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]: [
      { txid: TXIDS.multisig, vout: 0, amount: "50.00000000", height: 7 },
    ],
    [FIXTURE_DESCRIPTORS["p2tr-keypath"]]: [
      { txid: TXIDS.tr2, vout: 0, amount: "50.00000000", height: 9 },
      { txid: TXIDS.tr1, vout: 0, amount: "50.00000000", height: 8 },
    ],
  };
  if (options.emptyUtxos) {
    for (const entries of Object.values(unspents)) entries.splice(0);
  }
  const descriptorForOutpoint = new Map<string, string>();
  for (const [descriptor, entries] of Object.entries(unspents)) {
    for (const entry of entries)
      descriptorForOutpoint.set(`${entry.txid}:${entry.vout}`, descriptor);
  }
  const created = new Map<string, CreatedPsbt>();

  const rpc: RpcCaller = {
    async call<T>(method: string, params?: Record<string, unknown> | unknown[]): Promise<T> {
      calls.push({ method, params });
      if (method === "getblockchaininfo") return { chain: options.chain ?? "regtest", blocks } as T;
      if (method === "getnetworkinfo") {
        return {
          version: 310100,
          subversion: "/Satoshi:31.1.0/",
          connections: options.connections ?? 0,
        } as T;
      }
      if (method === "getdescriptorinfo") {
        const descriptor = paramObject(params)["descriptor"];
        if (typeof descriptor !== "string" || !(descriptor in addresses))
          throw new Error("Unknown descriptor");
        return { descriptor, isrange: false } as T;
      }
      if (method === "deriveaddresses") {
        const descriptor = paramObject(params)["descriptor"];
        if (typeof descriptor !== "string" || !(descriptor in addresses))
          throw new Error("Unknown descriptor");
        return [addresses[descriptor as keyof typeof addresses]] as T;
      }
      if (method === "validateaddress") {
        const address = paramObject(params)["address"];
        const descriptor = Object.entries(addresses).find(
          ([, candidate]) => candidate === address,
        )?.[0] as keyof typeof FIXTURE_SCRIPT_PUBKEYS | undefined;
        if (!descriptor || typeof address !== "string") throw new Error("Unknown address");
        return {
          isvalid: true,
          address,
          scriptPubKey: FIXTURE_SCRIPT_PUBKEYS[descriptor],
          iswitness: true,
          witness_version: descriptor === FIXTURE_DESCRIPTORS["p2tr-keypath"] ? 1 : 0,
        } as T;
      }
      if (method === "scantxoutset") {
        activeScans += 1;
        maxConcurrentScans = Math.max(maxConcurrentScans, activeScans);
        try {
          await Promise.resolve();
          if (options.guardConcurrentScans && activeScans > 1) {
            throw new Error("scantxoutset scan already in progress");
          }
          if (options.malformedScan) return { success: false, unspents: [] } as T;
          const scanobjects = paramObject(params)["scanobjects"];
          if (
            !Array.isArray(scanobjects) ||
            scanobjects.length !== 1 ||
            typeof scanobjects[0] !== "string"
          ) {
            throw new Error("Invalid scan request");
          }
          return {
            success: true,
            unspents: unspents[scanobjects[0] as keyof typeof unspents] ?? [],
          } as T;
        } finally {
          activeScans -= 1;
        }
      }
      if (method === "generatetoaddress") {
        const request = paramObject(params);
        const count = request["nblocks"];
        const address = request["address"];
        const descriptor = Object.entries(addresses).find(
          ([, candidate]) => candidate === address,
        )?.[0];
        if (
          !Number.isSafeInteger(count) ||
          (count as number) <= 0 ||
          typeof descriptor !== "string"
        ) {
          throw new Error("Invalid generatetoaddress request");
        }
        const descriptorUnspents = unspents[descriptor as keyof typeof unspents];
        if (!descriptorUnspents) throw new Error("Unknown fixture mining descriptor");
        const hashes = [];
        for (let index = 0; index < (count as number); index += 1) {
          blocks += 1;
          const txid = generatedCounter.toString(16).padStart(64, "0");
          generatedCounter += 1;
          descriptorUnspents.push({ txid, vout: 0, amount: "50.00000000", height: blocks });
          descriptorForOutpoint.set(`${txid}:0`, descriptor);
          hashes.push((blocks + 10_000).toString(16).padStart(64, "0"));
        }
        return hashes as T;
      }
      if (method === "createpsbt") {
        const request = paramObject(params);
        const inputs = request["inputs"];
        const outputs = request["outputs"];
        if (
          !Array.isArray(inputs) ||
          !Array.isArray(outputs) ||
          outputs.length !== 1 ||
          request["version"] !== 2 ||
          "psbt_version" in request
        ) {
          throw new Error("Invalid createpsbt request");
        }
        const fixtureInputs = inputs.map((rawInput) => {
          const input = paramObject(rawInput as Record<string, unknown>);
          if (typeof input["txid"] !== "string" || !Number.isSafeInteger(input["vout"])) {
            throw new Error("Invalid fixture input");
          }
          return { txid: input["txid"], vout: input["vout"] as number };
        });
        const output = paramObject(outputs[0] as Record<string, unknown>);
        const outputEntry = Object.entries(output)[0];
        const outputAddress = outputEntry?.[0];
        const outputAmount = outputEntry?.[1];
        const outputDescriptor = Object.entries(addresses).find(
          ([, address]) => address === outputAddress,
        )?.[0];
        if (typeof outputDescriptor !== "string" || typeof outputAmount !== "string") {
          throw new Error("Invalid fixture output");
        }
        const outputSats = Number(BigInt(outputAmount.replace(".", "").padEnd(8, "0")));
        const outputScriptPubKey = fixtureScriptPubKey(outputDescriptor);
        const psbt = makePsbt(fixtureInputs, outputSats, outputScriptPubKey);
        created.set(psbt, {
          inputs: fixtureInputs,
          outputSats,
          outputScriptPubKey,
          descriptors: [],
        });
        return psbt as T;
      }
      if (method === "utxoupdatepsbt") {
        const request = paramObject(params);
        const psbt = request["psbt"];
        const descriptors = request["descriptors"];
        if (typeof psbt !== "string" || !Array.isArray(descriptors) || !created.has(psbt)) {
          throw new Error("Invalid utxoupdatepsbt request");
        }
        const fixture = created.get(psbt);
        if (!fixture || descriptors.some((descriptor) => typeof descriptor !== "string")) {
          throw new Error("Invalid fixture descriptors");
        }
        fixture.descriptors = [...descriptors] as string[];
        return (options.malformedUpdatedPsbt ? "not-a-psbt" : psbt) as T;
      }
      if (method === "decodepsbt") {
        const psbt = paramObject(params)["psbt"];
        if (typeof psbt !== "string") throw new Error("Invalid decodepsbt request");
        const fixture = created.get(psbt);
        if (!fixture) throw new Error("Unknown PSBT");
        const inputSats = fixture.inputs.length * COINBASE_SATS;
        return {
          tx: {
            txid: "ab".repeat(32),
            vin: fixture.inputs,
            vout: [
              {
                value: satsToBtcString(fixture.outputSats),
                scriptPubKey: {
                  hex: options.wrongOutputScript
                    ? mutateHex(fixture.outputScriptPubKey)
                    : fixture.outputScriptPubKey,
                },
              },
            ],
          },
          inputs: fixture.inputs.map((input) => {
            const descriptor = descriptorForOutpoint.get(`${input.txid}:${input.vout}`);
            if (!descriptor) throw new Error("Unknown fixture outpoint");
            const inputScriptPubKey = fixtureScriptPubKey(descriptor);
            const witnessScript =
              descriptor === FIXTURE_DESCRIPTORS["p2wsh-single-key"]
                ? SINGLE_KEY_WITNESS_SCRIPT
                : descriptor === FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]
                  ? MULTISIG_WITNESS_SCRIPT
                  : undefined;
            const shouldMutateWitnessScript =
              (options.wrongWitnessScript === "single-key" &&
                descriptor === FIXTURE_DESCRIPTORS["p2wsh-single-key"]) ||
              (options.wrongWitnessScript === "multisig" &&
                descriptor === FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]);
            return {
              witness_utxo: {
                amount: "50.00000000",
                scriptPubKey: {
                  hex: options.wrongWitnessUtxoScript
                    ? mutateHex(inputScriptPubKey)
                    : inputScriptPubKey,
                },
              },
              ...(witnessScript
                ? {
                    witness_script: {
                      hex: shouldMutateWitnessScript ? mutateHex(witnessScript) : witnessScript,
                    },
                  }
                : {}),
              ...(descriptor.startsWith("tr(")
                ? { taproot_internal_key: FIXTURE_PUBLIC_KEYS.scalar1.slice(2) }
                : {}),
            };
          }),
          fee: satsToBtcString(inputSats - fixture.outputSats),
        } as T;
      }
      throw new Error(`Unexpected RPC ${method}`);
    },
  };
  return { rpc, calls, maxConcurrentScans: () => maxConcurrentScans };
}

describe("Bitcoin amount conversion", () => {
  test.each([
    ["0.00000001", 1],
    ["1.00000000", 100_000_000],
    [50, 5_000_000_000],
  ])("converts BTC to integer sats", (value, sats) => {
    expect(btcToSats(value)).toBe(sats);
  });

  test("formats integer sats without floating-point output", () => {
    expect(satsToBtcString(4_999_999_000)).toBe("49.99999000");
  });

  test.each(["0.000000001", -1, Number.NaN])("rejects invalid Bitcoin amounts", (value) => {
    expect(() => btcToSats(value)).toThrow(/amount/i);
  });
});

describe("prepareFixtures", () => {
  test("refuses to operate on a non-regtest chain", async () => {
    const rpc: RpcCaller = {
      async call<T>(method: string): Promise<T> {
        expect(method).toBe("getblockchaininfo");
        return { chain: "main", blocks: 800_000 } as T;
      },
    };

    await expect(prepareFixtures(rpc)).rejects.toThrow(/regtest/i);
  });

  test("refuses an unexpected Bitcoin Core version", async () => {
    const rpc: RpcCaller = {
      async call<T>(method: string): Promise<T> {
        if (method === "getblockchaininfo") return { chain: "regtest", blocks: 103 } as T;
        if (method === "getnetworkinfo") {
          return { version: 310000, subversion: "/Satoshi:31.0.0/", connections: 0 } as T;
        }
        throw new Error(`Unexpected RPC ${method}`);
      },
    };

    await expect(prepareFixtures(rpc)).rejects.toThrow(/Core 31\.1/i);
  });

  test("refuses a Core node with peers before touching descriptors or funds", async () => {
    const { rpc, calls } = createFixtureRpc({ connections: 1 });

    await expect(prepareFixtures(rpc)).rejects.toThrow(/zero peer connections/i);
    expect(calls.map((call) => call.method)).toEqual(["getblockchaininfo", "getnetworkinfo"]);
  });

  test("serializes scantxoutset starts because Core permits only one active scan", async () => {
    const { rpc, maxConcurrentScans } = createFixtureRpc({ guardConcurrentScans: true });

    await prepareFixtures(rpc);

    expect(maxConcurrentScans()).toBe(1);
  });

  test("uses Core 31.1 transaction version 2 and verifies the returned PSBTv0", async () => {
    const { rpc, calls } = createFixtureRpc();

    await prepareFixtures(rpc);

    const versions = calls
      .filter((call) => call.method === "createpsbt")
      .map((call) => {
        const request = paramObject(call.params);
        return { version: request["version"], psbtVersion: request["psbt_version"] };
      });
    expect(versions).toHaveLength(7);
    expect(versions).toEqual(
      Array.from({ length: 7 }, () => ({ version: 2, psbtVersion: undefined })),
    );
  });

  test("obtains every expected descriptor script from validateaddress", async () => {
    const { rpc, calls } = createFixtureRpc();

    await prepareFixtures(rpc);

    expect(
      calls
        .filter((call) => call.method === "validateaddress")
        .map((call) => paramObject(call.params)["address"]),
    ).toEqual(Object.values(FIXTURE_ADDRESSES));
  });

  test("commits to the exact PSBTv0 global unsigned transaction bytes", async () => {
    const fixtures = await prepareFixtures(createFixtureRpc().rpc);

    for (const fixture of [
      fixtures.happy,
      fixtures.regression,
      ...Object.values(fixtures.profiles),
    ]) {
      expect(fixture.unsignedTxSha256).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(fixture.unsignedTxSha256).toBe(semanticUnsignedTxSha256(fixture.initialPsbt));
    }
  });

  test("builds deterministic multi-profile fixtures with exact fees and signing descriptors", async () => {
    const { rpc, calls } = createFixtureRpc();

    const fixtures = await prepareFixtures(rpc);

    expect(fixtures.happy.id).toBe("happy-path");
    expect(fixtures.regression.id).toBe("bdk-finalize-regression");
    expect(fixtures.happy.outpoints.map((outpoint) => outpoint.txid)).toEqual([TXIDS.single1]);
    expect(fixtures.regression.outpoints.map((outpoint) => outpoint.txid)).toEqual([
      TXIDS.single2,
      TXIDS.single3,
    ]);
    expect(
      fixtures.profiles["p2wsh-single-key"].outpoints.map((outpoint) => outpoint.txid),
    ).toEqual([TXIDS.single4]);
    expect(fixtures.profiles["mixed-p2wpkh-p2tr"]).toMatchObject({
      id: "mixed-p2wpkh-p2tr",
      scriptTypes: ["p2wpkh", "p2tr-keypath"],
      inputCount: 2,
      outputCount: 1,
      feeSats: 25_000,
      inputDescriptors: [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
      psbtVersion: 0,
      transactionId: "ab".repeat(32),
    });
    expect(fixtures.profiles["p2wpkh"]).toMatchObject({
      feeSats: 11_000,
      inputCount: 1,
      outputCount: 1,
      scriptTypes: ["p2wpkh"],
    });
    expect(fixtures.profiles["p2wsh-2-of-3"]).toMatchObject({
      feeSats: 13_000,
      scriptTypes: ["p2wsh"],
    });
    expect(fixtures.profiles["p2tr-keypath"]).toMatchObject({
      feeSats: 14_000,
      scriptTypes: ["p2tr-keypath"],
    });
    expect(
      calls
        .filter((call) => call.method === "utxoupdatepsbt")
        .map((call) => paramObject(call.params)["descriptors"]),
    ).toEqual([
      [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
      [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
      [FIXTURE_DESCRIPTORS.p2wpkh],
      [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
      [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]],
      [FIXTURE_DESCRIPTORS["p2tr-keypath"]],
      [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    ]);
    expect(calls.some((call) => call.method === "generatetoaddress")).toBe(false);
    expect(calls.some((call) => /broadcast|sendrawtransaction/i.test(call.method))).toBe(false);
  });

  test("funds only the missing descriptor UTXOs, then matures them in one bounded pass", async () => {
    const { rpc, calls } = createFixtureRpc({ emptyUtxos: true });

    const fixtures = await prepareFixtures(rpc);

    expect(
      calls
        .filter((call) => call.method === "generatetoaddress")
        .map((call) => paramObject(call.params)["nblocks"]),
    ).toEqual([2, 4, 1, 2, 100]);
    expect(fixtures.core.blocks).toBe(609);
    for (const fixture of [
      fixtures.happy,
      fixtures.regression,
      ...Object.values(fixtures.profiles),
    ]) {
      expect(
        fixture.outpoints.every((outpoint) => outpoint.height <= fixtures.core.blocks - 100),
      ).toBe(true);
    }
  });

  test.each([
    ["witness UTXO script", { wrongWitnessUtxoScript: true }, /witness UTXO script/i],
    ["decoded output script", { wrongOutputScript: true }, /output script/i],
    [
      "single-key witness script",
      { wrongWitnessScript: "single-key" },
      /witness script does not match/i,
    ],
    [
      "multisig witness script",
      { wrongWitnessScript: "multisig" },
      /witness script does not match/i,
    ],
  ] as const)("rejects a wrong %s", async (_label, options, expectedError) => {
    await expect(prepareFixtures(createFixtureRpc(options).rpc)).rejects.toThrow(expectedError);
  });

  test("rejects malformed scan and PSBT RPC responses", async () => {
    await expect(prepareFixtures(createFixtureRpc({ malformedScan: true }).rpc)).rejects.toThrow(
      /scantxoutset/i,
    );
    await expect(
      prepareFixtures(createFixtureRpc({ malformedUpdatedPsbt: true }).rpc),
    ).rejects.toThrow(/PSBT/i);
  });
});
