import { describe, expect, test } from "vitest";
import { FIXTURE_DESCRIPTORS, FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import {
  btcToSats,
  prepareFixtures,
  type RpcCaller,
  satsToBtcString,
} from "../../src/core/fixtures.js";

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

interface CreatedPsbt {
  inputs: Array<{ txid: string; vout: number }>;
  outputSats: number;
  descriptors: string[];
}

interface FakeRpcOptions {
  chain?: string;
  connections?: number;
  malformedScan?: boolean;
  malformedUpdatedPsbt?: boolean;
  emptyUtxos?: boolean;
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

function makePsbt(inputs: Array<{ txid: string; vout: number }>, outputSats: number): string {
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
    Buffer.from("1600140000000000000000000000000000000000000000", "hex"),
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
} {
  const calls: Array<{ method: string; params: Record<string, unknown> | unknown[] | undefined }> =
    [];
  let blocks = 500;
  let generatedCounter = 1;
  const addresses = {
    [FIXTURE_DESCRIPTORS.p2wpkh]: "bcrt1qfixturep2wpkh",
    [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]: "bcrt1qfixturesingle",
    [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]: "bcrt1qfixturemultisig",
    [FIXTURE_DESCRIPTORS["p2tr-keypath"]]: "bcrt1pfixturetaproot",
  };
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
      if (method === "scantxoutset") {
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
        if (!Array.isArray(inputs) || !Array.isArray(outputs) || outputs.length !== 1) {
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
        const outputAmount = Object.values(output)[0];
        if (typeof outputAmount !== "string") throw new Error("Invalid fixture output");
        const outputSats = Number(BigInt(outputAmount.replace(".", "").padEnd(8, "0")));
        const psbt = makePsbt(fixtureInputs, outputSats);
        created.set(psbt, { inputs: fixtureInputs, outputSats, descriptors: [] });
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
            vout: [{ value: satsToBtcString(fixture.outputSats) }],
          },
          inputs: fixture.inputs.map((input) => {
            const descriptor = descriptorForOutpoint.get(`${input.txid}:${input.vout}`);
            if (!descriptor) throw new Error("Unknown fixture outpoint");
            return {
              witness_utxo: { amount: "50.00000000", scriptPubKey: "0014" },
              ...(descriptor.startsWith("wsh(") ? { witness_script: "51" } : {}),
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
  return { rpc, calls };
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

  test("rejects malformed scan and PSBT RPC responses", async () => {
    await expect(prepareFixtures(createFixtureRpc({ malformedScan: true }).rpc)).rejects.toThrow(
      /scantxoutset/i,
    );
    await expect(
      prepareFixtures(createFixtureRpc({ malformedUpdatedPsbt: true }).rpc),
    ).rejects.toThrow(/PSBT/i);
  });
});
