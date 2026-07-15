import { extractWireFacts } from "../psbt/wire-facts.js";

const LAB_PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const LAB_DESCRIPTOR = `wsh(pk(${LAB_PUBLIC_KEY}))`;
const COINBASE_MATURITY_BLOCKS = 100;
const REQUIRED_FIXTURE_UTXOS = 3;

export interface RpcCaller {
  call<T>(
    method: string,
    params?: Record<string, unknown> | unknown[],
    wallet?: string,
  ): Promise<T>;
}

export interface FixtureOutpoint {
  txid: string;
  vout: number;
  amountSats: number;
  height: number;
}

export interface PsbtFixture {
  id: "happy-path" | "bdk-finalize-regression";
  initialPsbt: string;
  outpoints: FixtureOutpoint[];
  inputCount: number;
  outputCount: number;
  feeSats: number;
}

export interface PreparedFixtures {
  descriptor: string;
  address: string;
  core: {
    version: number;
    subversion: string;
    blocks: number;
    connections: number;
  };
  happy: PsbtFixture;
  regression: PsbtFixture;
}

interface BlockchainInfo {
  chain: string;
  blocks: number;
}

interface NetworkInfo {
  version: number;
  subversion: string;
  connections: number;
}

interface DescriptorInfo {
  descriptor: string;
  isrange: boolean;
}

interface ScanUnspent {
  txid: string;
  vout: number;
  amount: string | number;
  height: number;
}

interface ScanResult {
  success: boolean;
  unspents: ScanUnspent[];
}

function assertObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid object`);
  }
  return value as Record<string, unknown>;
}

function parseBlockchainInfo(value: unknown): BlockchainInfo {
  const object = assertObject(value, "getblockchaininfo");
  if (
    typeof object["chain"] !== "string" ||
    !Number.isSafeInteger(object["blocks"]) ||
    (object["blocks"] as number) < 0
  ) {
    throw new Error("getblockchaininfo returned invalid chain metadata");
  }
  return { chain: object["chain"], blocks: object["blocks"] as number };
}

function parseNetworkInfo(value: unknown): NetworkInfo {
  const object = assertObject(value, "getnetworkinfo");
  if (
    !Number.isSafeInteger(object["version"]) ||
    typeof object["subversion"] !== "string" ||
    !Number.isSafeInteger(object["connections"])
  ) {
    throw new Error("getnetworkinfo returned invalid version metadata");
  }
  return {
    version: object["version"] as number,
    subversion: object["subversion"],
    connections: object["connections"] as number,
  };
}

function parseDescriptorInfo(value: unknown): DescriptorInfo {
  const object = assertObject(value, "getdescriptorinfo");
  if (typeof object["descriptor"] !== "string" || typeof object["isrange"] !== "boolean") {
    throw new Error("getdescriptorinfo returned invalid descriptor metadata");
  }
  return {
    descriptor: object["descriptor"],
    isrange: object["isrange"],
  };
}

function parseScan(value: unknown): ScanResult {
  const object = assertObject(value, "scantxoutset");
  if (object["success"] !== true || !Array.isArray(object["unspents"])) {
    throw new Error("scantxoutset did not complete successfully");
  }
  const unspents = object["unspents"].map((item, index) => {
    const entry = assertObject(item, `scantxoutset unspent ${index}`);
    if (
      typeof entry["txid"] !== "string" ||
      !/^[0-9a-f]{64}$/.test(entry["txid"]) ||
      !Number.isSafeInteger(entry["vout"]) ||
      (entry["vout"] as number) < 0 ||
      !Number.isSafeInteger(entry["height"]) ||
      (entry["height"] as number) < 0 ||
      (typeof entry["amount"] !== "string" && typeof entry["amount"] !== "number")
    ) {
      throw new Error(`scantxoutset unspent ${index} is invalid`);
    }
    return {
      txid: entry["txid"],
      vout: entry["vout"] as number,
      amount: entry["amount"],
      height: entry["height"] as number,
    };
  });
  return { success: true, unspents };
}

export function btcToSats(value: string | number): number {
  const normalized = typeof value === "number" ? value.toFixed(8) : value;
  if (
    (typeof value === "number" && (!Number.isFinite(value) || value < 0)) ||
    !/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?$/.test(normalized)
  ) {
    throw new TypeError("Bitcoin amount is invalid");
  }
  const [whole = "0", fraction = ""] = normalized.split(".");
  const sats = BigInt(whole) * 100_000_000n + BigInt(fraction.padEnd(8, "0"));
  if (sats > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TypeError("Bitcoin amount exceeds the safe integer range");
  }
  const result = Number(sats);
  if (typeof value === "number" && Math.abs(value * 100_000_000 - result) > 1e-6) {
    throw new TypeError("Bitcoin amount has sub-satoshi precision");
  }
  return result;
}

export function satsToBtcString(sats: number): string {
  if (!Number.isSafeInteger(sats) || sats < 0) {
    throw new TypeError("Satoshi amount must be a non-negative safe integer");
  }
  const whole = Math.floor(sats / 100_000_000);
  const fraction = String(sats % 100_000_000).padStart(8, "0");
  return `${whole}.${fraction}`;
}

async function scanFixtureUtxos(
  rpc: RpcCaller,
  descriptor: string,
  blocks: number,
): Promise<FixtureOutpoint[]> {
  const result = parseScan(
    await rpc.call("scantxoutset", {
      action: "start",
      scanobjects: [descriptor],
    }),
  );
  return result.unspents
    .filter((utxo) => utxo.height <= blocks - COINBASE_MATURITY_BLOCKS)
    .map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      amountSats: btcToSats(utxo.amount),
      height: utxo.height,
    }))
    .filter((utxo) => utxo.amountSats > 0)
    .sort(
      (left, right) =>
        left.height - right.height || left.txid.localeCompare(right.txid) || left.vout - right.vout,
    );
}

async function buildFixture(
  rpc: RpcCaller,
  id: PsbtFixture["id"],
  outpoints: FixtureOutpoint[],
  address: string,
  descriptor: string,
  feeSats: number,
): Promise<PsbtFixture> {
  const inputSats = outpoints.reduce((sum, outpoint) => sum + outpoint.amountSats, 0);
  const outputSats = inputSats - feeSats;
  if (!Number.isSafeInteger(inputSats) || outputSats <= 0) {
    throw new Error(`Fixture ${id} has an invalid amount or fee`);
  }

  const created = await rpc.call<string>("createpsbt", {
    inputs: outpoints.map((outpoint) => ({
      txid: outpoint.txid,
      vout: outpoint.vout,
      sequence: 0xffff_fffd,
    })),
    outputs: [{ [address]: satsToBtcString(outputSats) }],
    locktime: 0,
    replaceable: true,
    version: 2,
  });
  if (typeof created !== "string") {
    throw new Error("createpsbt did not return a base64 PSBT");
  }
  const updated = await rpc.call<string>("utxoupdatepsbt", {
    psbt: created,
    descriptors: [descriptor],
  });
  if (typeof updated !== "string") {
    throw new Error("utxoupdatepsbt did not return a base64 PSBT");
  }

  const facts = extractWireFacts(updated);
  if (facts.psbtVersion !== 0 || facts.inputCount !== outpoints.length || facts.outputCount !== 1) {
    throw new Error(`Fixture ${id} has unexpected PSBT structure`);
  }
  const decoded = assertObject(await rpc.call("decodepsbt", { psbt: updated }), "decodepsbt");
  if (!Array.isArray(decoded["inputs"]) || decoded["inputs"].length !== outpoints.length) {
    throw new Error(`Fixture ${id} has invalid decoded inputs`);
  }
  for (const [index, rawInput] of decoded["inputs"].entries()) {
    const input = assertObject(rawInput, `decodepsbt input ${index}`);
    if (
      !("witness_script" in input) ||
      (!("witness_utxo" in input) && !("non_witness_utxo" in input))
    ) {
      throw new Error(`Fixture ${id} input ${index} lacks signing metadata`);
    }
  }

  return {
    id,
    initialPsbt: updated,
    outpoints,
    inputCount: facts.inputCount,
    outputCount: facts.outputCount,
    feeSats,
  };
}

export async function prepareFixtures(rpc: RpcCaller): Promise<PreparedFixtures> {
  let blockchain = parseBlockchainInfo(await rpc.call("getblockchaininfo"));
  if (blockchain.chain !== "regtest") {
    throw new Error("PSBT Interop Lab refuses to run outside Bitcoin Core regtest");
  }
  const network = parseNetworkInfo(await rpc.call("getnetworkinfo"));
  if (network.connections !== 0) {
    throw new Error("PSBT Interop Lab requires Bitcoin Core to have zero peer connections");
  }

  const descriptorInfo = parseDescriptorInfo(
    await rpc.call("getdescriptorinfo", { descriptor: LAB_DESCRIPTOR }),
  );
  if (descriptorInfo.isrange) {
    throw new Error("Lab fixture descriptor must not be ranged");
  }
  const addresses = await rpc.call<unknown>("deriveaddresses", {
    descriptor: descriptorInfo.descriptor,
  });
  if (!Array.isArray(addresses) || addresses.length !== 1 || typeof addresses[0] !== "string") {
    throw new Error("deriveaddresses did not return one fixture address");
  }
  const address = addresses[0];

  let utxos = await scanFixtureUtxos(rpc, descriptorInfo.descriptor, blockchain.blocks);
  if (utxos.length < REQUIRED_FIXTURE_UTXOS) {
    await rpc.call("generatetoaddress", {
      nblocks: COINBASE_MATURITY_BLOCKS + REQUIRED_FIXTURE_UTXOS,
      address,
      maxtries: 1_000_000,
    });
    blockchain = parseBlockchainInfo(await rpc.call("getblockchaininfo"));
    utxos = await scanFixtureUtxos(rpc, descriptorInfo.descriptor, blockchain.blocks);
  }
  if (utxos.length < REQUIRED_FIXTURE_UTXOS) {
    throw new Error("Could not create three mature deterministic regtest UTXOs");
  }

  const happyOutpoint = utxos[0];
  const firstRegressionOutpoint = utxos[1];
  const secondRegressionOutpoint = utxos[2];
  if (!happyOutpoint || !firstRegressionOutpoint || !secondRegressionOutpoint) {
    throw new Error("Fixture UTXO selection failed");
  }

  return {
    descriptor: descriptorInfo.descriptor,
    address,
    core: {
      version: network.version,
      subversion: network.subversion,
      blocks: blockchain.blocks,
      connections: network.connections,
    },
    happy: await buildFixture(
      rpc,
      "happy-path",
      [happyOutpoint],
      address,
      descriptorInfo.descriptor,
      10_000,
    ),
    regression: await buildFixture(
      rpc,
      "bdk-finalize-regression",
      [firstRegressionOutpoint, secondRegressionOutpoint],
      address,
      descriptorInfo.descriptor,
      20_000,
    ),
  };
}
