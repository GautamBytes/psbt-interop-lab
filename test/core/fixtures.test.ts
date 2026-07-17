import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { FIXTURE_DESCRIPTORS, FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";
import {
  btcToSats,
  prepareFixtures,
  type RpcCaller,
  satsToBtcString,
} from "../../src/core/fixtures.js";
import { compileUserFixturePlans } from "../../src/custom/fixtures.js";
import type { UserFixtureSpec } from "../../src/custom/manifest.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";

const COINBASE_SATS = 5_000_000_000;
const TXIDS = {
  single1: "11".repeat(32),
  single2: "22".repeat(32),
  single3: "33".repeat(32),
  single4: "44".repeat(32),
  wpkh1: "55".repeat(32),
  wpkh2: "66".repeat(32),
  wpkh3: "aa".repeat(32),
  nested: "bb".repeat(32),
  multisig: "77".repeat(32),
  tr1: "88".repeat(32),
  tr2: "99".repeat(32),
  trScript: "cc".repeat(32),
} as const;

const P2WPKH_REDEEM_SCRIPT = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
const SINGLE_KEY_WITNESS_SCRIPT = `21${FIXTURE_PUBLIC_KEYS.scalar1}ac`;
const MULTISIG_WITNESS_SCRIPT =
  `5221${FIXTURE_PUBLIC_KEYS.scalar1}21${FIXTURE_PUBLIC_KEYS.scalar2}` +
  `21${FIXTURE_PUBLIC_KEYS.scalar3}53ae`;
const FIXTURE_ADDRESSES = {
  [FIXTURE_DESCRIPTORS.p2wpkh]: "bcrt1qfixturep2wpkh",
  [FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]]: "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN",
  [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]: "bcrt1qfixturesingle",
  [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]: "bcrt1qfixturemultisig",
  [FIXTURE_DESCRIPTORS["p2tr-keypath"]]: "bcrt1pfixturetaproot",
  [FIXTURE_DESCRIPTORS["p2tr-scriptpath"]]:
    "bcrt1pg44et8f66qnjn5fd0hu6dnnx7tczqslmt3dkzpccjlzeg99psshqfkkdep",
} as const;
const FIXTURE_SCRIPT_PUBKEYS = {
  [FIXTURE_DESCRIPTORS.p2wpkh]: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
  [FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]]: "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487",
  [FIXTURE_DESCRIPTORS["p2wsh-single-key"]]:
    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
  [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]]:
    "002012c2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c572",
  [FIXTURE_DESCRIPTORS["p2tr-keypath"]]:
    "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
  [FIXTURE_DESCRIPTORS["p2tr-scriptpath"]]:
    "5120456b959d3ad02729d12d7df9a6ce66f2f02043fb5c5b61071897c59414a1842e",
} as const;
const BIP370_VALID_PSBT_V2 =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";

function fixtureScriptPubKey(descriptor: string): string {
  const scriptPubKey = FIXTURE_SCRIPT_PUBKEYS[descriptor as keyof typeof FIXTURE_SCRIPT_PUBKEYS];
  if (!scriptPubKey) throw new Error("Unknown fixture script descriptor");
  return scriptPubKey;
}

interface FakeUnsignedTransaction {
  version: number;
  inputs: Array<{ txid: string; vout: number; sequence: number }>;
  outputs: Array<{ amountSats: number; scriptPubKey: string }>;
  locktime: number;
  bytes: Buffer;
}

interface FakeRpcOptions {
  chain?: string;
  connections?: number;
  networkActive?: boolean;
  malformedScan?: boolean;
  malformedUpdatedPsbt?: boolean;
  emptyUtxos?: boolean;
  guardConcurrentScans?: boolean;
  scanFailures?: number;
  wrongWitnessUtxoScript?: boolean;
  wrongOutputScript?: boolean;
  wrongWitnessScript?: "single-key" | "multisig";
  mutateCoreScriptFor?: keyof typeof FIXTURE_DESCRIPTORS;
  mutateInputScript?: {
    descriptorId: keyof typeof FIXTURE_DESCRIPTORS;
    inputCount?: number;
    inputIndex?: number;
    txid?: string;
  };
  mutateOutputScript?: {
    descriptorId: keyof typeof FIXTURE_DESCRIPTORS;
    inputCount?: number;
    inputTxid?: string;
  };
  unsignedTxLocktime?: number;
  createdPsbtV2?: boolean;
  updatedPsbtV2?: boolean;
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

function readCompactSize(buffer: Buffer, offset: number): { value: number; nextOffset: number } {
  const value = buffer[offset];
  if (value === undefined || value >= 253) throw new Error("Unsupported test compact size");
  return { value, nextOffset: offset + 1 };
}

function psbtEntry(keyType: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  const key = Buffer.concat([Buffer.from([keyType]), keyData]);
  return Buffer.concat([
    encodeCompactSize(key.length),
    key,
    encodeCompactSize(value.length),
    value,
  ]);
}

function psbtMap(entries: readonly Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.from([0])]);
}

function serializedTxOut(amountSats: number, scriptPubKey: string): Buffer {
  const script = Buffer.from(scriptPubKey, "hex");
  return Buffer.concat([encodeUint64(amountSats), encodeCompactSize(script.length), script]);
}

function parseTxOut(value: Buffer): { amountSats: number; scriptPubKey: string } {
  if (value.length < 9) throw new Error("Invalid fake witness UTXO");
  const amount = value.readBigUInt64LE(0);
  const scriptLength = readCompactSize(value, 8);
  const scriptEnd = scriptLength.nextOffset + scriptLength.value;
  if (amount > BigInt(Number.MAX_SAFE_INTEGER) || scriptEnd !== value.length) {
    throw new Error("Invalid fake witness UTXO");
  }
  return {
    amountSats: Number(amount),
    scriptPubKey: value.subarray(scriptLength.nextOffset, scriptEnd).toString("hex"),
  };
}

function parseUnsignedTransaction(psbt: string): FakeUnsignedTransaction {
  const document = parsePsbtDocument(psbt);
  const globalMap = document.maps.find((map) => map.location.kind === "global");
  const unsignedTransactions = globalMap?.entries.filter(
    (entry) => entry.keyType === 0 && entry.keyData.length === 0,
  );
  if (document.psbtVersion !== 0 || unsignedTransactions?.length !== 1) {
    throw new Error("Fake RPC expected one PSBTv0 unsigned transaction");
  }
  const bytes = unsignedTransactions[0]?.value;
  if (!bytes) throw new Error("Fake RPC lacks an unsigned transaction");
  const version = bytes.readUInt32LE(0);
  let offset = 4;
  const inputCount = readCompactSize(bytes, offset);
  offset = inputCount.nextOffset;
  const inputs = [];
  for (let index = 0; index < inputCount.value; index += 1) {
    const txidBytes = bytes.subarray(offset, offset + 32);
    if (txidBytes.length !== 32) throw new Error("Truncated fake transaction input");
    offset += 32;
    const vout = bytes.readUInt32LE(offset);
    offset += 4;
    const scriptLength = readCompactSize(bytes, offset);
    offset = scriptLength.nextOffset + scriptLength.value;
    const sequence = bytes.readUInt32LE(offset);
    offset += 4;
    inputs.push({ txid: Buffer.from(txidBytes).reverse().toString("hex"), vout, sequence });
  }
  const outputCount = readCompactSize(bytes, offset);
  offset = outputCount.nextOffset;
  const outputs = [];
  for (let index = 0; index < outputCount.value; index += 1) {
    const amount = bytes.readBigUInt64LE(offset);
    offset += 8;
    const scriptLength = readCompactSize(bytes, offset);
    const scriptEnd = scriptLength.nextOffset + scriptLength.value;
    if (amount > BigInt(Number.MAX_SAFE_INTEGER) || scriptEnd > bytes.length) {
      throw new Error("Invalid fake transaction output");
    }
    outputs.push({
      amountSats: Number(amount),
      scriptPubKey: bytes.subarray(scriptLength.nextOffset, scriptEnd).toString("hex"),
    });
    offset = scriptEnd;
  }
  if (offset + 4 !== bytes.length) throw new Error("Invalid fake unsigned transaction length");
  const locktime = bytes.readUInt32LE(offset);
  return { version, inputs, outputs, locktime, bytes };
}

function addInputMetadata(psbt: string, additions: readonly (readonly Buffer[])[]): string {
  const document = parsePsbtDocument(psbt);
  let inputIndex = 0;
  const encodedMaps = document.maps.map((map) => {
    const existing = map.entries.map((entry) => {
      const key = entry.completeKey;
      return Buffer.concat([
        encodeCompactSize(key.length),
        key,
        encodeCompactSize(entry.value.length),
        entry.value,
      ]);
    });
    if (map.location.kind !== "input") return psbtMap(existing);
    const added = additions[inputIndex];
    inputIndex += 1;
    if (!added) throw new Error("Missing fake PSBT input metadata");
    return psbtMap([...existing, ...added]);
  });
  if (inputIndex !== additions.length) throw new Error("Extra fake PSBT input metadata");
  return Buffer.concat([Buffer.from("70736274ff", "hex"), ...encodedMaps]).toString("base64");
}

function inputEntryValue(psbt: string, inputIndex: number, keyType: number): Buffer | undefined {
  const map = parsePsbtDocument(psbt).maps.find(
    (candidate) => candidate.location.kind === "input" && candidate.location.index === inputIndex,
  );
  const entries = map?.entries.filter(
    (entry) => entry.keyType === keyType && entry.keyData.length === 0,
  );
  if (!entries || entries.length === 0) return undefined;
  if (entries.length !== 1) throw new Error("Duplicate fake PSBT input metadata");
  return entries[0]?.value;
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
  return `sha256:${createHash("sha256").update(unsignedTransaction.value).digest("hex")}`;
}

function semanticTransactionId(psbt: string): string {
  const transaction = parseUnsignedTransaction(psbt).bytes;
  return Buffer.from(
    createHash("sha256").update(createHash("sha256").update(transaction).digest()).digest(),
  )
    .reverse()
    .toString("hex");
}

function makePsbt(
  inputs: Array<{ txid: string; vout: number; sequence: number }>,
  outputs: Array<{ amountSats: number; scriptPubKey: string }>,
  version: number,
  locktime: number,
): string {
  const unsignedTransaction = Buffer.concat([
    encodeUint32(version),
    encodeCompactSize(inputs.length),
    ...inputs.flatMap((input) => [
      Buffer.from(input.txid, "hex").reverse(),
      encodeUint32(input.vout),
      Buffer.from([0]),
      encodeUint32(input.sequence),
    ]),
    encodeCompactSize(outputs.length),
    ...outputs.flatMap((output) => {
      const script = Buffer.from(output.scriptPubKey, "hex");
      return [encodeUint64(output.amountSats), encodeCompactSize(script.byteLength), script];
    }),
    encodeUint32(locktime),
  ]);
  return Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    psbtMap([psbtEntry(0x00, unsignedTransaction)]),
    ...inputs.map(() => psbtMap([])),
    ...outputs.map(() => psbtMap([])),
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
  let remainingScanFailures = options.scanFailures ?? 0;
  const addresses = FIXTURE_ADDRESSES;
  const coreScriptPubKey = (descriptor: string): string => {
    const scriptPubKey = fixtureScriptPubKey(descriptor);
    const descriptorId = Object.entries(FIXTURE_DESCRIPTORS).find(
      ([, candidate]) => candidate === descriptor,
    )?.[0];
    return descriptorId === options.mutateCoreScriptFor ? mutateHex(scriptPubKey) : scriptPubKey;
  };
  const unspents = {
    [FIXTURE_DESCRIPTORS.p2wpkh]: [
      { txid: TXIDS.wpkh3, vout: 0, amount: "50.00000000", height: 10 },
      { txid: TXIDS.wpkh2, vout: 0, amount: "50.00000000", height: 6 },
      { txid: TXIDS.wpkh1, vout: 0, amount: "50.00000000", height: 5 },
    ],
    [FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]]: [
      { txid: TXIDS.nested, vout: 0, amount: "50.00000000", height: 11 },
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
    [FIXTURE_DESCRIPTORS["p2tr-scriptpath"]]: [
      { txid: TXIDS.trScript, vout: 0, amount: "50.00000000", height: 12 },
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
  const rpc: RpcCaller = {
    async call<T>(method: string, params?: Record<string, unknown> | unknown[]): Promise<T> {
      calls.push({ method, params });
      if (method === "getblockchaininfo") return { chain: options.chain ?? "regtest", blocks } as T;
      if (method === "getnetworkinfo") {
        return {
          version: 310100,
          subversion: "/Satoshi:31.1.0/",
          connections: options.connections ?? 0,
          networkactive: options.networkActive ?? false,
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
        )?.[0];
        if (!descriptor || typeof address !== "string") throw new Error("Unknown address");
        return {
          isvalid: true,
          address,
          scriptPubKey: coreScriptPubKey(descriptor),
          iswitness: descriptor !== FIXTURE_DESCRIPTORS["p2sh-p2wpkh"],
          ...(descriptor === FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]
            ? {}
            : {
                witness_version:
                  descriptor === FIXTURE_DESCRIPTORS["p2tr-keypath"] ||
                  descriptor === FIXTURE_DESCRIPTORS["p2tr-scriptpath"]
                    ? 1
                    : 0,
              }),
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
          if (remainingScanFailures > 0) {
            remainingScanFailures -= 1;
            return { success: false, unspents: [] } as T;
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
          outputs.length === 0 ||
          request["version"] !== 2 ||
          !Number.isSafeInteger(request["locktime"]) ||
          "psbt_version" in request
        ) {
          throw new Error("Invalid createpsbt request");
        }
        const fixtureInputs = inputs.map((rawInput) => {
          const input = paramObject(rawInput as Record<string, unknown>);
          if (
            typeof input["txid"] !== "string" ||
            !Number.isSafeInteger(input["vout"]) ||
            !Number.isSafeInteger(input["sequence"])
          ) {
            throw new Error("Invalid fixture input");
          }
          return {
            txid: input["txid"],
            vout: input["vout"] as number,
            sequence: input["sequence"] as number,
          };
        });
        const fixtureOutputs = outputs.map((rawOutput) => {
          const output = paramObject(rawOutput as Record<string, unknown>);
          const outputEntries = Object.entries(output);
          const outputAddress = outputEntries[0]?.[0];
          const outputAmount = outputEntries[0]?.[1];
          const outputDescriptor = Object.entries(addresses).find(
            ([, address]) => address === outputAddress,
          )?.[0];
          if (
            outputEntries.length !== 1 ||
            typeof outputDescriptor !== "string" ||
            typeof outputAmount !== "string"
          ) {
            throw new Error("Invalid fixture output");
          }
          const outputDescriptorId = Object.entries(FIXTURE_DESCRIPTORS).find(
            ([, candidate]) => candidate === outputDescriptor,
          )?.[0];
          const outputMutation = options.mutateOutputScript;
          const shouldMutateOutputScript =
            outputMutation !== undefined &&
            outputDescriptorId === outputMutation.descriptorId &&
            (outputMutation.inputCount === undefined ||
              outputMutation.inputCount === fixtureInputs.length) &&
            (outputMutation.inputTxid === undefined ||
              fixtureInputs.some((input) => input.txid === outputMutation.inputTxid));
          const expectedOutputScript = coreScriptPubKey(outputDescriptor);
          return {
            amountSats: btcToSats(outputAmount),
            scriptPubKey:
              options.wrongOutputScript || shouldMutateOutputScript
                ? mutateHex(expectedOutputScript)
                : expectedOutputScript,
          };
        });
        if (options.createdPsbtV2) return BIP370_VALID_PSBT_V2 as T;
        return makePsbt(
          fixtureInputs,
          fixtureOutputs,
          request["version"] as number,
          options.unsignedTxLocktime ?? (request["locktime"] as number),
        ) as T;
      }
      if (method === "utxoupdatepsbt") {
        const request = paramObject(params);
        const psbt = request["psbt"];
        const descriptors = request["descriptors"];
        if (typeof psbt !== "string" || !Array.isArray(descriptors)) {
          throw new Error("Invalid utxoupdatepsbt request");
        }
        if (descriptors.some((descriptor) => typeof descriptor !== "string")) {
          throw new Error("Invalid fixture descriptors");
        }
        if (options.updatedPsbtV2) return BIP370_VALID_PSBT_V2 as T;
        const transaction = parseUnsignedTransaction(psbt);
        const inputMetadata = transaction.inputs.map((input, inputIndex) => {
          const descriptor = descriptorForOutpoint.get(`${input.txid}:${input.vout}`);
          if (!descriptor || !descriptors.includes(descriptor)) {
            throw new Error("Missing fixture descriptor for PSBT input");
          }
          const descriptorId = Object.entries(FIXTURE_DESCRIPTORS).find(
            ([, candidate]) => candidate === descriptor,
          )?.[0];
          const inputMutation = options.mutateInputScript;
          const shouldMutateInputScript =
            inputMutation !== undefined &&
            descriptorId === inputMutation.descriptorId &&
            (inputMutation.inputCount === undefined ||
              inputMutation.inputCount === transaction.inputs.length) &&
            (inputMutation.inputIndex === undefined || inputMutation.inputIndex === inputIndex) &&
            (inputMutation.txid === undefined || inputMutation.txid === input.txid);
          const inputScriptPubKey = coreScriptPubKey(descriptor);
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
          return [
            psbtEntry(
              0x01,
              serializedTxOut(
                COINBASE_SATS,
                options.wrongWitnessUtxoScript || shouldMutateInputScript
                  ? mutateHex(inputScriptPubKey)
                  : inputScriptPubKey,
              ),
            ),
            ...(witnessScript
              ? [
                  psbtEntry(
                    0x05,
                    Buffer.from(
                      shouldMutateWitnessScript ? mutateHex(witnessScript) : witnessScript,
                      "hex",
                    ),
                  ),
                ]
              : []),
            ...(descriptor === FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]
              ? [psbtEntry(0x04, Buffer.from(P2WPKH_REDEEM_SCRIPT, "hex"))]
              : []),
            ...(descriptor === FIXTURE_DESCRIPTORS["p2tr-scriptpath"]
              ? [
                  psbtEntry(
                    0x15,
                    Buffer.from(`20${FIXTURE_PUBLIC_KEYS.scalar2.slice(2)}acc0`, "hex"),
                    Buffer.concat([
                      Buffer.from([0xc0]),
                      Buffer.from(FIXTURE_PUBLIC_KEYS.scalar1.slice(2), "hex"),
                    ]),
                  ),
                ]
              : []),
            ...(descriptor === FIXTURE_DESCRIPTORS["p2tr-keypath"] ||
            descriptor === FIXTURE_DESCRIPTORS["p2tr-scriptpath"]
              ? [psbtEntry(0x17, Buffer.from(FIXTURE_PUBLIC_KEYS.scalar1.slice(2), "hex"))]
              : []),
          ];
        });
        return (
          options.malformedUpdatedPsbt ? "not-a-psbt" : addInputMetadata(psbt, inputMetadata)
        ) as T;
      }
      if (method === "decodepsbt") {
        const psbt = paramObject(params)["psbt"];
        if (typeof psbt !== "string") throw new Error("Invalid decodepsbt request");
        const transaction = parseUnsignedTransaction(psbt);
        const decodedInputs = transaction.inputs.map((_input, index) => {
          const witnessUtxo = inputEntryValue(psbt, index, 0x01);
          if (!witnessUtxo) throw new Error("Fake PSBT input lacks witness UTXO");
          const decodedWitnessUtxo = parseTxOut(witnessUtxo);
          const witnessScript = inputEntryValue(psbt, index, 0x05);
          const redeemScript = inputEntryValue(psbt, index, 0x04);
          const taprootInternalKey = inputEntryValue(psbt, index, 0x17);
          return {
            witness_utxo: {
              amount: satsToBtcString(decodedWitnessUtxo.amountSats),
              scriptPubKey: { hex: decodedWitnessUtxo.scriptPubKey },
            },
            ...(witnessScript ? { witness_script: { hex: witnessScript.toString("hex") } } : {}),
            ...(redeemScript ? { redeem_script: { hex: redeemScript.toString("hex") } } : {}),
            ...(taprootInternalKey
              ? { taproot_internal_key: taprootInternalKey.toString("hex") }
              : {}),
          };
        });
        const inputSats = decodedInputs.reduce(
          (sum, input) => sum + btcToSats(input.witness_utxo.amount),
          0,
        );
        const outputSats = transaction.outputs.reduce((sum, output) => sum + output.amountSats, 0);
        const txid = Buffer.from(
          createHash("sha256")
            .update(createHash("sha256").update(transaction.bytes).digest())
            .digest(),
        )
          .reverse()
          .toString("hex");
        return {
          tx: {
            txid,
            version: transaction.version,
            locktime: transaction.locktime,
            vin: transaction.inputs,
            vout: transaction.outputs.map((output) => ({
              value: satsToBtcString(output.amountSats),
              scriptPubKey: { hex: output.scriptPubKey },
            })),
          },
          inputs: decodedInputs,
          fee: satsToBtcString(inputSats - outputSats),
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
          return {
            version: 310000,
            subversion: "/Satoshi:31.0.0/",
            connections: 0,
            networkactive: false,
          } as T;
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

  test("refuses a Core node with networking enabled before touching descriptors or funds", async () => {
    const { rpc, calls } = createFixtureRpc({ networkActive: true });

    await expect(prepareFixtures(rpc)).rejects.toThrow(/networking.*disabled/i);
    expect(calls.map((call) => call.method)).toEqual(["getblockchaininfo", "getnetworkinfo"]);
  });

  test("serializes scantxoutset starts because Core permits only one active scan", async () => {
    const { rpc, maxConcurrentScans } = createFixtureRpc({ guardConcurrentScans: true });

    await prepareFixtures(rpc);

    expect(maxConcurrentScans()).toBe(1);
  });

  test("serializes scantxoutset across concurrent prepareFixtures calls", async () => {
    const { rpc, maxConcurrentScans } = createFixtureRpc({ guardConcurrentScans: true });

    const prepared = await Promise.all([prepareFixtures(rpc), prepareFixtures(rpc)]);

    expect(prepared).toHaveLength(2);
    expect(maxConcurrentScans()).toBe(1);
  });

  test("releases the global scan lock after an RPC error", async () => {
    const { rpc, maxConcurrentScans } = createFixtureRpc({
      guardConcurrentScans: true,
      scanFailures: 1,
    });

    const results = await Promise.allSettled([prepareFixtures(rpc), prepareFixtures(rpc)]);

    expect(results.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
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
    expect(versions).toHaveLength(10);
    expect(versions).toEqual(
      Array.from({ length: 10 }, () => ({ version: 2, psbtVersion: undefined })),
    );
  });

  test("builds the deterministic intent-rich fixture with immutable transaction metadata", async () => {
    const fixtures = await prepareFixtures(createFixtureRpc().rpc);

    const fixture = fixtures.profiles["intent-rich-p2wpkh"];
    expect(fixture).toMatchObject({
      id: "intent-rich-p2wpkh",
      inputCount: 1,
      outputCount: 2,
      feeSats: 15_000,
      scriptTypes: ["p2wpkh"],
      transactionIntent: {
        version: 2,
        locktime: 42,
        sequences: [0xffff_fffc],
        outputCount: 2,
        outputs: [
          { descriptor: FIXTURE_DESCRIPTORS.p2wpkh, amountSats: 2_499_992_500 },
          { descriptor: FIXTURE_DESCRIPTORS["p2tr-keypath"], amountSats: 2_499_992_500 },
        ],
      },
    });
    expect(fixture.outpoints.map((outpoint) => outpoint.txid)).toEqual([TXIDS.wpkh3]);

    const transaction = parseUnsignedTransaction(fixture.initialPsbt);
    expect(transaction).toMatchObject({
      version: 2,
      locktime: 42,
      inputs: [{ txid: TXIDS.wpkh3, vout: 0, sequence: 0xffff_fffc }],
      outputs: [
        {
          amountSats: 2_499_992_500,
          scriptPubKey: fixtureScriptPubKey(FIXTURE_DESCRIPTORS.p2wpkh),
        },
        {
          amountSats: 2_499_992_500,
          scriptPubKey: fixtureScriptPubKey(FIXTURE_DESCRIPTORS["p2tr-keypath"]),
        },
      ],
    });
    expect(
      transaction.outputs.reduce((sum, output) => sum + output.amountSats, fixture.feeSats),
    ).toBe(fixture.outpoints[0]?.amountSats);
    expect(Object.isFrozen(fixture.transactionIntent)).toBe(true);
    expect(Object.isFrozen(fixture.transactionIntent.sequences)).toBe(true);
    expect(Object.isFrozen(fixture.transactionIntent.outputs)).toBe(true);
    expect(fixture.transactionIntent.outputs.every(Object.isFrozen)).toBe(true);
  });

  test("builds user-defined public-template fixtures with exact amounts and fee", async () => {
    const spec: UserFixtureSpec = {
      id: "merchant-refund",
      inputs: [{ descriptor: "p2wpkh", sequence: 0xffff_fffc }],
      outputs: [
        { descriptor: "p2wpkh", amountSats: 100_000 },
        { descriptor: "p2tr-keypath", remainder: true },
      ],
      feeSats: 15_000,
      locktime: 42,
      transactionVersion: 2,
    };
    const plans = compileUserFixturePlans([spec]);

    const fixtures = await prepareFixtures(createFixtureRpc().rpc, plans);

    const fixture = fixtures.custom["merchant-refund"];
    expect(fixture).toMatchObject({
      id: "merchant-refund",
      inputCount: 1,
      outputCount: 2,
      feeSats: 15_000,
      scriptTypes: ["p2wpkh"],
      specSha256: plans[0]?.specSha256,
      transactionIntent: {
        version: 2,
        locktime: 42,
        sequences: [0xffff_fffc],
        outputCount: 2,
        outputs: [
          { descriptor: FIXTURE_DESCRIPTORS.p2wpkh, amountSats: 100_000 },
          {
            descriptor: FIXTURE_DESCRIPTORS["p2tr-keypath"],
            amountSats: 4_999_885_000,
          },
        ],
      },
    });
    expect(parseUnsignedTransaction(fixture?.initialPsbt ?? "").outputs).toMatchObject([
      { amountSats: 100_000 },
      { amountSats: 4_999_885_000 },
    ]);
  });

  test("rejects a PSBTv2 createpsbt response", async () => {
    await expect(prepareFixtures(createFixtureRpc({ createdPsbtV2: true }).rpc)).rejects.toThrow(
      /unexpected PSBT structure/i,
    );
  });

  test("rejects a PSBTv2 utxoupdatepsbt response", async () => {
    await expect(prepareFixtures(createFixtureRpc({ updatedPsbtV2: true }).rpc)).rejects.toThrow(
      /unexpected PSBT structure/i,
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

  test.each(["p2wpkh", "p2wsh-single-key", "p2wsh-2-of-3", "p2tr-keypath"] as const)(
    "rejects an internally consistent %s Core script that differs from the local commitment",
    async (mutateCoreScriptFor) => {
      await expect(prepareFixtures(createFixtureRpc({ mutateCoreScriptFor }).rpc)).rejects.toThrow(
        /local descriptor script commitment/i,
      );
    },
  );

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

  test("rejects an unsigned transaction whose locktime differs from the requested intent", async () => {
    await expect(prepareFixtures(createFixtureRpc({ unsignedTxLocktime: 1 }).rpc)).rejects.toThrow(
      /locktime/i,
    );
  });

  test("serializes signer metadata into the fake PSBT input maps", async () => {
    const fixtures = await prepareFixtures(createFixtureRpc().rpc);
    const inputKeyTypes = (psbt: string) =>
      parsePsbtDocument(psbt)
        .maps.filter((map) => map.location.kind === "input")
        .map((map) => map.entries.map((entry) => entry.keyType));

    expect(inputKeyTypes(fixtures.profiles.p2wpkh.initialPsbt)).toEqual([[0x01]]);
    expect(inputKeyTypes(fixtures.profiles["p2sh-p2wpkh"].initialPsbt)).toEqual([[0x01, 0x04]]);
    expect(inputKeyTypes(fixtures.profiles["p2wsh-single-key"].initialPsbt)).toEqual([
      [0x01, 0x05],
    ]);
    expect(inputKeyTypes(fixtures.profiles["p2wsh-2-of-3"].initialPsbt)).toEqual([[0x01, 0x05]]);
    expect(inputKeyTypes(fixtures.profiles["p2tr-keypath"].initialPsbt)).toEqual([[0x01, 0x17]]);
    expect(inputKeyTypes(fixtures.profiles["p2tr-scriptpath"].initialPsbt)).toEqual([
      [0x01, 0x15, 0x17],
    ]);
    expect(inputKeyTypes(fixtures.profiles["mixed-p2wpkh-p2tr"].initialPsbt)).toEqual([
      [0x01],
      [0x01, 0x17],
    ]);
    expect(inputKeyTypes(fixtures.profiles["intent-rich-p2wpkh"].initialPsbt)).toEqual([[0x01]]);
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
    });
    expect(fixtures.profiles["mixed-p2wpkh-p2tr"].transactionId).toBe(
      semanticTransactionId(fixtures.profiles["mixed-p2wpkh-p2tr"].initialPsbt),
    );
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
      [FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]],
      [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
      [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]],
      [FIXTURE_DESCRIPTORS["p2tr-keypath"]],
      [FIXTURE_DESCRIPTORS["p2tr-scriptpath"]],
      [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
      [FIXTURE_DESCRIPTORS.p2wpkh],
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
    ).toEqual([3, 1, 4, 1, 2, 1, 100]);
    expect(fixtures.core.blocks).toBe(612);
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

  test.each([
    ["P2WPKH", { descriptorId: "p2wpkh", txid: TXIDS.wpkh1 }],
    ["single-key P2WSH", { descriptorId: "p2wsh-single-key", txid: TXIDS.single4 }],
    ["multisig P2WSH", { descriptorId: "p2wsh-2-of-3", txid: TXIDS.multisig }],
    ["Taproot", { descriptorId: "p2tr-keypath", txid: TXIDS.tr1 }],
    ["mixed P2WPKH", { descriptorId: "p2wpkh", inputCount: 2, inputIndex: 0 }],
    ["mixed Taproot", { descriptorId: "p2tr-keypath", inputCount: 2, inputIndex: 1 }],
  ] as const)("rejects a %s input script mutation", async (_label, mutateInputScript) => {
    await expect(prepareFixtures(createFixtureRpc({ mutateInputScript }).rpc)).rejects.toThrow(
      /witness UTXO script/i,
    );
  });

  test.each([
    ["P2WPKH", { descriptorId: "p2wpkh", inputTxid: TXIDS.wpkh1 }],
    ["single-key P2WSH", { descriptorId: "p2wsh-single-key", inputTxid: TXIDS.single4 }],
    ["multisig P2WSH", { descriptorId: "p2wsh-2-of-3", inputTxid: TXIDS.multisig }],
    ["Taproot", { descriptorId: "p2tr-keypath", inputTxid: TXIDS.tr1 }],
    ["mixed", { descriptorId: "p2wpkh", inputCount: 2 }],
    ["intent-rich P2WPKH", { descriptorId: "p2wpkh", inputTxid: TXIDS.wpkh3 }],
    ["intent-rich Taproot", { descriptorId: "p2tr-keypath", inputTxid: TXIDS.wpkh3 }],
  ] as const)("rejects a %s profile output script mutation", async (_label, mutateOutputScript) => {
    await expect(prepareFixtures(createFixtureRpc({ mutateOutputScript }).rpc)).rejects.toThrow(
      /output script/i,
    );
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
