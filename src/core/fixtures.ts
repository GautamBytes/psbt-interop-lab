import { createHash } from "node:crypto";
import type { CompiledUserFixturePlan } from "../custom/fixtures.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { extractWireFacts } from "../psbt/wire-facts.js";
import {
  FIXTURE_DESCRIPTORS,
  FIXTURE_PROFILES,
  FIXTURE_PUBLIC_KEYS,
  type FixtureDescriptorId,
  type FixtureProfileId,
  type FixtureScriptType,
} from "./fixture-profiles.js";

const COINBASE_MATURITY_BLOCKS = 100;
const LEGACY_DESCRIPTOR_ID = "p2wsh-single-key" as const;
const DEFAULT_GENERATE_MAX_TRIES = 1_000_000;
const DEFAULT_SEQUENCE = 0xffff_fffd;
const MAX_UINT32 = 0xffff_ffff;
const P2WPKH_REDEEM_SCRIPT = `0014${createHash("ripemd160")
  .update(createHash("sha256").update(Buffer.from(FIXTURE_PUBLIC_KEYS.scalar1, "hex")).digest())
  .digest("hex")}`;
const SINGLE_KEY_WITNESS_SCRIPT = `21${FIXTURE_PUBLIC_KEYS.scalar1}ac`;
const MULTISIG_WITNESS_SCRIPT =
  `5221${FIXTURE_PUBLIC_KEYS.scalar1}21${FIXTURE_PUBLIC_KEYS.scalar2}` +
  `21${FIXTURE_PUBLIC_KEYS.scalar3}53ae`;
const TAPROOT_SINGLE_KEY_LEAF_SCRIPT = `20${FIXTURE_PUBLIC_KEYS.scalar2.slice(2)}ac`;
const EXPECTED_REDEEM_SCRIPTS = {
  "p2sh-p2wpkh": P2WPKH_REDEEM_SCRIPT,
} as const satisfies Partial<Record<FixtureDescriptorId, string>>;
const EXPECTED_WITNESS_SCRIPTS = {
  "p2wsh-single-key": SINGLE_KEY_WITNESS_SCRIPT,
  "p2wsh-2-of-3": MULTISIG_WITNESS_SCRIPT,
} as const satisfies Partial<Record<FixtureDescriptorId, string>>;
const EXPECTED_SCRIPT_PUBKEYS = {
  p2wpkh: `0014${createHash("ripemd160")
    .update(createHash("sha256").update(Buffer.from(FIXTURE_PUBLIC_KEYS.scalar1, "hex")).digest())
    .digest("hex")}`,
  "p2sh-p2wpkh": `a914${createHash("ripemd160")
    .update(createHash("sha256").update(Buffer.from(P2WPKH_REDEEM_SCRIPT, "hex")).digest())
    .digest("hex")}87`,
  "p2wsh-single-key": `0020${createHash("sha256")
    .update(Buffer.from(SINGLE_KEY_WITNESS_SCRIPT, "hex"))
    .digest("hex")}`,
  "p2wsh-2-of-3": `0020${createHash("sha256")
    .update(Buffer.from(MULTISIG_WITNESS_SCRIPT, "hex"))
    .digest("hex")}`,
  // BIP341 TapTweak output key for the scalar-1 x-only internal key.
  "p2tr-keypath": "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
  // BIP341 output key for scalar-1 with pk(scalar-2) as its only tapscript leaf.
  "p2tr-scriptpath": "5120456b959d3ad02729d12d7df9a6ce66f2f02043fb5c5b61071897c59414a1842e",
} as const satisfies Record<FixtureDescriptorId, string>;
let scanLockTail = Promise.resolve();
export const BITCOIN_CORE_VERSION = 310100;

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

export type BuiltInFixtureId = "happy-path" | "bdk-finalize-regression" | FixtureProfileId;
export type FixtureId = string;

export interface FixtureOutputIntent {
  readonly descriptor: string;
  readonly amountSats: number;
}

export interface FixtureTransactionIntent {
  readonly version: number;
  readonly locktime: number;
  readonly sequences: readonly number[];
  readonly outputCount: number;
  readonly outputs: readonly FixtureOutputIntent[];
}

export interface PsbtFixture {
  id: FixtureId;
  initialPsbt: string;
  outpoints: FixtureOutpoint[];
  inputCount: number;
  outputCount: number;
  feeSats: number;
  scriptTypes: readonly FixtureScriptType[];
  inputDescriptors: readonly string[];
  outputDescriptor: string;
  psbtVersion: 0;
  transactionId: string;
  psbtSha256: string;
  unsignedTxSha256: `sha256:${string}`;
  readonly specSha256?: `sha256:${string}`;
  readonly transactionIntent?: FixtureTransactionIntent;
}

export interface PreparedPsbtFixture extends PsbtFixture {
  readonly transactionIntent: FixtureTransactionIntent;
}

export interface PreparedFixtureSet {
  descriptor?: string;
  address?: string;
  core: {
    version: number;
    subversion: string;
    blocks: number;
    connections: number;
  };
  happy?: PreparedPsbtFixture;
  regression?: PreparedPsbtFixture;
  profiles: Partial<Record<FixtureProfileId, PreparedPsbtFixture>>;
  custom: Readonly<Record<string, PreparedPsbtFixture>>;
}

export interface PreparedFixtures extends PreparedFixtureSet {
  descriptor: string;
  address: string;
  happy: PreparedPsbtFixture;
  regression: PreparedPsbtFixture;
  profiles: Record<FixtureProfileId, PreparedPsbtFixture>;
}

interface BlockchainInfo {
  chain: string;
  blocks: number;
}

interface NetworkInfo {
  version: number;
  subversion: string;
  connections: number;
  networkActive: boolean;
}

interface DescriptorInfo {
  descriptor: string;
  isrange: boolean;
}

interface CanonicalDescriptor {
  id: FixtureDescriptorId;
  descriptor: string;
  address: string;
  scriptPubKey: string;
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

interface FixturePlan {
  id: FixtureId;
  scriptTypes: readonly FixtureScriptType[];
  inputDescriptorIds: readonly FixtureDescriptorId[];
  outputDescriptorIds: readonly FixtureDescriptorId[];
  sequences: readonly number[];
  locktime: number;
  transactionVersion: number;
  feeSats: number;
  outputAmounts?: readonly (number | null)[];
  specSha256?: `sha256:${string}`;
}

function assertObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid object`);
  }
  return value as Record<string, unknown>;
}

function assertHex(value: unknown, bytes: number, label: string): string {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "i").test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value.toLowerCase();
}

function parseScriptHex(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || !/^(?:[0-9a-f]{2})+$/i.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value.toLowerCase();
}

function parseDecodedScript(value: unknown, label: string): string {
  return parseScriptHex(assertObject(value, label)["hex"], `${label} hex`);
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
    !Number.isSafeInteger(object["connections"]) ||
    (object["connections"] as number) < 0 ||
    typeof object["networkactive"] !== "boolean"
  ) {
    throw new Error("getnetworkinfo returned invalid version metadata");
  }
  return {
    version: object["version"] as number,
    subversion: object["subversion"],
    connections: object["connections"] as number,
    networkActive: object["networkactive"],
  };
}

function parseDescriptorInfo(value: unknown): DescriptorInfo {
  const object = assertObject(value, "getdescriptorinfo");
  if (typeof object["descriptor"] !== "string" || typeof object["isrange"] !== "boolean") {
    throw new Error("getdescriptorinfo returned invalid descriptor metadata");
  }
  if (!object["descriptor"] || /(?:xprv|tprv|priv|secret)/i.test(object["descriptor"])) {
    throw new Error("getdescriptorinfo returned a non-public fixture descriptor");
  }
  return {
    descriptor: object["descriptor"],
    isrange: object["isrange"],
  };
}

function parseAddress(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(?:bcrt1[qp]|2)[A-Za-z0-9]+$/.test(value)) {
    throw new Error(`${label} did not return one regtest witness address`);
  }
  return value;
}

function parseValidatedScriptPubKey(
  value: unknown,
  id: FixtureDescriptorId,
  address: string,
): string {
  const object = assertObject(value, `validateaddress ${id}`);
  const scriptPubKey = object["scriptPubKey"];
  const isNestedSegwit = id === "p2sh-p2wpkh";
  const isTaproot = id === "p2tr-keypath" || id === "p2tr-scriptpath";
  const witnessVersion = isTaproot ? 1 : 0;
  const expectedScriptPattern = isNestedSegwit
    ? /^a914[0-9a-f]{40}87$/i
    : isTaproot
      ? /^5120[0-9a-f]{64}$/i
      : id === "p2wpkh"
        ? /^0014[0-9a-f]{40}$/i
        : /^0020[0-9a-f]{64}$/i;
  if (
    object["isvalid"] !== true ||
    object["address"] !== address ||
    object["iswitness"] !== !isNestedSegwit ||
    (!isNestedSegwit && object["witness_version"] !== witnessVersion) ||
    typeof scriptPubKey !== "string" ||
    !expectedScriptPattern.test(scriptPubKey)
  ) {
    throw new Error(`validateaddress returned invalid script metadata for ${id}`);
  }
  if (scriptPubKey.toLowerCase() !== EXPECTED_SCRIPT_PUBKEYS[id]) {
    throw new Error(`validateaddress does not match local descriptor script commitment for ${id}`);
  }
  return EXPECTED_SCRIPT_PUBKEYS[id];
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
      !/^[0-9a-f]{64}$/i.test(entry["txid"]) ||
      !Number.isSafeInteger(entry["vout"]) ||
      (entry["vout"] as number) < 0 ||
      !Number.isSafeInteger(entry["height"]) ||
      (entry["height"] as number) < 0 ||
      (typeof entry["amount"] !== "string" && typeof entry["amount"] !== "number")
    ) {
      throw new Error(`scantxoutset unspent ${index} is invalid`);
    }
    return {
      txid: entry["txid"].toLowerCase(),
      vout: entry["vout"] as number,
      amount: entry["amount"] as string | number,
      height: entry["height"] as number,
    };
  });
  return { success: true, unspents };
}

function parseGeneratedBlocks(value: unknown, expectedCount: number): void {
  if (
    !Array.isArray(value) ||
    value.length !== expectedCount ||
    value.some((blockHash) => typeof blockHash !== "string" || !/^[0-9a-f]{64}$/i.test(blockHash))
  ) {
    throw new Error("generatetoaddress returned invalid block hashes");
  }
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

async function canonicalizeDescriptors(
  rpc: RpcCaller,
  requiredIds: ReadonlySet<FixtureDescriptorId>,
): Promise<Record<FixtureDescriptorId, CanonicalDescriptor>> {
  const entries = await Promise.all(
    (Object.entries(FIXTURE_DESCRIPTORS) as Array<[FixtureDescriptorId, string]>)
      .filter(([id]) => requiredIds.has(id))
      .map(async ([id, raw]) => {
        const descriptorInfo = parseDescriptorInfo(
          await rpc.call("getdescriptorinfo", { descriptor: raw }),
        );
        if (descriptorInfo.isrange) throw new Error(`Fixture descriptor ${id} must not be ranged`);
        const addresses = await rpc.call<unknown>("deriveaddresses", {
          descriptor: descriptorInfo.descriptor,
        });
        if (!Array.isArray(addresses) || addresses.length !== 1) {
          throw new Error(`deriveaddresses did not return one fixture address for ${id}`);
        }
        const address = parseAddress(addresses[0], `deriveaddresses ${id}`);
        return [
          id,
          {
            id,
            descriptor: descriptorInfo.descriptor,
            address,
            scriptPubKey: parseValidatedScriptPubKey(
              await rpc.call("validateaddress", { address }),
              id,
              address,
            ),
          },
        ] as const;
      }),
  );
  return Object.fromEntries(entries) as Record<FixtureDescriptorId, CanonicalDescriptor>;
}

async function scanFixtureUtxos(
  rpc: RpcCaller,
  descriptor: string,
  blocks: number,
): Promise<FixtureOutpoint[]> {
  const previousScan = scanLockTail;
  let releaseScan: (() => void) | undefined;
  scanLockTail = new Promise<void>((resolve) => {
    releaseScan = resolve;
  });
  await previousScan;
  let result: ScanResult;
  try {
    result = parseScan(
      await rpc.call("scantxoutset", {
        action: "start",
        scanobjects: [descriptor],
      }),
    );
  } finally {
    releaseScan?.();
  }
  const selected = result.unspents
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
  const seen = new Set<string>();
  for (const outpoint of selected) {
    const key = `${outpoint.txid}:${outpoint.vout}`;
    if (seen.has(key)) throw new Error(`scantxoutset returned duplicate fixture UTXO ${key}`);
    seen.add(key);
  }
  return selected;
}

function fixturePlans(
  customPlans: readonly CompiledUserFixturePlan[],
  requiredFixtureIds?: readonly BuiltInFixtureId[],
): readonly FixturePlan[] {
  const builtInPlans: readonly FixturePlan[] = [
    {
      id: "happy-path",
      scriptTypes: ["p2wsh"],
      inputDescriptorIds: [LEGACY_DESCRIPTOR_ID],
      outputDescriptorIds: [LEGACY_DESCRIPTOR_ID],
      sequences: [DEFAULT_SEQUENCE],
      locktime: 0,
      transactionVersion: 2,
      feeSats: 10_000,
    },
    {
      id: "bdk-finalize-regression",
      scriptTypes: ["p2wsh"],
      inputDescriptorIds: [LEGACY_DESCRIPTOR_ID, LEGACY_DESCRIPTOR_ID],
      outputDescriptorIds: [LEGACY_DESCRIPTOR_ID],
      sequences: [DEFAULT_SEQUENCE, DEFAULT_SEQUENCE],
      locktime: 0,
      transactionVersion: 2,
      feeSats: 20_000,
    },
    ...FIXTURE_PROFILES.map((profile) => ({
      id: profile.id,
      scriptTypes: profile.scriptTypes,
      inputDescriptorIds: profile.inputDescriptorIds,
      outputDescriptorIds: profile.outputDescriptorIds,
      sequences: profile.sequences,
      locktime: profile.locktime,
      transactionVersion: profile.transactionVersion,
      feeSats: profile.feeSats,
    })),
  ];
  const selectedIds = requiredFixtureIds ? new Set(requiredFixtureIds) : undefined;
  if (selectedIds) {
    const knownIds = new Set(builtInPlans.map((plan) => plan.id));
    for (const id of selectedIds) {
      if (!knownIds.has(id)) throw new TypeError(`Unknown built-in fixture ${id}`);
    }
  }
  const plans: readonly FixturePlan[] = [
    ...builtInPlans.filter((plan) => selectedIds?.has(plan.id as BuiltInFixtureId) ?? true),
    ...customPlans.map((plan) => ({
      id: plan.id,
      scriptTypes: plan.scriptTypes,
      inputDescriptorIds: plan.inputDescriptorIds,
      outputDescriptorIds: plan.outputDescriptorIds,
      sequences: plan.sequences,
      locktime: plan.locktime,
      transactionVersion: plan.transactionVersion,
      feeSats: plan.feeSats,
      outputAmounts: plan.outputAmounts,
      specSha256: plan.specSha256,
    })),
  ];
  const ids = new Set<string>();
  for (const plan of plans) {
    if (ids.has(plan.id)) throw new Error(`Duplicate fixture plan id ${plan.id}`);
    ids.add(plan.id);
  }
  for (const plan of plans) assertFixturePlan(plan);
  return plans;
}

function assertFixturePlan(plan: FixturePlan): void {
  if (
    plan.inputDescriptorIds.length === 0 ||
    plan.scriptTypes.length === 0 ||
    plan.sequences.length !== plan.inputDescriptorIds.length
  ) {
    throw new Error(`Fixture ${plan.id} has inconsistent input intent`);
  }
  if (plan.outputDescriptorIds.length === 0) {
    throw new Error(`Fixture ${plan.id} must declare at least one output`);
  }
  if (
    plan.transactionVersion !== 2 ||
    !Number.isSafeInteger(plan.locktime) ||
    plan.locktime < 0 ||
    plan.locktime > MAX_UINT32
  ) {
    throw new Error(`Fixture ${plan.id} has invalid transaction intent`);
  }
  if (
    plan.sequences.some(
      (sequence) =>
        !Number.isSafeInteger(sequence) ||
        sequence < 0 ||
        sequence > MAX_UINT32 ||
        sequence >= 0xffff_fffe,
    )
  ) {
    throw new Error(`Fixture ${plan.id} must declare one exact RBF sequence per input`);
  }
  if (!Number.isSafeInteger(plan.feeSats) || plan.feeSats <= 0) {
    throw new Error(`Fixture ${plan.id} has an invalid exact-satoshi fee`);
  }
  if (plan.outputAmounts) {
    if (
      plan.outputAmounts.length !== plan.outputDescriptorIds.length ||
      plan.outputAmounts.filter((amount) => amount === null).length !== 1 ||
      plan.outputAmounts.some(
        (amount) => amount !== null && (!Number.isSafeInteger(amount) || amount <= 0),
      )
    ) {
      throw new Error(`Fixture ${plan.id} has invalid custom output amounts`);
    }
  }
  if (plan.specSha256 && !/^sha256:[0-9a-f]{64}$/.test(plan.specSha256)) {
    throw new Error(`Fixture ${plan.id} has an invalid specification commitment`);
  }
}

function requiredUtxos(plans: readonly FixturePlan[]): Record<FixtureDescriptorId, number> {
  const required = Object.fromEntries(
    (Object.keys(FIXTURE_DESCRIPTORS) as FixtureDescriptorId[]).map((id) => [id, 0]),
  ) as Record<FixtureDescriptorId, number>;
  for (const plan of plans) {
    for (const id of plan.inputDescriptorIds) required[id] += 1;
  }
  return required;
}

function requiredDescriptorIds(plans: readonly FixturePlan[]): Set<FixtureDescriptorId> {
  return new Set(
    plans.flatMap((plan) => [...plan.inputDescriptorIds, ...plan.outputDescriptorIds]),
  );
}

async function scanAllFixtureUtxos(
  rpc: RpcCaller,
  descriptors: Record<FixtureDescriptorId, CanonicalDescriptor>,
  blocks: number,
): Promise<Record<FixtureDescriptorId, FixtureOutpoint[]>> {
  const entries: Array<readonly [FixtureDescriptorId, FixtureOutpoint[]]> = [];
  for (const id of Object.keys(descriptors) as FixtureDescriptorId[]) {
    entries.push([id, await scanFixtureUtxos(rpc, descriptors[id].descriptor, blocks)]);
  }
  return Object.fromEntries(entries) as Record<FixtureDescriptorId, FixtureOutpoint[]>;
}

async function ensureMatureUtxos(
  rpc: RpcCaller,
  blockchain: BlockchainInfo,
  descriptors: Record<FixtureDescriptorId, CanonicalDescriptor>,
  plans: readonly FixturePlan[],
): Promise<{ blockchain: BlockchainInfo; utxos: Record<FixtureDescriptorId, FixtureOutpoint[]> }> {
  const required = requiredUtxos(plans);
  let currentBlockchain = blockchain;
  let utxos = await scanAllFixtureUtxos(rpc, descriptors, currentBlockchain.blocks);
  const shortages = (Object.keys(descriptors) as FixtureDescriptorId[]).map((id) => ({
    id,
    count: Math.max(0, required[id] - utxos[id].length),
  }));
  if (shortages.every((shortage) => shortage.count === 0)) return { blockchain, utxos };
  const maturitySink = shortages.find((shortage) => shortage.count > 0);
  if (!maturitySink) throw new Error("Fixture funding shortage could not be resolved");

  for (const shortage of shortages) {
    if (shortage.count === 0) continue;
    parseGeneratedBlocks(
      await rpc.call("generatetoaddress", {
        nblocks: shortage.count,
        address: descriptors[shortage.id].address,
        maxtries: DEFAULT_GENERATE_MAX_TRIES,
      }),
      shortage.count,
    );
  }
  parseGeneratedBlocks(
    await rpc.call("generatetoaddress", {
      nblocks: COINBASE_MATURITY_BLOCKS,
      address: descriptors[maturitySink.id].address,
      maxtries: DEFAULT_GENERATE_MAX_TRIES,
    }),
    COINBASE_MATURITY_BLOCKS,
  );
  currentBlockchain = parseBlockchainInfo(await rpc.call("getblockchaininfo"));
  utxos = await scanAllFixtureUtxos(rpc, descriptors, currentBlockchain.blocks);
  for (const id of Object.keys(descriptors) as FixtureDescriptorId[]) {
    if (utxos[id].length < required[id]) {
      throw new Error(
        `Could not create ${required[id]} mature deterministic regtest UTXOs for ${id}`,
      );
    }
  }
  return { blockchain: currentBlockchain, utxos };
}

function assertPsbtFacts(
  encoded: string,
  id: FixtureId,
  inputCount: number,
  outputCount: number,
): ReturnType<typeof extractWireFacts> {
  if (typeof encoded !== "string") throw new Error(`${id} RPC did not return a base64 PSBT`);
  const facts = extractWireFacts(encoded);
  if (
    facts.psbtVersion !== 0 ||
    facts.inputCount !== inputCount ||
    facts.outputCount !== outputCount
  ) {
    throw new Error(`Fixture ${id} has unexpected PSBT structure`);
  }
  return facts;
}

function unsignedTransactionSha256(encoded: string, id: FixtureId): `sha256:${string}` {
  const document = parsePsbtDocument(encoded);
  const globalMaps = document.maps.filter((map) => map.location.kind === "global");
  const unsignedTransactions = globalMaps[0]?.entries.filter(
    (entry) => entry.keyType === 0 && entry.keyData.byteLength === 0,
  );
  const unsignedTransaction = unsignedTransactions?.[0];
  if (
    document.psbtVersion !== 0 ||
    globalMaps.length !== 1 ||
    unsignedTransactions?.length !== 1 ||
    !unsignedTransaction ||
    !/^[0-9a-f]{64}$/.test(unsignedTransaction.valueSha256)
  ) {
    throw new Error(`Fixture ${id} lacks one valid PSBTv0 unsigned transaction`);
  }
  return `sha256:${createHash("sha256").update(unsignedTransaction.value).digest("hex")}`;
}

function allocateOutputSats(inputSats: number, plan: FixturePlan): readonly number[] {
  const spendableSats = inputSats - plan.feeSats;
  const outputCount = plan.outputDescriptorIds.length;
  if (
    !Number.isSafeInteger(inputSats) ||
    !Number.isSafeInteger(spendableSats) ||
    spendableSats < outputCount
  ) {
    throw new Error(`Fixture ${plan.id} has an invalid amount or fee`);
  }
  if (plan.outputAmounts) {
    const fixedTotal = plan.outputAmounts.reduce<number>(
      (sum, amount) => sum + (amount === null ? 0 : amount),
      0,
    );
    const remainder = spendableSats - fixedTotal;
    if (!Number.isSafeInteger(remainder) || remainder <= 0) {
      throw new Error(`Fixture ${plan.id} fixed outputs and fee exceed its selected inputs`);
    }
    return plan.outputAmounts.map((amount) => amount ?? remainder);
  }
  const amountPerOutput = Math.floor(spendableSats / outputCount);
  const remainder = spendableSats % outputCount;
  return Array.from(
    { length: outputCount },
    (_, index) => amountPerOutput + (index < remainder ? 1 : 0),
  );
}

function assertDecodedFixture(
  value: unknown,
  encoded: string,
  plan: FixturePlan,
  outpoints: readonly FixtureOutpoint[],
  outputSats: readonly number[],
  descriptors: Record<FixtureDescriptorId, CanonicalDescriptor>,
): string {
  const inputMaps = parsePsbtDocument(encoded).maps.filter((map) => map.location.kind === "input");
  const decoded = assertObject(value, "decodepsbt");
  const transaction = assertObject(decoded["tx"], `Fixture ${plan.id} decoded transaction`);
  const transactionId = assertHex(transaction["txid"], 32, `Fixture ${plan.id} transaction id`);
  if (transaction["version"] !== plan.transactionVersion) {
    throw new Error(`Fixture ${plan.id} decoded transaction version does not match intent`);
  }
  if (transaction["locktime"] !== plan.locktime) {
    throw new Error(`Fixture ${plan.id} decoded transaction locktime does not match intent`);
  }
  if (!Array.isArray(transaction["vin"]) || transaction["vin"].length !== outpoints.length) {
    throw new Error(`Fixture ${plan.id} has invalid decoded transaction inputs`);
  }
  if (
    !Array.isArray(transaction["vout"]) ||
    transaction["vout"].length !== plan.outputDescriptorIds.length ||
    outputSats.length !== plan.outputDescriptorIds.length
  ) {
    throw new Error(`Fixture ${plan.id} has invalid decoded transaction outputs`);
  }
  for (const [index, rawVin] of transaction["vin"].entries()) {
    const vin = assertObject(rawVin, `Fixture ${plan.id} decoded transaction input ${index}`);
    const outpoint = outpoints[index];
    const sequence = plan.sequences[index];
    if (
      !outpoint ||
      sequence === undefined ||
      vin["txid"] !== outpoint.txid ||
      vin["vout"] !== outpoint.vout
    ) {
      throw new Error(
        `Fixture ${plan.id} decoded transaction input ${index} does not match selection`,
      );
    }
    if (vin["sequence"] !== sequence) {
      throw new Error(`Fixture ${plan.id} decoded input ${index} sequence does not match intent`);
    }
  }
  for (const [index, rawOutput] of transaction["vout"].entries()) {
    const output = assertObject(
      rawOutput,
      `Fixture ${plan.id} decoded transaction output ${index}`,
    );
    const amountSats = outputSats[index];
    const descriptorId = plan.outputDescriptorIds[index];
    if (
      amountSats === undefined ||
      !descriptorId ||
      (typeof output["value"] !== "string" && typeof output["value"] !== "number") ||
      btcToSats(output["value"]) !== amountSats
    ) {
      throw new Error(`Fixture ${plan.id} decoded transaction output ${index} amount is invalid`);
    }
    if (
      parseDecodedScript(
        output["scriptPubKey"],
        `Fixture ${plan.id} decoded transaction output ${index} scriptPubKey`,
      ) !== descriptors[descriptorId].scriptPubKey
    ) {
      throw new Error(`Fixture ${plan.id} decoded output script does not match descriptor`);
    }
  }
  if (!Array.isArray(decoded["inputs"]) || decoded["inputs"].length !== outpoints.length) {
    throw new Error(`Fixture ${plan.id} has invalid decoded inputs`);
  }
  for (const [index, rawInput] of decoded["inputs"].entries()) {
    const input = assertObject(rawInput, `Fixture ${plan.id} input ${index}`);
    const witnessUtxo = assertObject(
      input["witness_utxo"],
      `Fixture ${plan.id} input ${index} witness UTXO`,
    );
    const outpoint = outpoints[index];
    const descriptorId = plan.inputDescriptorIds[index];
    const scriptType = plan.scriptTypes[index] ?? plan.scriptTypes[0];
    const inputMap = inputMaps[index];
    if (
      !outpoint ||
      !inputMap ||
      !descriptorId ||
      (typeof witnessUtxo["amount"] !== "string" && typeof witnessUtxo["amount"] !== "number") ||
      btcToSats(witnessUtxo["amount"]) !== outpoint.amountSats
    ) {
      throw new Error(`Fixture ${plan.id} input ${index} has invalid witness UTXO metadata`);
    }
    if (
      parseDecodedScript(
        witnessUtxo["scriptPubKey"],
        `Fixture ${plan.id} input ${index} witness UTXO scriptPubKey`,
      ) !== descriptors[descriptorId].scriptPubKey
    ) {
      throw new Error(
        `Fixture ${plan.id} input ${index} witness UTXO script does not match descriptor`,
      );
    }
    const expectedWitnessScript =
      EXPECTED_WITNESS_SCRIPTS[descriptorId as keyof typeof EXPECTED_WITNESS_SCRIPTS];
    const expectedRedeemScript =
      EXPECTED_REDEEM_SCRIPTS[descriptorId as keyof typeof EXPECTED_REDEEM_SCRIPTS];
    if (scriptType === "p2wsh" && !expectedWitnessScript) {
      throw new Error(`Fixture ${plan.id} input ${index} has no declared witness script`);
    }
    if (
      expectedWitnessScript &&
      parseDecodedScript(
        input["witness_script"],
        `Fixture ${plan.id} input ${index} witness script`,
      ) !== expectedWitnessScript
    ) {
      throw new Error(`Fixture ${plan.id} input ${index} witness script does not match descriptor`);
    }
    if (
      expectedRedeemScript &&
      parseDecodedScript(
        input["redeem_script"],
        `Fixture ${plan.id} input ${index} redeem script`,
      ) !== expectedRedeemScript
    ) {
      throw new Error(`Fixture ${plan.id} input ${index} redeem script does not match descriptor`);
    }
    if (scriptType === "p2tr-keypath" || scriptType === "p2tr-scriptpath") {
      if (input["taproot_internal_key"] !== FIXTURE_PUBLIC_KEYS.scalar1.slice(2)) {
        throw new Error(`Fixture ${plan.id} input ${index} lacks Taproot internal-key metadata`);
      }
    }
    if (scriptType === "p2tr-scriptpath") {
      const leafEntries = inputMap.entries.filter((entry) => entry.keyType === 0x15);
      const internalKeyEntries = inputMap.entries.filter((entry) => entry.keyType === 0x17);
      const leaf = leafEntries[0];
      const internalKey = internalKeyEntries[0];
      if (
        leafEntries.length !== 1 ||
        internalKeyEntries.length !== 1 ||
        !leaf ||
        !internalKey ||
        leaf.keyData.byteLength < 33 ||
        (leaf.keyData[0] as number) >> 1 !== 0x60 ||
        leaf.keyData.subarray(1, 33).toString("hex") !== FIXTURE_PUBLIC_KEYS.scalar1.slice(2) ||
        leaf.value.toString("hex") !== `${TAPROOT_SINGLE_KEY_LEAF_SCRIPT}c0` ||
        internalKey.value.toString("hex") !== FIXTURE_PUBLIC_KEYS.scalar1.slice(2)
      ) {
        throw new Error(
          `Fixture ${plan.id} input ${index} lacks exact Taproot script-path metadata`,
        );
      }
    }
  }
  if (
    (typeof decoded["fee"] !== "string" && typeof decoded["fee"] !== "number") ||
    btcToSats(decoded["fee"]) !== plan.feeSats
  ) {
    throw new Error(`Fixture ${plan.id} decoded fee does not match exact satoshi fee`);
  }
  return transactionId;
}

function freezeTransactionIntent(
  plan: FixturePlan,
  outputDescriptors: readonly CanonicalDescriptor[],
  outputSats: readonly number[],
): FixtureTransactionIntent {
  const outputs = Object.freeze(
    outputDescriptors.map((descriptor, index) => {
      const amountSats = outputSats[index];
      if (amountSats === undefined) {
        throw new Error(`Fixture ${plan.id} lacks output amount ${index}`);
      }
      return Object.freeze({
        descriptor: descriptor.descriptor,
        amountSats,
      });
    }),
  );
  return Object.freeze({
    version: plan.transactionVersion,
    locktime: plan.locktime,
    sequences: Object.freeze([...plan.sequences]),
    outputCount: outputs.length,
    outputs,
  });
}

async function buildFixture(
  rpc: RpcCaller,
  plan: FixturePlan,
  outpoints: FixtureOutpoint[],
  descriptors: Record<FixtureDescriptorId, CanonicalDescriptor>,
): Promise<PreparedPsbtFixture> {
  const inputSats = outpoints.reduce((sum, outpoint) => sum + outpoint.amountSats, 0);
  const outputSats = allocateOutputSats(inputSats, plan);
  const outputDescriptors = plan.outputDescriptorIds.map((id) => descriptors[id]);
  const outputDescriptor = outputDescriptors[0];
  if (!outputDescriptor) throw new Error(`Fixture ${plan.id} has no output descriptor`);
  const inputDescriptors = [
    ...new Set(plan.inputDescriptorIds.map((id) => descriptors[id].descriptor)),
  ];
  const created = await rpc.call<string>("createpsbt", {
    inputs: outpoints.map((outpoint, index) => {
      const sequence = plan.sequences[index];
      if (sequence === undefined)
        throw new Error(`Fixture ${plan.id} lacks input sequence ${index}`);
      return { txid: outpoint.txid, vout: outpoint.vout, sequence };
    }),
    outputs: outputDescriptors.map((descriptor, index) => {
      const amountSats = outputSats[index];
      if (amountSats === undefined) {
        throw new Error(`Fixture ${plan.id} lacks output amount ${index}`);
      }
      return { [descriptor.address]: satsToBtcString(amountSats) };
    }),
    locktime: plan.locktime,
    replaceable: true,
    version: plan.transactionVersion,
  });
  assertPsbtFacts(created, plan.id, outpoints.length, outputDescriptors.length);
  const updated = await rpc.call<string>("utxoupdatepsbt", {
    psbt: created,
    descriptors: inputDescriptors,
  });
  const facts = assertPsbtFacts(updated, plan.id, outpoints.length, outputDescriptors.length);
  const transactionId = assertDecodedFixture(
    await rpc.call("decodepsbt", { psbt: updated }),
    updated,
    plan,
    outpoints,
    outputSats,
    descriptors,
  );
  return {
    id: plan.id,
    initialPsbt: updated,
    outpoints,
    inputCount: facts.inputCount,
    outputCount: facts.outputCount,
    feeSats: plan.feeSats,
    scriptTypes: plan.scriptTypes,
    inputDescriptors,
    outputDescriptor: outputDescriptor.descriptor,
    psbtVersion: 0,
    transactionId,
    psbtSha256: facts.sha256,
    unsignedTxSha256: unsignedTransactionSha256(updated, plan.id),
    ...(plan.specSha256 ? { specSha256: plan.specSha256 } : {}),
    transactionIntent: freezeTransactionIntent(plan, outputDescriptors, outputSats),
  };
}

function takeOutpoint(
  available: Record<FixtureDescriptorId, FixtureOutpoint[]>,
  id: FixtureDescriptorId,
): FixtureOutpoint {
  const outpoint = available[id].shift();
  if (!outpoint) throw new Error(`Fixture UTXO selection failed for ${id}`);
  return outpoint;
}

export function prepareFixtures(
  rpc: RpcCaller,
  customPlans?: readonly CompiledUserFixturePlan[],
): Promise<PreparedFixtures>;
export function prepareFixtures(
  rpc: RpcCaller,
  customPlans: readonly CompiledUserFixturePlan[],
  requiredFixtureIds: readonly BuiltInFixtureId[],
): Promise<PreparedFixtureSet>;
export async function prepareFixtures(
  rpc: RpcCaller,
  customPlans: readonly CompiledUserFixturePlan[] = [],
  requiredFixtureIds?: readonly BuiltInFixtureId[],
): Promise<PreparedFixtureSet> {
  let blockchain = parseBlockchainInfo(await rpc.call("getblockchaininfo"));
  if (blockchain.chain !== "regtest") {
    throw new Error("PSBT Interop Lab refuses to run outside Bitcoin Core regtest");
  }
  const network = parseNetworkInfo(await rpc.call("getnetworkinfo"));
  if (network.version !== BITCOIN_CORE_VERSION) {
    throw new Error(
      `PSBT Interop Lab requires Bitcoin Core 31.1 (${BITCOIN_CORE_VERSION}); received ${network.version}`,
    );
  }
  if (network.connections !== 0) {
    throw new Error("PSBT Interop Lab requires Bitcoin Core to have zero peer connections");
  }
  if (network.networkActive !== false) {
    throw new Error("PSBT Interop Lab requires Bitcoin Core networking to be disabled");
  }

  const plans = fixturePlans(customPlans, requiredFixtureIds);
  if (plans.length === 0) throw new TypeError("At least one fixture must be requested");
  const descriptors = await canonicalizeDescriptors(rpc, requiredDescriptorIds(plans));
  const funded = await ensureMatureUtxos(rpc, blockchain, descriptors, plans);
  blockchain = funded.blockchain;
  const available = Object.fromEntries(
    (Object.keys(funded.utxos) as FixtureDescriptorId[]).map((id) => [id, [...funded.utxos[id]]]),
  ) as Record<FixtureDescriptorId, FixtureOutpoint[]>;
  const fixtures = new Map<string, PreparedPsbtFixture>();
  for (const plan of plans) {
    const outpoints = plan.inputDescriptorIds.map((id) => takeOutpoint(available, id));
    fixtures.set(plan.id, await buildFixture(rpc, plan, outpoints, descriptors));
  }
  const happy = fixtures.get("happy-path");
  const regression = fixtures.get("bdk-finalize-regression");
  const profiles = Object.fromEntries(
    FIXTURE_PROFILES.filter((profile) => fixtures.has(profile.id)).map((profile) => {
      const fixture = fixtures.get(profile.id);
      if (!fixture) throw new Error(`Profile fixture construction failed for ${profile.id}`);
      return [profile.id, fixture] as const;
    }),
  ) as Partial<Record<FixtureProfileId, PreparedPsbtFixture>>;
  const custom = Object.fromEntries(
    customPlans.map((plan) => {
      const fixture = fixtures.get(plan.id);
      if (!fixture) throw new Error(`Custom fixture construction failed for ${plan.id}`);
      return [plan.id, fixture] as const;
    }),
  );
  const legacyDescriptor = descriptors[LEGACY_DESCRIPTOR_ID];
  const prepared: PreparedFixtureSet = {
    core: {
      version: network.version,
      subversion: network.subversion,
      blocks: blockchain.blocks,
      connections: network.connections,
    },
    ...(legacyDescriptor
      ? { descriptor: legacyDescriptor.descriptor, address: legacyDescriptor.address }
      : {}),
    ...(happy ? { happy } : {}),
    ...(regression ? { regression } : {}),
    profiles,
    custom,
  };
  if (requiredFixtureIds === undefined) {
    if (!prepared.descriptor || !prepared.address || !happy || !regression) {
      throw new Error("Legacy fixture construction failed");
    }
    if (Object.keys(profiles).length !== FIXTURE_PROFILES.length) {
      throw new Error("Profile fixture construction failed");
    }
  }
  return prepared;
}
