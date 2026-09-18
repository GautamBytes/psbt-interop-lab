import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { readCompactSize } from "../psbt/compact-size.js";
import { type PsbtDocumentMap, parsePsbtDocument } from "../psbt/document.js";

export const RECEIVER_SPEND_KEY =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
export const RECEIVER_DESTINATION = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
export const RECEIVER_FEE = 10_000n;
export interface DiscoveredOutput {
  index: number;
  amountSats: bigint;
  scriptHex: string;
  tweakHex: string;
}
const sha = (bytes: Buffer) => createHash("sha256").update(bytes).digest();
function tagged(tag: string, message: Buffer): Buffer {
  const h = sha(Buffer.from(tag));
  return sha(Buffer.concat([h, h, message]));
}
function field(map: PsbtDocumentMap, type: number): Buffer {
  const value = map.entries.find((e) => e.keyType === type && e.keyData.length === 0)?.value;
  if (!value) throw new Error(`Missing public transaction field ${type}`);
  return value;
}
function scalar(bytes: Buffer): bigint {
  const n = BigInt(`0x${bytes.toString("hex")}`);
  if (n === 0n || n >= secp256k1.Point.Fn.ORDER) throw new Error("Invalid BIP352 scalar");
  return n;
}
function inputPublicKey(map: PsbtDocumentMap): Buffer {
  const witness = field(map, 8),
    count = readCompactSize(witness, 0);
  if (count.value !== 2) throw new Error("Discovery requires a two-item P2WPKH witness");
  const signature = readCompactSize(witness, count.nextOffset);
  const key = readCompactSize(witness, signature.nextOffset + signature.value);
  if (
    signature.value < 9 ||
    signature.value > 73 ||
    key.value !== 33 ||
    key.nextOffset + 33 !== witness.length
  )
    throw new Error("Invalid P2WPKH witness");
  const pubkey = witness.subarray(key.nextOffset);
  const hash = createHash("ripemd160").update(sha(pubkey)).digest();
  const utxo = field(map, 1);
  if (
    utxo.length !== 31 ||
    !utxo.subarray(8).equals(Buffer.concat([Buffer.from([22, 0, 20]), hash]))
  )
    throw new Error("Witness key does not match P2WPKH funding");
  return pubkey;
}

// Deliberately ignores all sender SP shares, proofs and recipient metadata.
// This reference scanner supports only the bounded two-P2WPKH, single-recipient fixture.
export function discoverReceiverOutput(
  parent: string,
  scan = 2n,
  spend = RECEIVER_SPEND_KEY,
): DiscoveredOutput | undefined {
  if (scan <= 0n || scan >= secp256k1.Point.Fn.ORDER) throw new Error("Invalid receiver scan key");
  const doc = parsePsbtDocument(parent);
  if (doc.psbtVersion !== 2 || doc.inputCount !== 2 || doc.outputCount !== 2)
    throw new Error("Discovery requires the bounded two-input/two-output fixture");
  const inputs = doc.maps.filter((m) => m.location.kind === "input");
  const points = inputs.map((m) => secp256k1.Point.fromBytes(inputPublicKey(m)));
  const aggregate = points.reduce((a, b) => a.add(b));
  if (aggregate.equals(secp256k1.Point.ZERO)) throw new Error("Input keys cancel");
  const outpoints = inputs
    .map((m) => Buffer.concat([field(m, 14), field(m, 15)]))
    .sort(Buffer.compare);
  if (outpoints[0]?.equals(outpoints[1] ?? Buffer.alloc(0)))
    throw new Error("Duplicate funding outpoint");
  const lowest = outpoints[0];
  if (!lowest) throw new Error("Missing input outpoint");
  const inputHash = scalar(
    tagged("BIP0352/Inputs", Buffer.concat([lowest, Buffer.from(aggregate.toBytes(true))])),
  );
  const shared = aggregate.multiply(scan).multiply(inputHash);
  const tweak = tagged(
    "BIP0352/SharedSecret",
    Buffer.concat([Buffer.from(shared.toBytes(true)), Buffer.alloc(4)]),
  );
  const expected = secp256k1.Point.fromHex(spend).add(secp256k1.Point.BASE.multiply(scalar(tweak)));
  const script = Buffer.concat([
    Buffer.from([0x51, 0x20]),
    Buffer.from(expected.toBytes(true)).subarray(1),
  ]);
  const matches = doc.maps.filter(
    (m) => m.location.kind === "output" && field(m, 4).equals(script),
  );
  if (matches.length > 1) throw new Error("Duplicate recipient output outside the bounded fixture");
  const match = matches[0];
  if (match?.location.kind !== "output") return undefined;
  return {
    index: match.location.index,
    amountSats: field(match, 3).readBigUInt64LE(),
    scriptHex: script.toString("hex"),
    tweakHex: tweak.toString("hex"),
  };
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}
function u64(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}
function pair(type: number, value: Buffer, keyData = Buffer.alloc(0)): Buffer {
  if (value.length >= 253 || keyData.length >= 252)
    throw new Error("Fixture field exceeds compact single-byte encoding");
  return Buffer.concat([
    Buffer.from([1 + keyData.length, type]),
    keyData,
    Buffer.from([value.length]),
    value,
  ]);
}
export function createReceiverPsbt(txid: string, output: DiscoveredOutput): string {
  if (
    !/^[0-9a-f]{64}$/.test(txid) ||
    output.index !== 0 ||
    !/^5120[0-9a-f]{64}$/.test(output.scriptHex) ||
    !/^[0-9a-f]{64}$/.test(output.tweakHex) ||
    output.amountSats <= RECEIVER_FEE + 330n ||
    output.amountSats > 2_100_000_000_000_000n
  )
    throw new Error("Invalid discovered fixture output");
  scalar(Buffer.from(output.tweakHex, "hex"));
  const script = Buffer.from(output.scriptHex, "hex");
  const bytes = Buffer.concat([
    Buffer.from("70736274ff", "hex"),
    pair(0xfb, u32(2)),
    pair(2, u32(2)),
    pair(3, u32(0)),
    pair(4, Buffer.from([1])),
    pair(5, Buffer.from([1])),
    pair(6, Buffer.from([0])),
    Buffer.from([0]),
    pair(14, Buffer.from(txid, "hex").reverse()),
    pair(15, u32(output.index)),
    pair(16, u32(0xfffffffd)),
    pair(1, Buffer.concat([u64(output.amountSats), Buffer.from([script.length]), script])),
    pair(0x1f, Buffer.alloc(4), Buffer.from(RECEIVER_SPEND_KEY, "hex")),
    pair(0x20, Buffer.from(output.tweakHex, "hex")),
    Buffer.from([0]),
    pair(3, u64(output.amountSats - RECEIVER_FEE)),
    pair(4, Buffer.from(RECEIVER_DESTINATION, "hex")),
    Buffer.from([0]),
  ]);
  const encoded = bytes.toString("base64");
  parsePsbtDocument(encoded);
  return encoded;
}
