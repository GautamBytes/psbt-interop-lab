import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { schnorr } from "@noble/curves/secp256k1.js";
import * as musig2 from "@scure/btc-signer/musig2.js";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";

import { createMusig2ScureAdapter, PROTOCOL, parseFixtureCommitments } from "../adapter.mjs";

bitcoin.initEccLib(ecc);

const DIGEST = `sha256:${"a".repeat(64)}`;
const SECRET_ONE = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const SECRET_TWO = Buffer.concat([Buffer.alloc(31), Buffer.from([2])]);
const PUBLIC_KEYS = [SECRET_ONE, SECRET_TWO].map((secret) =>
  Buffer.from(musig2.IndividualPubkey(secret)),
);
const AGGREGATE_X_ONLY = Buffer.from(musig2.keyAggExport(musig2.keyAggregate(PUBLIC_KEYS)));
const AGGREGATE_COMPRESSED = Buffer.concat([Buffer.from([2]), AGGREGATE_X_ONLY]);
const ENTRYPOINT = fileURLToPath(new URL("../adapter.mjs", import.meta.url));

assert.equal(
  AGGREGATE_COMPRESSED.toString("hex"),
  "023b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec",
);

function request(operation, payload = {}, extra = {}) {
  return { protocol: PROTOCOL, id: "test-1", operation, payload, ...extra };
}

function bip373Key(type, participant) {
  return Buffer.concat([
    Buffer.from([type]),
    ...(participant ? [participant] : []),
    AGGREGATE_COMPRESSED,
  ]);
}

function addInputField(psbt, type, value, participant) {
  psbt.addUnknownKeyValToInput(0, {
    key: bip373Key(type, participant),
    value: Buffer.from(value),
  });
}

function fixturePsbt() {
  const script = Buffer.concat([Buffer.from([0x51, 0x20]), AGGREGATE_X_ONLY]);
  const funding = new bitcoin.Transaction();
  funding.version = 2;
  funding.addInput(Buffer.alloc(32), 0xffffffff);
  funding.addOutput(script, 5_000_000_000n);

  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
  psbt.addInput({
    hash: funding.getId(),
    index: 0,
    witnessUtxo: { script, value: 5_000_000_000n },
  });
  psbt.addOutput({ script, value: 4_999_980_000n });
  addInputField(psbt, 0x1a, Buffer.concat(PUBLIC_KEYS));
  return psbt;
}

function unsignedCommitment(psbt) {
  return `sha256:${createHash("sha256")
    .update(psbt.data.globalMap.unsignedTx.toBuffer())
    .digest("hex")}`;
}

function fixtureConfig(psbt, overrides = {}) {
  return {
    fixtureCommitments: new Map([["p2tr-musig2", unsignedCommitment(psbt)]]),
    randomBytes: () => Buffer.alloc(32, 7),
    now: () => 1_000,
    ...overrides,
  };
}

function taprootMessage(psbt) {
  const input = psbt.data.inputs[0];
  assert.ok(input?.witnessUtxo);
  const tx = bitcoin.Transaction.fromBuffer(psbt.data.globalMap.unsignedTx.toBuffer());
  return Buffer.from(
    tx.hashForWitnessV1(
      0,
      [Buffer.from(input.witnessUtxo.script)],
      [input.witnessUtxo.value],
      bitcoin.Transaction.SIGHASH_DEFAULT,
    ),
  );
}

function fieldValue(psbt, type, participant) {
  const expected = bip373Key(type, participant);
  const entry = psbt.data.inputs[0]?.unknownKeyVals?.find(({ key }) =>
    Buffer.from(key).equals(expected),
  );
  assert.ok(entry, `missing field ${type.toString(16)}`);
  return Buffer.from(entry.value);
}

test("advertises an independently identified Scure MuSig2 signer", () => {
  const adapter = createMusig2ScureAdapter(fixtureConfig(fixturePsbt()));
  const result = adapter.handleValue(request("hello"), DIGEST);

  assert.equal(result.status, "ok");
  assert.deepEqual(result.implementation, {
    name: "musig2-scure-signer-2",
    version: "0.1.0",
    artifactDigest: DIGEST,
    sourceRevision: "@scure/btc-signer@2.2.0+bitcoinjs-lib@7.0.1",
  });
  assert.deepEqual(result.output.operations, [
    "hello",
    "native-parse",
    "roundtrip",
    "musig2-nonce",
    "musig2-partial-sign",
    "musig2-aggregate",
  ]);
  assert.ok(result.output.features.includes("bip327-csprng-nonce-v1"));
});

test("produces a signer-two partial that interoperates with an independent participant", () => {
  const source = fixturePsbt();
  const message = taprootMessage(source);
  const sessionId = "interop-session";
  const nonceOne = musig2.nonceGen(
    PUBLIC_KEYS[0],
    SECRET_ONE,
    AGGREGATE_X_ONLY,
    message,
    Buffer.from(sessionId),
    Buffer.alloc(32, 3),
  );
  addInputField(source, 0x1b, nonceOne.public, PUBLIC_KEYS[0]);
  const adapter = createMusig2ScureAdapter(fixtureConfig(source));

  const nonceResult = adapter.handleValue(
    request("musig2-nonce", {
      psbt: source.toBase64(),
      fixtureId: "p2tr-musig2",
      sessionId,
    }),
    DIGEST,
  );
  assert.equal(nonceResult.status, "ok");
  const withNonces = bitcoin.Psbt.fromBase64(nonceResult.output.psbt);
  const nonceTwo = fieldValue(withNonces, 0x1b, PUBLIC_KEYS[1]);
  const publicNonces = [Buffer.from(nonceOne.public), nonceTwo];
  const session = new musig2.Session(musig2.nonceAggregate(publicNonces), PUBLIC_KEYS, message);
  const partialOne = Buffer.from(session.sign(Buffer.from(nonceOne.secret), SECRET_ONE));
  addInputField(withNonces, 0x1c, partialOne, PUBLIC_KEYS[0]);

  const partialResult = adapter.handleValue(
    request("musig2-partial-sign", {
      psbt: withNonces.toBase64(),
      fixtureId: "p2tr-musig2",
      sessionId,
    }),
    DIGEST,
  );
  assert.equal(partialResult.status, "ok");
  const withPartials = bitcoin.Psbt.fromBase64(partialResult.output.psbt);
  const partialTwo = fieldValue(withPartials, 0x1c, PUBLIC_KEYS[1]);
  assert.equal(session.partialSigVerify(partialOne, publicNonces, 0), true);
  assert.equal(session.partialSigVerify(partialTwo, publicNonces, 1), true);
  const signature = Buffer.from(session.partialSigAgg([partialOne, partialTwo]));
  assert.equal(schnorr.verify(signature, message, AGGREGATE_X_ONLY), true);

  const aggregateResult = adapter.handleValue(
    request("musig2-aggregate", {
      psbt: withPartials.toBase64(),
      fixtureId: "p2tr-musig2",
    }),
    DIGEST,
  );
  assert.equal(aggregateResult.status, "ok");
  assert.deepEqual(
    Buffer.from(bitcoin.Psbt.fromBase64(aggregateResult.output.psbt).data.inputs[0].tapKeySig),
    signature,
  );
});

test("refuses nonce reuse and consumes a secret nonce after partial signing", () => {
  const source = fixturePsbt();
  const adapter = createMusig2ScureAdapter(fixtureConfig(source));
  const payload = {
    psbt: source.toBase64(),
    fixtureId: "p2tr-musig2",
    sessionId: "single-use",
  };

  const first = adapter.handleValue(request("musig2-nonce", payload), DIGEST);
  assert.equal(first.status, "ok");
  const reused = adapter.handleValue(request("musig2-nonce", payload), DIGEST);
  assert.equal(reused.status, "rejected");
  assert.equal(reused.error.class, "musig2.nonce_reuse");

  const partial = adapter.handleValue(
    request("musig2-partial-sign", { ...payload, psbt: first.output.psbt }),
    DIGEST,
  );
  assert.equal(partial.status, "rejected");
  assert.equal(partial.error.class, "bip373.nonce_set");
  const repeated = adapter.handleValue(
    request("musig2-partial-sign", { ...payload, psbt: first.output.psbt }),
    DIGEST,
  );
  assert.equal(repeated.status, "rejected");
  assert.equal(repeated.error.class, "musig2.session_missing");
});

test("bounds live nonce sessions and permanently consumes expired session identifiers", () => {
  const source = fixturePsbt();
  let clock = 1_000;
  const adapter = createMusig2ScureAdapter(
    fixtureConfig(source, {
      now: () => clock,
    }),
  );
  const noncePayload = (sessionId) => ({
    psbt: source.toBase64(),
    fixtureId: "p2tr-musig2",
    sessionId,
  });

  for (let index = 0; index < 64; index += 1) {
    const result = adapter.handleValue(
      request("musig2-nonce", noncePayload(`bounded-${index}`)),
      DIGEST,
    );
    assert.equal(result.status, "ok");
  }
  const atLimit = adapter.handleValue(
    request("musig2-nonce", noncePayload("bounded-overflow")),
    DIGEST,
  );
  assert.equal(atLimit.status, "rejected");
  assert.equal(atLimit.error.class, "musig2.session_limit");

  clock += 15 * 60 * 1_000;
  const afterExpiry = adapter.handleValue(
    request("musig2-nonce", noncePayload("after-expiry")),
    DIGEST,
  );
  assert.equal(afterExpiry.status, "ok");
  const reusedExpired = adapter.handleValue(
    request("musig2-nonce", noncePayload("bounded-0")),
    DIGEST,
  );
  assert.equal(reusedExpired.status, "rejected");
  assert.equal(reusedExpired.error.class, "musig2.nonce_reuse");
});

test("rejects uncommitted fixtures and malformed request shapes", () => {
  const source = fixturePsbt();
  const adapter = createMusig2ScureAdapter({
    ...fixtureConfig(source),
    fixtureCommitments: new Map([["p2tr-musig2", `sha256:${"0".repeat(64)}`]]),
  });
  const mismatch = adapter.handleValue(
    request("musig2-nonce", {
      psbt: source.toBase64(),
      fixtureId: "p2tr-musig2",
      sessionId: "bad-commitment",
    }),
    DIGEST,
  );
  assert.equal(mismatch.status, "rejected");
  assert.equal(mismatch.error.class, "fixture.commitment_mismatch");

  const extra = adapter.handleValue(request("hello", {}, { unexpected: true }), DIGEST);
  assert.equal(extra.status, "rejected");
  assert.equal(extra.error.class, "protocol.invalid_request");
  const malformed = adapter.handleValue(request("native-parse", { psbt: "cHNidP8" }), DIGEST);
  assert.equal(malformed.status, "rejected");
  assert.equal(malformed.error.class, "psbt.native_parse_failed");
});

test("strictly parses one bounded fixture commitment", () => {
  const valid = `sha256:${"b".repeat(64)}`;
  assert.deepEqual(parseFixtureCommitments(JSON.stringify({ "p2tr-musig2": valid })), {
    fixtureCommitments: new Map([["p2tr-musig2", valid]]),
  });
  assert.equal(parseFixtureCommitments(undefined).fixtureCommitmentsError, "missing");
  assert.equal(parseFixtureCommitments("{}").fixtureCommitmentsError, "invalid");
  assert.equal(
    parseFixtureCommitments(JSON.stringify({ "p2tr-musig2": valid, extra: valid }))
      .fixtureCommitmentsError,
    "invalid",
  );
});

test("process returns one protocol response for one JSONL request", () => {
  const child = spawnSync(process.execPath, [ENTRYPOINT], {
    input: `${JSON.stringify(request("hello"))}\n`,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      PSBT_LAB_FIXTURE_COMMITMENTS: JSON.stringify({
        "p2tr-musig2": `sha256:${"c".repeat(64)}`,
      }),
    },
  });
  assert.equal(child.status, 0, child.stderr);
  const response = JSON.parse(child.stdout);
  assert.equal(response.status, "ok");
  assert.equal(response.implementation.name, "musig2-scure-signer-2");
});
