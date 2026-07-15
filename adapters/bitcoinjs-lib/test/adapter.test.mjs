import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import * as adapter from "../adapter.mjs";

import { handleValue, MAX_LINE_BYTES, PROTOCOL } from "../adapter.mjs";

const TEST_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const TEST_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(TEST_PRIVATE_KEY, true));
const TEST_WITNESS_SCRIPT = bitcoin.script.compile([TEST_PUBLIC_KEY, bitcoin.opcodes.OP_CHECKSIG]);
const TEST_SCRIPT_PUBKEY = bitcoin.payments.p2wsh({
  redeem: { output: TEST_WITNESS_SCRIPT },
}).output;
const DIGEST = `sha256:${"a".repeat(64)}`;
const IMPLEMENTATION_KEYS = ["artifactDigest", "name", "sourceRevision", "version"];
const RESPONSE_KEYS = ["id", "implementation", "output", "protocol", "status"];
const FAILURE_KEYS = ["error", "id", "implementation", "protocol", "status"];

function request(operation, payload = {}) {
  return { protocol: PROTOCOL, id: "test-1", operation, payload };
}

function response(value, config = fixtureConfig()) {
  return handleValue(value, DIGEST, config);
}

function fixturePsbt(inputCount = 1) {
  const funding = new bitcoin.Transaction();
  funding.version = 2;
  funding.addInput(Buffer.alloc(32), 0xffffffff);
  for (let index = 0; index < inputCount; index += 1) {
    funding.addOutput(TEST_SCRIPT_PUBKEY, 50_000n);
  }

  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
  for (let index = 0; index < inputCount; index += 1) {
    psbt.addInput({
      hash: funding.getId(),
      index,
      witnessUtxo: { script: TEST_SCRIPT_PUBKEY, value: 50_000n },
      witnessScript: TEST_WITNESS_SCRIPT,
    });
  }
  psbt.addOutput({ script: TEST_SCRIPT_PUBKEY, value: BigInt(50_000 * inputCount - 1_000) });
  return psbt;
}

function fixtureCommitment(psbt) {
  const unsignedTx = psbt.data.globalMap.unsignedTx.toBuffer();
  return `sha256:${createHash("sha256").update(unsignedTx).digest("hex")}`;
}

function fixtureConfig() {
  return {
    fixtureCommitments: new Map([
      ["happy-path", fixtureCommitment(fixturePsbt())],
      ["bdk-finalize-regression", fixtureCommitment(fixturePsbt(2))],
    ]),
  };
}

function signingPayload(psbt, fixtureId = "happy-path") {
  return { psbt: psbt.toBase64(), network: "regtest", fixtureId };
}

function assertSchemaShape(value) {
  assert.deepEqual(Object.keys(value).sort(), value.status === "ok" ? RESPONSE_KEYS : FAILURE_KEYS);
  assert.equal(value.protocol, PROTOCOL);
  assert.match(value.id, /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
  assert.deepEqual(Object.keys(value.implementation).sort(), IMPLEMENTATION_KEYS);
  assert.match(value.implementation.artifactDigest, /^sha256:[0-9a-f]{64}$/);
  if (value.status !== "ok") {
    assert.deepEqual(Object.keys(value.error).sort(), ["class", "message", "retryable"]);
    assert.equal(value.error.retryable, false);
    assert.ok(value.error.message.length > 0 && value.error.message.length <= 2048);
  }
}

test("hello advertises only proven PSBTv0 P2WSH operations", () => {
  const result = response(request("hello"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.output, {
    operations: ["hello", "inspect", "roundtrip", "sign", "combine", "finalize", "finalize-inputs"],
    roles: ["parser", "signer", "combiner", "finalizer"],
    psbtVersions: [0],
    scriptTypes: ["p2wsh"],
    features: ["fixture-commitment-sha256"],
  });
  assertSchemaShape(result);
});

test("roundtrip canonicalizes a valid PSBTv0 without changing it", () => {
  const psbt = fixturePsbt();
  const result = response(request("roundtrip", { psbt: psbt.toBase64() }));
  assert.equal(result.status, "ok");
  assert.equal(result.output.psbt, psbt.toBase64());
  assert.equal(result.output.byteIdentical, true);
  assert.equal(result.output.psbtVersion, 0);
  assertSchemaShape(result);
});

test("inspect returns bounded structural facts", () => {
  const result = response(request("inspect", { psbt: fixturePsbt(2).toBase64() }));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.output, { inputs: 2, outputs: 1, psbtVersion: 0 });
  assertSchemaShape(result);
});

test("rejects noncanonical base64, oversized PSBTs, malformed PSBTs, and PSBTv2", () => {
  const valid = fixturePsbt().toBase64();
  const cases = [
    `${valid}\n`,
    Buffer.from("not a psbt").toString("base64"),
    Buffer.alloc(MAX_LINE_BYTES + 1).toString("base64"),
    Buffer.concat([
      Buffer.from("70736274ff", "hex"),
      Buffer.from([1, 0xfb, 4, 2, 0, 0, 0, 0]),
    ]).toString("base64"),
  ];
  for (const psbt of cases) {
    const result = response(request("roundtrip", { psbt }));
    assert.equal(result.status, "rejected");
    assert.equal(result.error.class, "psbt.parse_failed");
    assertSchemaShape(result);
  }
});

test("rejects a PSBT whose base64 response would exceed the JSONL line cap", () => {
  const psbt = fixturePsbt();
  psbt.addUnknownKeyValToGlobal({ key: Buffer.from([0xfc]), value: Buffer.alloc(3_200_000) });
  const result = response(request("roundtrip", { psbt: psbt.toBase64() }));
  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "psbt.parse_failed");
  assertSchemaShape(result);
});

test("rejects malformed protocol requests and strict payloads without leaking input", () => {
  const cases = [
    { protocol: PROTOCOL, id: "bad id", operation: "hello", payload: {} },
    { protocol: "psbt-lab.adapter/0.1", id: "test-1", operation: "hello", payload: {} },
    request("hello", { unexpected: true }),
    request("roundtrip", { psbt: fixturePsbt().toBase64(), unexpected: true }),
    request("combine", { psbts: [] }),
  ];
  for (const value of cases) {
    const result = response(value);
    assert.equal(result.status, "rejected");
    assert.match(result.error.class, /^protocol\./);
    assert.doesNotMatch(result.error.message, /cHNid|private|key/i);
    assertSchemaShape(result);
  }
});

test("rejects unauthorized fixture signing before accessing signing material", () => {
  const psbt = fixturePsbt();
  const cases = [
    { ...signingPayload(psbt), network: "bitcoin" },
    { ...signingPayload(psbt), fixtureId: "unknown" },
    { ...signingPayload(psbt), keyWif: "caller-controlled" },
    {
      ...signingPayload(psbt),
      psbt: new bitcoin.Psbt()
        .addInput({ hash: Buffer.alloc(32), index: 0 })
        .addOutput({ script: TEST_SCRIPT_PUBKEY, value: 1n })
        .toBase64(),
    },
  ];
  for (const payload of cases) {
    const result = response(request("sign", payload));
    assert.equal(result.status, "rejected");
    assert.match(result.error.class, /^(policy\.|protocol\.)/);
    assert.doesNotMatch(result.error.message, /cMahea|private|key material/i);
    assertSchemaShape(result);
  }
});

test("rejects signing when fixture commitment configuration is missing or invalid", () => {
  const payload = signingPayload(fixturePsbt());
  const missing = handleValue(request("sign", payload), DIGEST);
  const invalid = handleValue(request("sign", payload), DIGEST, {
    fixtureCommitments: null,
    fixtureCommitmentsError: "invalid",
  });

  assert.equal(missing.status, "rejected");
  assert.equal(missing.error.class, "adapter.fixture_commitments_missing");
  assert.equal(invalid.status, "rejected");
  assert.equal(invalid.error.class, "adapter.fixture_commitments_invalid");
  assertSchemaShape(missing);
  assertSchemaShape(invalid);
});

test("parses only bounded fixture commitment environment objects", () => {
  assert.equal(typeof adapter.parseFixtureCommitments, "function");
  const configured = fixtureConfig();
  const raw = JSON.stringify(Object.fromEntries(configured.fixtureCommitments));
  const parsed = adapter.parseFixtureCommitments(raw);
  assert.deepEqual(parsed, configured);

  for (const invalid of [
    undefined,
    "{}",
    "[]",
    JSON.stringify({ unknown: `sha256:${"a".repeat(64)}` }),
    JSON.stringify({ "happy-path": `sha256:${"A".repeat(64)}` }),
    "x".repeat(4097),
  ]) {
    const result = adapter.parseFixtureCommitments(invalid);
    assert.equal(result.fixtureCommitments, null);
    assert.match(result.fixtureCommitmentsError, /^(missing|invalid)$/);
  }
});

test("rejects a different unsigned transaction claiming an allowed fixture id", () => {
  const configured = fixturePsbt();
  const forged = fixturePsbt();
  forged.setLocktime(1);
  const config = {
    fixtureCommitments: new Map([["happy-path", fixtureCommitment(configured)]]),
  };

  const result = response(request("sign", signingPayload(forged)), config);

  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "policy.fixture_commitment_mismatch");
  assert.doesNotMatch(result.error.message, /sha256|[0-9a-f]{64}|cHNid/i);
  assertSchemaShape(result);
});

test("does not accept caller-provided fixture commitments", () => {
  const psbt = fixturePsbt();
  const result = response(
    request("sign", {
      ...signingPayload(psbt),
      fixtureCommitment: fixtureCommitment(psbt),
    }),
  );

  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "protocol.invalid_payload");
  assertSchemaShape(result);
});

test("signs and finalizes the authorized deterministic P2WSH fixture", () => {
  const initial = fixturePsbt();
  const signed = response(request("sign", signingPayload(initial)));
  assert.equal(signed.status, "ok");
  assert.equal(signed.output.signedInputs, 1);

  const finalized = response(
    request("finalize", signingPayload(bitcoin.Psbt.fromBase64(signed.output.psbt))),
  );
  assert.equal(finalized.status, "ok");
  assert.deepEqual(finalized.output.finalizedInputs, [0]);
  const finalizedPsbt = bitcoin.Psbt.fromBase64(finalized.output.psbt);
  assert.ok(finalizedPsbt.data.inputs[0].finalScriptWitness);
  assert.equal(finalizedPsbt.extractTransaction().ins.length, 1);
  assertSchemaShape(signed);
  assertSchemaShape(finalized);
});

test("rejects a tampered expected-key signature before finalization", () => {
  const initial = fixturePsbt();
  const signed = response(request("sign", signingPayload(initial)));
  assert.equal(signed.status, "ok");
  const tampered = bitcoin.Psbt.fromBase64(signed.output.psbt);
  const partialSig = tampered.data.inputs[0].partialSig[0];
  const signature = Buffer.from(partialSig.signature);
  signature[signature.length - 2] ^= 1;
  partialSig.signature = signature;

  const result = response(request("finalize", signingPayload(tampered)));

  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "finalize.signature_invalid");
  assert.doesNotMatch(result.error.message, /[0-9a-f]{64}|cHNid/i);
  assertSchemaShape(result);
});

test("finalizes remaining inputs after one input was already finalized", () => {
  const initial = fixturePsbt(2);
  const signed = response(request("sign", signingPayload(initial, "bdk-finalize-regression")));
  assert.equal(signed.status, "ok");
  const first = response(
    request("finalize-inputs", {
      ...signingPayload(bitcoin.Psbt.fromBase64(signed.output.psbt), "bdk-finalize-regression"),
      inputIndexes: [0],
    }),
  );
  assert.equal(first.status, "ok");

  const completed = response(
    request(
      "finalize",
      signingPayload(bitcoin.Psbt.fromBase64(first.output.psbt), "bdk-finalize-regression"),
    ),
  );

  assert.equal(completed.status, "ok");
  assert.deepEqual(completed.output.finalizedInputs, [1]);
  const transaction = bitcoin.Psbt.fromBase64(completed.output.psbt).extractTransaction();
  assert.equal(transaction.ins.length, 2);
  assert.equal(
    transaction.ins.every((input) => input.witness.length === 2),
    true,
  );
  assertSchemaShape(completed);
});

test("combines compatible PSBTs and rejects inconsistent candidates", () => {
  const initial = fixturePsbt();
  const signed = response(request("sign", signingPayload(initial)));
  const combined = response(
    request("combine", { psbts: [initial.toBase64(), signed.output.psbt] }),
  );
  assert.equal(combined.status, "ok");
  assert.equal(combined.output.combinedCount, 2);
  assert.equal(bitcoin.Psbt.fromBase64(combined.output.psbt).data.inputs[0].partialSig.length, 1);

  const mismatched = response(
    request("combine", { psbts: [initial.toBase64(), fixturePsbt(2).toBase64()] }),
  );
  assert.equal(mismatched.status, "rejected");
  assert.equal(mismatched.error.class, "combine.failed");
  assertSchemaShape(combined);
  assertSchemaShape(mismatched);
});

test("finalize-inputs validates strict unique indexes and only finalizes selected inputs", () => {
  const initial = fixturePsbt(2);
  const signed = response(request("sign", signingPayload(initial, "bdk-finalize-regression")));
  assert.equal(signed.status, "ok");
  const validPayload = {
    psbt: signed.output.psbt,
    network: "regtest",
    fixtureId: "bdk-finalize-regression",
    inputIndexes: [1],
  };
  const finalized = response(request("finalize-inputs", validPayload));
  assert.equal(finalized.status, "ok");
  assert.deepEqual(finalized.output.finalizedInputs, [1]);
  assert.equal(finalized.output.remainingPartialInputs, 1);

  for (const inputIndexes of [[], [0, 0], [-1], [0.5], [2], [Number.MAX_SAFE_INTEGER + 1]]) {
    const result = response(request("finalize-inputs", { ...validPayload, inputIndexes }));
    assert.equal(result.status, "rejected");
    assert.equal(result.error.class, "protocol.invalid_payload");
    assertSchemaShape(result);
  }
});

test("reports unsupported operations with the stable class", () => {
  const result = response(request("broadcast"));
  assert.equal(result.status, "unsupported");
  assert.equal(result.error.class, "operation.unsupported");
  assertSchemaShape(result);
});

test("JSONL entrypoint rejects invalid JSON and a line above the cap", async () => {
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../adapter.mjs", import.meta.url))],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  child.stdin.end(`${"{not json"}\n${"x".repeat(MAX_LINE_BYTES + 1)}\n`);
  const output = [];
  for await (const chunk of child.stdout) output.push(chunk);
  const [invalidJson, oversized] = Buffer.concat(output)
    .toString("utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(invalidJson.error.class, "protocol.invalid_json");
  assert.equal(oversized.error.class, "protocol.line_too_large");
  assertSchemaShape(invalidJson);
  assertSchemaShape(oversized);
});

test("awaits stdout drain before writing the next JSONL response", async () => {
  assert.equal(typeof adapter.runJsonLines, "function");
  const input = [
    Buffer.from(`${JSON.stringify(request("hello"))}\n${JSON.stringify(request("hello"))}\n`),
  ];
  /** @type {EventEmitter & { write: (chunk: string) => boolean }} */
  const writer = /** @type {any} */ (new EventEmitter());
  const lines = [];
  let blocked = false;
  writer.write = (chunk) => {
    assert.equal(blocked, false, "write occurred before the preceding drain");
    blocked = true;
    lines.push(String(chunk));
    queueMicrotask(() => {
      blocked = false;
      writer.emit("drain");
    });
    return false;
  };

  await adapter.runJsonLines({ input, output: writer, digest: DIGEST, config: fixtureConfig() });

  assert.equal(lines.length, 2);
  assert.equal(
    lines.every((line) => JSON.parse(line).status === "ok"),
    true,
  );
});

test("implementation digest is a real SHA256-shaped deterministic identity", () => {
  const result = response(request("hello"));
  assert.equal(result.implementation.sourceRevision, "bitcoinjs-lib-7.0.1+tiny-secp256k1-2.2.4");
  assert.equal(result.implementation.version, "1.0.0");
  assert.equal(createHash("sha256").update("test").digest("hex").length, 64);
});
