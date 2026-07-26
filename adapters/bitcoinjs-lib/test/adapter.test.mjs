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
const SECOND_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([2])]);
const THIRD_PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([3])]);
const TEST_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(TEST_PRIVATE_KEY, true));
const SECOND_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(SECOND_PRIVATE_KEY, true));
const THIRD_PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(THIRD_PRIVATE_KEY, true));
const TEST_X_ONLY_PUBLIC_KEY = TEST_PUBLIC_KEY.subarray(1);
const TEST_WITNESS_SCRIPT = bitcoin.script.compile([TEST_PUBLIC_KEY, bitcoin.opcodes.OP_CHECKSIG]);
const TEST_SCRIPT_PUBKEY = bitcoin.payments.p2wsh({
  redeem: { output: TEST_WITNESS_SCRIPT },
}).output;
const MULTISIG_WITNESS_SCRIPT = bitcoin.script.compile([
  bitcoin.opcodes.OP_2,
  TEST_PUBLIC_KEY,
  SECOND_PUBLIC_KEY,
  THIRD_PUBLIC_KEY,
  bitcoin.opcodes.OP_3,
  bitcoin.opcodes.OP_CHECKMULTISIG,
]);
const MULTISIG_REDEEM_SCRIPT = bitcoin.payments.p2wsh({
  redeem: { output: MULTISIG_WITNESS_SCRIPT },
}).output;
const PROFILE_SCRIPT_PUBKEYS = {
  p2wpkh: bitcoin.payments.p2wpkh({ pubkey: TEST_PUBLIC_KEY }).output,
  "p2wsh-2-of-3": bitcoin.payments.p2wsh({
    redeem: { output: MULTISIG_WITNESS_SCRIPT },
  }).output,
  "p2sh-p2wsh-2-of-3": bitcoin.payments.p2sh({
    redeem: { output: MULTISIG_REDEEM_SCRIPT },
  }).output,
  "p2tr-keypath": bitcoin.payments.p2tr({ internalPubkey: TEST_X_ONLY_PUBLIC_KEY }).output,
};
const PROFILE_FIXTURE_IDS = ["p2wpkh", "p2wsh-2-of-3", "p2sh-p2wsh-2-of-3", "p2tr-keypath"];
const EXACT_PROFILE_SCRIPT_HEX = {
  p2wpkh: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
  "p2wsh-2-of-3": "002012c2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c572",
  "p2sh-p2wsh-2-of-3": "a914c95ef7c9117a56571c2ddc44e5fd8ba29d45989387",
  "p2tr-keypath": "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
};
const EXACT_MULTISIG_WITNESS_SCRIPT_HEX =
  "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
  "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae";
const PROFILE_FUNDING_VALUE = 5_000_000_000n;
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

function deterministicSigner(privateKey) {
  return {
    publicKey: Buffer.from(ecc.pointFromScalar(privateKey, true)),
    sign: (hash) => Buffer.from(ecc.sign(hash, privateKey)),
  };
}

function taprootSigner() {
  const normalizedPrivateKey =
    TEST_PUBLIC_KEY[0] === 3 ? Buffer.from(ecc.privateNegate(TEST_PRIVATE_KEY)) : TEST_PRIVATE_KEY;
  const tweak = bitcoin.crypto.taggedHash("TapTweak", TEST_X_ONLY_PUBLIC_KEY);
  const tweakedPrivateKey = ecc.privateAdd(normalizedPrivateKey, tweak);
  assert.ok(tweakedPrivateKey);
  return {
    publicKey: Buffer.from(ecc.pointFromScalar(tweakedPrivateKey, true)),
    sign: (hash) => Buffer.from(ecc.sign(hash, tweakedPrivateKey)),
    signSchnorr: (hash) => Buffer.from(ecc.signSchnorr(hash, tweakedPrivateKey)),
  };
}

function profilePsbt(fixtureId, { includeNonWitnessUtxo = false } = {}) {
  const script = PROFILE_SCRIPT_PUBKEYS[fixtureId];
  assert.ok(script);
  const funding = new bitcoin.Transaction();
  funding.version = 2;
  funding.addInput(Buffer.alloc(32), 0xffffffff);
  funding.addOutput(script, PROFILE_FUNDING_VALUE);

  const input = {
    hash: funding.getId(),
    index: 0,
    witnessUtxo: { script, value: PROFILE_FUNDING_VALUE },
    ...(includeNonWitnessUtxo ? { nonWitnessUtxo: funding.toBuffer() } : {}),
    ...(fixtureId === "p2wsh-2-of-3" || fixtureId === "p2sh-p2wsh-2-of-3"
      ? { witnessScript: MULTISIG_WITNESS_SCRIPT }
      : {}),
    ...(fixtureId === "p2sh-p2wsh-2-of-3" ? { redeemScript: MULTISIG_REDEEM_SCRIPT } : {}),
    ...(fixtureId === "p2tr-keypath" ? { tapInternalKey: TEST_X_ONLY_PUBLIC_KEY } : {}),
  };
  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
  psbt.addInput(input);
  psbt.addOutput({ script, value: PROFILE_FUNDING_VALUE - 20_000n });
  return { funding, psbt };
}

function profileConfig(fixtureId, psbt) {
  return { fixtureCommitments: new Map([[fixtureId, fixtureCommitment(psbt)]]) };
}

function signProfile(psbt, fixtureId) {
  return response(request("sign", signingPayload(psbt, fixtureId)), profileConfig(fixtureId, psbt));
}

function partialSignatureHex(input) {
  return (input.partialSig ?? []).map(({ pubkey, signature }) => ({
    pubkey: Buffer.from(pubkey).toString("hex"),
    signature: Buffer.from(signature).toString("hex"),
  }));
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

test("hello advertises only proven PSBTv0 operations and script types", () => {
  const result = response(request("hello"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.output, {
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
    scriptTypes: [
      "p2wpkh",
      "p2sh-p2wpkh",
      "p2sh-p2wsh",
      "p2wsh",
      "p2tr-keypath",
      "p2tr-scriptpath",
    ],
    operationScriptTypes: {
      inspect: ["p2wpkh", "p2sh-p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
      roundtrip: [
        "p2wpkh",
        "p2sh-p2wpkh",
        "p2sh-p2wsh",
        "p2wsh",
        "p2tr-keypath",
        "p2tr-scriptpath",
      ],
      sign: ["p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath"],
      combine: ["p2wpkh", "p2sh-p2wsh", "p2wsh", "p2tr-keypath"],
      finalize: ["p2wsh"],
      "finalize-inputs": ["p2wsh"],
    },
    features: ["fixture-commitment-sha256", "combiner-conflicts-v1"],
  });
  assertSchemaShape(result);
});

test("native-parse invokes bitcoinjs-lib without fixture policy", () => {
  const accepted = response(request("native-parse", { psbt: fixturePsbt().toBase64() }));
  assert.equal(accepted.status, "ok");
  assert.deepEqual(accepted.output, {
    nativeParser: "bitcoinjs-lib",
    psbtVersion: 0,
    inputs: 1,
    outputs: 1,
  });

  const rejected = response(
    request("native-parse", { psbt: Buffer.from("not a psbt").toString("base64") }),
  );
  assert.equal(rejected.status, "rejected");
  assert.equal(rejected.error.class, "psbt.native_parse_failed");
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

test("accepts commitments for each exact signable profile and no undeclared profiles", () => {
  const commitments = new Map(fixtureConfig().fixtureCommitments);
  for (const fixtureId of PROFILE_FIXTURE_IDS) {
    const { psbt } = profilePsbt(fixtureId);
    commitments.set(fixtureId, fixtureCommitment(psbt));
  }

  assert.deepEqual(
    adapter.parseFixtureCommitments(JSON.stringify(Object.fromEntries(commitments))),
    { fixtureCommitments: commitments },
  );
  for (const fixtureId of ["p2wsh-single-key", "mixed-p2wpkh-p2tr"]) {
    const result = adapter.parseFixtureCommitments(
      JSON.stringify({ [fixtureId]: `sha256:${"a".repeat(64)}` }),
    );
    assert.equal(result.fixtureCommitments, null);
    assert.equal(result.fixtureCommitmentsError, "invalid");
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

test("scalar 1 signs the exact P2WPKH profile deterministically", () => {
  const { psbt } = profilePsbt("p2wpkh");
  const expected = psbt.clone();
  expected.signInput(0, deterministicSigner(TEST_PRIVATE_KEY));

  const result = signProfile(psbt, "p2wpkh");

  assert.equal(result.status, "ok");
  assert.equal(result.output.signedInputs, 1);
  const signed = bitcoin.Psbt.fromBase64(result.output.psbt);
  assert.equal(
    Buffer.from(signed.data.inputs[0].witnessUtxo.script).toString("hex"),
    EXACT_PROFILE_SCRIPT_HEX.p2wpkh,
  );
  assert.deepEqual(
    partialSignatureHex(signed.data.inputs[0]),
    partialSignatureHex(expected.data.inputs[0]),
  );
  assert.deepEqual(
    signed.data.inputs[0].partialSig.map(({ pubkey }) => Buffer.from(pubkey).toString("hex")),
    [TEST_PUBLIC_KEY.toString("hex")],
  );
  assert.equal(
    signed.validateSignaturesOfInput(0, (publicKey, hash, signature) =>
      ecc.verify(hash, publicKey, signature),
    ),
    true,
  );
  assertSchemaShape(result);
});

test("scalar 2 contributes its deterministic signature to the exact ordered 2-of-3 P2WSH profile", () => {
  const { psbt } = profilePsbt("p2wsh-2-of-3");
  const expected = psbt.clone();
  expected.signInput(0, deterministicSigner(SECOND_PRIVATE_KEY));

  const result = signProfile(psbt, "p2wsh-2-of-3");

  assert.equal(result.status, "ok");
  assert.equal(result.output.signedInputs, 1);
  const signed = bitcoin.Psbt.fromBase64(result.output.psbt);
  assert.equal(
    Buffer.from(signed.data.inputs[0].witnessUtxo.script).toString("hex"),
    EXACT_PROFILE_SCRIPT_HEX["p2wsh-2-of-3"],
  );
  assert.equal(
    Buffer.from(signed.data.inputs[0].witnessScript).toString("hex"),
    EXACT_MULTISIG_WITNESS_SCRIPT_HEX,
  );
  assert.deepEqual(
    bitcoin.script
      .decompile(signed.data.inputs[0].witnessScript)
      .map((item) => (item instanceof Uint8Array ? Buffer.from(item).toString("hex") : item)),
    [
      bitcoin.opcodes.OP_2,
      TEST_PUBLIC_KEY.toString("hex"),
      SECOND_PUBLIC_KEY.toString("hex"),
      THIRD_PUBLIC_KEY.toString("hex"),
      bitcoin.opcodes.OP_3,
      bitcoin.opcodes.OP_CHECKMULTISIG,
    ],
  );
  assert.deepEqual(
    partialSignatureHex(signed.data.inputs[0]),
    partialSignatureHex(expected.data.inputs[0]),
  );
  assert.deepEqual(
    signed.data.inputs[0].partialSig.map(({ pubkey }) => Buffer.from(pubkey).toString("hex")),
    [SECOND_PUBLIC_KEY.toString("hex")],
  );
  assert.equal(
    signed.validateSignaturesOfInput(0, (publicKey, hash, signature) =>
      ecc.verify(hash, publicKey, signature),
    ),
    true,
  );
  assertSchemaShape(result);
});

test("scalar 2 signs the exact nested P2SH-P2WSH 2-of-3 profile", () => {
  const { psbt } = profilePsbt("p2sh-p2wsh-2-of-3");
  const expected = psbt.clone();
  expected.signInput(0, deterministicSigner(SECOND_PRIVATE_KEY));

  const result = signProfile(psbt, "p2sh-p2wsh-2-of-3");

  assert.equal(result.status, "ok");
  const signed = bitcoin.Psbt.fromBase64(result.output.psbt);
  assert.equal(
    Buffer.from(signed.data.inputs[0].witnessUtxo.script).toString("hex"),
    EXACT_PROFILE_SCRIPT_HEX["p2sh-p2wsh-2-of-3"],
  );
  assert.equal(
    Buffer.from(signed.data.inputs[0].redeemScript).toString("hex"),
    Buffer.from(MULTISIG_REDEEM_SCRIPT).toString("hex"),
  );
  assert.deepEqual(
    partialSignatureHex(signed.data.inputs[0]),
    partialSignatureHex(expected.data.inputs[0]),
  );
  assert.equal(
    signed.validateSignaturesOfInput(0, (publicKey, hash, signature) =>
      ecc.verify(hash, publicKey, signature),
    ),
    true,
  );
  assertSchemaShape(result);
});

test("TapTweak-adjusted scalar 1 signs the exact key-path Taproot profile with Schnorr", () => {
  const { psbt } = profilePsbt("p2tr-keypath");
  const expected = psbt.clone();
  expected.signInput(0, taprootSigner(), [bitcoin.Transaction.SIGHASH_DEFAULT]);

  const result = signProfile(psbt, "p2tr-keypath");

  assert.equal(result.status, "ok");
  assert.equal(result.output.signedInputs, 1);
  const signed = bitcoin.Psbt.fromBase64(result.output.psbt);
  assert.equal(
    Buffer.from(signed.data.inputs[0].witnessUtxo.script).toString("hex"),
    EXACT_PROFILE_SCRIPT_HEX["p2tr-keypath"],
  );
  assert.equal(
    Buffer.from(signed.data.inputs[0].tapInternalKey).toString("hex"),
    TEST_X_ONLY_PUBLIC_KEY.toString("hex"),
  );
  assert.equal(
    Buffer.from(signed.data.inputs[0].tapKeySig).toString("hex"),
    Buffer.from(expected.data.inputs[0].tapKeySig).toString("hex"),
  );
  assert.equal(signed.data.inputs[0].tapKeySig.length, 64);
  assert.equal(signed.data.inputs[0].tapScriptSig, undefined);
  assert.equal(
    signed.validateSignaturesOfInput(0, (publicKey, hash, signature) =>
      ecc.verifySchnorr(hash, publicKey, signature),
    ),
    true,
  );
  assertSchemaShape(result);
});

test("rejects every profile when its exact funding script is replaced", () => {
  for (const [index, fixtureId] of PROFILE_FIXTURE_IDS.entries()) {
    const { psbt } = profilePsbt(fixtureId);
    const replacementId = PROFILE_FIXTURE_IDS[(index + 1) % PROFILE_FIXTURE_IDS.length];
    psbt.data.inputs[0].witnessUtxo.script = PROFILE_SCRIPT_PUBKEYS[replacementId];

    const result = signProfile(psbt, fixtureId);

    assert.equal(result.status, "rejected");
    assert.equal(result.error.class, "policy.psbt_not_authorized");
    assertSchemaShape(result);
  }
});

test("rejects inconsistent witness and non-witness UTXO metadata", () => {
  const mismatchedValue = profilePsbt("p2wpkh", { includeNonWitnessUtxo: true }).psbt;
  mismatchedValue.data.inputs[0].witnessUtxo.value += 1n;

  const wrongTransaction = profilePsbt("p2wpkh", { includeNonWitnessUtxo: true }).psbt;
  const unrelatedFunding = new bitcoin.Transaction();
  unrelatedFunding.addInput(Buffer.alloc(32, 1), 0xffffffff);
  unrelatedFunding.addOutput(PROFILE_SCRIPT_PUBKEYS.p2wpkh, PROFILE_FUNDING_VALUE);
  wrongTransaction.data.inputs[0].nonWitnessUtxo = unrelatedFunding.toBuffer();

  for (const psbt of [mismatchedValue, wrongTransaction]) {
    const result = signProfile(psbt, "p2wpkh");
    assert.equal(result.status, "rejected");
    assert.equal(result.error.class, "policy.psbt_not_authorized");
    assertSchemaShape(result);
  }
});

test("rejects Taproot internal-key, script-path, and non-default sighash metadata", () => {
  const wrongInternalKey = profilePsbt("p2tr-keypath").psbt;
  wrongInternalKey.data.inputs[0].tapInternalKey = SECOND_PUBLIC_KEY.subarray(1);

  const merkleRoot = profilePsbt("p2tr-keypath").psbt;
  merkleRoot.data.inputs[0].tapMerkleRoot = Buffer.alloc(32, 1);

  const leafScript = profilePsbt("p2tr-keypath").psbt;
  leafScript.data.inputs[0].tapLeafScript = [
    {
      controlBlock: Buffer.concat([Buffer.from([0xc0]), TEST_X_ONLY_PUBLIC_KEY]),
      leafVersion: 0xc0,
      script: Buffer.from([bitcoin.opcodes.OP_TRUE]),
    },
  ];

  const scriptSignature = profilePsbt("p2tr-keypath").psbt;
  scriptSignature.data.inputs[0].tapScriptSig = [
    {
      pubkey: TEST_X_ONLY_PUBLIC_KEY,
      leafHash: Buffer.alloc(32, 2),
      signature: Buffer.alloc(64, 3),
    },
  ];

  const nonDefaultSighash = profilePsbt("p2tr-keypath").psbt;
  nonDefaultSighash.updateInput(0, { sighashType: bitcoin.Transaction.SIGHASH_ALL });

  for (const psbt of [
    wrongInternalKey,
    merkleRoot,
    leafScript,
    scriptSignature,
    nonDefaultSighash,
  ]) {
    const result = signProfile(psbt, "p2tr-keypath");
    assert.equal(result.status, "rejected");
    assert.equal(result.error.class, "policy.psbt_not_authorized");
    assertSchemaShape(result);
  }
});

test("rejects caller-controlled key material for every signable profile", () => {
  for (const fixtureId of PROFILE_FIXTURE_IDS) {
    const { psbt } = profilePsbt(fixtureId);
    for (const callerKey of [
      { keyWif: "caller-controlled" },
      { privateKey: TEST_PRIVATE_KEY.toString("hex") },
      { signer: "caller-controlled" },
    ]) {
      const result = response(
        request("sign", { ...signingPayload(psbt, fixtureId), ...callerKey }),
        profileConfig(fixtureId, psbt),
      );
      assert.equal(result.status, "rejected");
      assert.equal(result.error.class, "protocol.invalid_payload");
      assert.doesNotMatch(result.error.message, /[0-9a-f]{64}|private|key material/i);
      assertSchemaShape(result);
    }
  }
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

  const left = profilePsbt("p2wpkh").psbt;
  const conflictingUtxo = left.clone();
  conflictingUtxo.data.inputs[0].witnessUtxo.value += 1n;
  const utxoConflict = response(
    request("combine", { psbts: [left.toBase64(), conflictingUtxo.toBase64()] }),
  );
  assert.equal(utxoConflict.status, "rejected");
  assert.equal(utxoConflict.error.class, "combine.conflict");

  const all = left.clone();
  all.updateInput(0, { sighashType: bitcoin.Transaction.SIGHASH_ALL });
  const none = left.clone();
  none.updateInput(0, { sighashType: bitcoin.Transaction.SIGHASH_NONE });
  const sighashConflict = response(
    request("combine", { psbts: [all.toBase64(), none.toBase64()] }),
  );
  assert.equal(sighashConflict.status, "rejected");
  assert.equal(sighashConflict.error.class, "combine.conflict");

  assertSchemaShape(combined);
  assertSchemaShape(mismatched);
  assertSchemaShape(utxoConflict);
  assertSchemaShape(sighashConflict);
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
