import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";

import {
  DERIVATION_PATH,
  DEVICE_FINGERPRINT,
  DEVICE_PATH,
  handleValue,
  PROTOCOL,
} from "../adapter.mjs";
import { signTransaction } from "../device-simulator.mjs";

bitcoin.initEccLib(ecc);

const PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(PRIVATE_KEY, true));
const DIGEST = `sha256:${"a".repeat(64)}`;
const DEVICE_ENTRYPOINT = fileURLToPath(new URL("../device-simulator.mjs", import.meta.url));

function request(operation, payload = {}) {
  return { protocol: PROTOCOL, id: "test-1", operation, payload };
}

function fixturePsbt(fingerprint = DEVICE_FINGERPRINT, path = DERIVATION_PATH) {
  const script = bitcoin.payments.p2wpkh({ pubkey: PUBLIC_KEY }).output;
  assert.ok(script);
  const funding = new bitcoin.Transaction();
  funding.version = 2;
  funding.addInput(Buffer.alloc(32), 0xffffffff);
  funding.addOutput(script, 5_000_000_000n);

  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
  psbt.addInput({
    hash: funding.getId(),
    index: 0,
    witnessUtxo: { script, value: 5_000_000_000n },
    bip32Derivation: [
      {
        masterFingerprint: Buffer.from(fingerprint, "hex"),
        path,
        pubkey: PUBLIC_KEY,
      },
    ],
  });
  psbt.addOutput({ script, value: 4_999_980_000n });
  return psbt;
}

function fixtureConfig(psbt) {
  const unsignedTx = psbt.data.globalMap.unsignedTx.toBuffer();
  return {
    fixtureCommitments: new Map([
      ["p2wpkh", `sha256:${createHash("sha256").update(unsignedTx).digest("hex")}`],
    ]),
  };
}

test("device process enumerates one deterministic simulator using HWI JSON", () => {
  const child = spawnSync(process.execPath, [DEVICE_ENTRYPOINT, "enumerate"], {
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), [
    {
      type: "simulator",
      path: DEVICE_PATH,
      fingerprint: DEVICE_FINGERPRINT,
      model: "psbt-interop-lab",
      needs_pin_sent: false,
      needs_passphrase_sent: false,
    },
  ]);
});

test("adapter advertises the simulator boundary without claiming physical hardware", () => {
  const result = handleValue(request("hello"), DIGEST, { fixtureCommitments: null });
  assert.equal(result.status, "ok");
  assert.deepEqual(result.output, {
    operations: ["hello", "native-parse", "roundtrip", "sign"],
    roles: ["parser", "signer"],
    psbtVersions: [0],
    scriptTypes: ["p2wpkh"],
    operationScriptTypes: {
      roundtrip: ["p2wpkh"],
      sign: ["p2wpkh"],
    },
    features: [
      "fixture-commitment-sha256",
      "hwi-json-process-v1",
      "hwi-simulator-v1",
      "simulated-user-confirmation-v1",
      "network-free",
    ],
  });
});

test("device process requires an explicit approval decision", () => {
  const result = signTransaction(fixturePsbt().toBase64());

  assert.deepEqual(result, { error: "Invalid simulated user action", code: -7 });
});

test("adapter signs through the device process and preserves the unsigned transaction", () => {
  const source = fixturePsbt();
  const sourceUnsigned = Buffer.from(source.data.globalMap.unsignedTx.toBuffer());
  const result = handleValue(
    request("sign", {
      psbt: source.toBase64(),
      network: "regtest",
      fixtureId: "p2wpkh",
      userAction: "approve",
    }),
    DIGEST,
    fixtureConfig(source),
  );
  assert.equal(result.status, "ok");
  assert.equal(result.output.deviceFingerprint, DEVICE_FINGERPRINT);
  assert.equal(result.output.signedInputs, 1);

  const signed = bitcoin.Psbt.fromBase64(result.output.psbt, {
    network: bitcoin.networks.regtest,
  });
  assert.deepEqual(Buffer.from(signed.data.globalMap.unsignedTx.toBuffer()), sourceUnsigned);
  assert.equal(signed.data.inputs[0].partialSig?.length, 1);
  assert.deepEqual(Buffer.from(signed.data.inputs[0].partialSig[0].pubkey), PUBLIC_KEY);
  assert.equal(
    signed.validateSignaturesOfAllInputs((pubkey, hash, signature) =>
      ecc.verify(hash, pubkey, signature),
    ),
    true,
  );
});

test("device policy rejects an unexpected key origin", () => {
  const source = fixturePsbt("deadbeef");
  const result = handleValue(
    request("sign", {
      psbt: source.toBase64(),
      network: "regtest",
      fixtureId: "p2wpkh",
      userAction: "approve",
    }),
    DIGEST,
    fixtureConfig(source),
  );
  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "hwi.key_origin_mismatch");
});

test("simulated user rejection is surfaced as an HWI cancellation", () => {
  const source = fixturePsbt();
  const result = handleValue(
    request("sign", {
      psbt: source.toBase64(),
      network: "regtest",
      fixtureId: "p2wpkh",
      userAction: "reject",
    }),
    DIGEST,
    fixtureConfig(source),
  );
  assert.equal(result.status, "rejected");
  assert.equal(result.error.class, "hwi.action_canceled");
});
