#!/usr/bin/env node

// @ts-check

import { fileURLToPath } from "node:url";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";

bitcoin.initEccLib(ecc);

export const DEVICE_TYPE = "simulator";
export const DEVICE_PATH = "simulator:0";
export const DEVICE_FINGERPRINT = "73c5da0a";
export const DERIVATION_PATH = "m/84'/1'/0'/0/0";

const PRIVATE_KEY = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const PUBLIC_KEY = Buffer.from(ecc.pointFromScalar(PRIVATE_KEY, true));
const SCRIPT_PUBKEY = bitcoin.payments.p2wpkh({ pubkey: PUBLIC_KEY }).output;

function error(message, code) {
  return { error: message, code };
}

export function enumerateDevices() {
  return [
    {
      type: DEVICE_TYPE,
      path: DEVICE_PATH,
      fingerprint: DEVICE_FINGERPRINT,
      model: "psbt-interop-lab",
      needs_pin_sent: false,
      needs_passphrase_sent: false,
    },
  ];
}

function deterministicSigner() {
  return {
    publicKey: PUBLIC_KEY,
    sign: (hash) => Buffer.from(ecc.sign(hash, PRIVATE_KEY)),
  };
}

function hasAuthorizedOrigin(psbt) {
  if (psbt.inputCount !== 1) return false;
  const input = psbt.data.inputs[0];
  const origins = input?.bip32Derivation ?? [];
  return (
    origins.length === 1 &&
    Buffer.from(origins[0].pubkey).equals(PUBLIC_KEY) &&
    Buffer.from(origins[0].masterFingerprint).toString("hex") === DEVICE_FINGERPRINT &&
    origins[0].path === DERIVATION_PATH
  );
}

function hasAuthorizedScript(psbt) {
  if (psbt.inputCount !== 1 || !SCRIPT_PUBKEY) return false;
  const witnessUtxo = psbt.data.inputs[0]?.witnessUtxo;
  return Boolean(witnessUtxo && Buffer.from(witnessUtxo.script).equals(SCRIPT_PUBKEY));
}

export function signTransaction(encoded, userAction) {
  if (userAction === "reject") return error("Action canceled by user", -13);
  if (userAction !== "approve") return error("Invalid simulated user action", -7);

  let psbt;
  try {
    psbt = bitcoin.Psbt.fromBase64(encoded, { network: bitcoin.networks.regtest });
  } catch {
    return error("Invalid PSBT", -7);
  }
  if (!hasAuthorizedOrigin(psbt)) return error("Unexpected key origin", -7);
  if (!hasAuthorizedScript(psbt)) return error("PSBT is outside the simulator policy", -7);

  try {
    psbt.signInput(0, deterministicSigner(), [bitcoin.Transaction.SIGHASH_ALL]);
    return { psbt: psbt.toBase64() };
  } catch {
    return error("PSBT signing failed", -7);
  }
}

function parseSignArguments(args) {
  const expectedPrefix = ["-t", DEVICE_TYPE, "-d", DEVICE_PATH, "--chain", "regtest", "signtx"];
  if (
    args.length !== expectedPrefix.length + 1 ||
    expectedPrefix.some((value, index) => args[index] !== value)
  ) {
    return null;
  }
  return args[expectedPrefix.length];
}

export function handleCommand(args, environment = process.env) {
  if (args.length === 1 && args[0] === "enumerate") return enumerateDevices();
  const encoded = parseSignArguments(args);
  if (!encoded) return error("Invalid command", -7);
  return signTransaction(encoded, environment["PSBT_LAB_HWI_USER_ACTION"]);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = handleCommand(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = "error" in result ? 1 : 0;
}
