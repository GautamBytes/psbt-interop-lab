export type PsbtFieldScope = "global" | "input" | "output";
export type PsbtFieldBip =
  | "BIP127"
  | "BIP174"
  | "BIP322"
  | "BIP353"
  | "BIP370"
  | "BIP371"
  | "BIP373"
  | "BIP375"
  | "BIP376";
export type PsbtFieldKind = "standard" | "proprietary" | "unknown";

export interface PsbtFieldMetadata {
  readonly scope: PsbtFieldScope;
  readonly keyType: number;
  readonly keyTypeHex: string;
  readonly symbol: string;
  readonly displayName: string;
  readonly bip?: PsbtFieldBip;
  readonly kind: PsbtFieldKind;
}

function registeredField(
  scope: PsbtFieldScope,
  keyType: number,
  symbol: string,
  displayName: string,
  bip: PsbtFieldBip,
): PsbtFieldMetadata {
  return Object.freeze({
    scope,
    keyType,
    keyTypeHex: renderKeyType(keyType),
    symbol,
    displayName,
    bip,
    kind: keyType === 0xfc ? "proprietary" : "standard",
  });
}

function renderKeyType(keyType: number): string {
  return `0x${keyType.toString(16).padStart(2, "0")}`;
}

export const PSBT_FIELD_REGISTRY: readonly PsbtFieldMetadata[] = Object.freeze([
  registeredField("global", 0x00, "PSBT_GLOBAL_UNSIGNED_TX", "Unsigned transaction", "BIP174"),
  registeredField("global", 0x01, "PSBT_GLOBAL_XPUB", "Global extended public key", "BIP174"),
  registeredField("global", 0x02, "PSBT_GLOBAL_TX_VERSION", "Transaction version", "BIP370"),
  registeredField("global", 0x03, "PSBT_GLOBAL_FALLBACK_LOCKTIME", "Fallback locktime", "BIP370"),
  registeredField("global", 0x04, "PSBT_GLOBAL_INPUT_COUNT", "Input count", "BIP370"),
  registeredField("global", 0x05, "PSBT_GLOBAL_OUTPUT_COUNT", "Output count", "BIP370"),
  registeredField(
    "global",
    0x06,
    "PSBT_GLOBAL_TX_MODIFIABLE",
    "Transaction modifiable flags",
    "BIP370",
  ),
  registeredField(
    "global",
    0x07,
    "PSBT_GLOBAL_SP_ECDH_SHARE",
    "Silent Payment global ECDH share",
    "BIP375",
  ),
  registeredField(
    "global",
    0x08,
    "PSBT_GLOBAL_SP_DLEQ",
    "Silent Payment global DLEQ proof",
    "BIP375",
  ),
  registeredField(
    "global",
    0x09,
    "PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE",
    "Generic signed message",
    "BIP322",
  ),
  registeredField("global", 0xfb, "PSBT_GLOBAL_VERSION", "PSBT version", "BIP174"),
  registeredField("global", 0xfc, "PSBT_GLOBAL_PROPRIETARY", "Proprietary global field", "BIP174"),

  registeredField("input", 0x00, "PSBT_IN_NON_WITNESS_UTXO", "Non-witness UTXO", "BIP174"),
  registeredField("input", 0x01, "PSBT_IN_WITNESS_UTXO", "Witness UTXO", "BIP174"),
  registeredField("input", 0x02, "PSBT_IN_PARTIAL_SIG", "Partial signature", "BIP174"),
  registeredField("input", 0x03, "PSBT_IN_SIGHASH_TYPE", "Sighash type", "BIP174"),
  registeredField("input", 0x04, "PSBT_IN_REDEEM_SCRIPT", "Redeem script", "BIP174"),
  registeredField("input", 0x05, "PSBT_IN_WITNESS_SCRIPT", "Witness script", "BIP174"),
  registeredField("input", 0x06, "PSBT_IN_BIP32_DERIVATION", "BIP32 derivation", "BIP174"),
  registeredField("input", 0x07, "PSBT_IN_FINAL_SCRIPTSIG", "Final scriptSig", "BIP174"),
  registeredField("input", 0x08, "PSBT_IN_FINAL_SCRIPTWITNESS", "Final script witness", "BIP174"),
  registeredField(
    "input",
    0x09,
    "PSBT_IN_POR_COMMITMENT",
    "Proof-of-reserves commitment",
    "BIP127",
  ),
  registeredField("input", 0x0a, "PSBT_IN_RIPEMD160", "RIPEMD160 preimage", "BIP174"),
  registeredField("input", 0x0b, "PSBT_IN_SHA256", "SHA256 preimage", "BIP174"),
  registeredField("input", 0x0c, "PSBT_IN_HASH160", "HASH160 preimage", "BIP174"),
  registeredField("input", 0x0d, "PSBT_IN_HASH256", "HASH256 preimage", "BIP174"),
  registeredField("input", 0x0e, "PSBT_IN_PREVIOUS_TXID", "Previous transaction ID", "BIP370"),
  registeredField("input", 0x0f, "PSBT_IN_OUTPUT_INDEX", "Output index", "BIP370"),
  registeredField("input", 0x10, "PSBT_IN_SEQUENCE", "Sequence", "BIP370"),
  registeredField(
    "input",
    0x11,
    "PSBT_IN_REQUIRED_TIME_LOCKTIME",
    "Required time locktime",
    "BIP370",
  ),
  registeredField(
    "input",
    0x12,
    "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
    "Required height locktime",
    "BIP370",
  ),
  registeredField("input", 0x13, "PSBT_IN_TAP_KEY_SIG", "Taproot key-path signature", "BIP371"),
  registeredField(
    "input",
    0x14,
    "PSBT_IN_TAP_SCRIPT_SIG",
    "Taproot script-path signature",
    "BIP371",
  ),
  registeredField("input", 0x15, "PSBT_IN_TAP_LEAF_SCRIPT", "Taproot leaf script", "BIP371"),
  registeredField(
    "input",
    0x16,
    "PSBT_IN_TAP_BIP32_DERIVATION",
    "Taproot BIP32 derivation",
    "BIP371",
  ),
  registeredField("input", 0x17, "PSBT_IN_TAP_INTERNAL_KEY", "Taproot internal key", "BIP371"),
  registeredField("input", 0x18, "PSBT_IN_TAP_MERKLE_ROOT", "Taproot Merkle root", "BIP371"),
  registeredField(
    "input",
    0x1a,
    "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS",
    "MuSig2 participant public keys",
    "BIP373",
  ),
  registeredField("input", 0x1b, "PSBT_IN_MUSIG2_PUB_NONCE", "MuSig2 public nonce", "BIP373"),
  registeredField(
    "input",
    0x1c,
    "PSBT_IN_MUSIG2_PARTIAL_SIG",
    "MuSig2 participant partial signature",
    "BIP373",
  ),
  registeredField(
    "input",
    0x1d,
    "PSBT_IN_SP_ECDH_SHARE",
    "Silent Payment input ECDH share",
    "BIP375",
  ),
  registeredField("input", 0x1e, "PSBT_IN_SP_DLEQ", "Silent Payment input DLEQ proof", "BIP375"),
  registeredField(
    "input",
    0x1f,
    "PSBT_IN_SP_SPEND_BIP32_DERIVATION",
    "Silent Payment spend key BIP32 derivation",
    "BIP376",
  ),
  registeredField("input", 0x20, "PSBT_IN_SP_TWEAK", "Silent Payment tweak", "BIP376"),
  registeredField("input", 0xfc, "PSBT_IN_PROPRIETARY", "Proprietary input field", "BIP174"),

  registeredField("output", 0x00, "PSBT_OUT_REDEEM_SCRIPT", "Redeem script", "BIP174"),
  registeredField("output", 0x01, "PSBT_OUT_WITNESS_SCRIPT", "Witness script", "BIP174"),
  registeredField("output", 0x02, "PSBT_OUT_BIP32_DERIVATION", "BIP32 derivation", "BIP174"),
  registeredField("output", 0x03, "PSBT_OUT_AMOUNT", "Output amount", "BIP370"),
  registeredField("output", 0x04, "PSBT_OUT_SCRIPT", "Output script", "BIP370"),
  registeredField("output", 0x05, "PSBT_OUT_TAP_INTERNAL_KEY", "Taproot internal key", "BIP371"),
  registeredField("output", 0x06, "PSBT_OUT_TAP_TREE", "Taproot tree", "BIP371"),
  registeredField(
    "output",
    0x07,
    "PSBT_OUT_TAP_BIP32_DERIVATION",
    "Taproot BIP32 derivation",
    "BIP371",
  ),
  registeredField(
    "output",
    0x08,
    "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS",
    "MuSig2 participant public keys",
    "BIP373",
  ),
  registeredField("output", 0x09, "PSBT_OUT_SP_V0_INFO", "Silent Payment v0 data", "BIP375"),
  registeredField("output", 0x0a, "PSBT_OUT_SP_V0_LABEL", "Silent Payment v0 label", "BIP375"),
  registeredField("output", 0x35, "PSBT_OUT_DNSSEC_PROOF", "BIP353 DNSSEC proof", "BIP353"),
  registeredField("output", 0xfc, "PSBT_OUT_PROPRIETARY", "Proprietary output field", "BIP174"),
]);

const FIELD_BY_SCOPE_AND_TYPE = new Map(
  PSBT_FIELD_REGISTRY.map((field) => [`${field.scope}:${field.keyType}`, field]),
);

export function describePsbtField(scope: PsbtFieldScope, keyType: number): PsbtFieldMetadata {
  if (!Number.isSafeInteger(keyType) || keyType < 0) {
    throw new TypeError("PSBT key type must be a non-negative safe integer");
  }
  const registered = FIELD_BY_SCOPE_AND_TYPE.get(`${scope}:${keyType}`);
  if (registered) return registered;
  const prefix = scope === "global" ? "GLOBAL" : scope === "input" ? "IN" : "OUT";
  return Object.freeze({
    scope,
    keyType,
    keyTypeHex: renderKeyType(keyType),
    symbol: `PSBT_${prefix}_UNKNOWN`,
    displayName: `Unknown ${scope} field`,
    kind: "unknown",
  });
}
