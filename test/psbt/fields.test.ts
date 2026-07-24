import { describe, expect, test } from "vitest";
import { describePsbtField, PSBT_FIELD_REGISTRY } from "../../src/psbt/fields.js";

const EXPECTED_FIELDS = {
  global: [
    [0x00, "PSBT_GLOBAL_UNSIGNED_TX", "BIP174"],
    [0x01, "PSBT_GLOBAL_XPUB", "BIP174"],
    [0x02, "PSBT_GLOBAL_TX_VERSION", "BIP370"],
    [0x03, "PSBT_GLOBAL_FALLBACK_LOCKTIME", "BIP370"],
    [0x04, "PSBT_GLOBAL_INPUT_COUNT", "BIP370"],
    [0x05, "PSBT_GLOBAL_OUTPUT_COUNT", "BIP370"],
    [0x06, "PSBT_GLOBAL_TX_MODIFIABLE", "BIP370"],
    [0x07, "PSBT_GLOBAL_SP_ECDH_SHARE", "BIP375"],
    [0x08, "PSBT_GLOBAL_SP_DLEQ", "BIP375"],
    [0x09, "PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE", "BIP322"],
    [0xfb, "PSBT_GLOBAL_VERSION", "BIP174"],
    [0xfc, "PSBT_GLOBAL_PROPRIETARY", "BIP174"],
  ],
  input: [
    [0x00, "PSBT_IN_NON_WITNESS_UTXO", "BIP174"],
    [0x01, "PSBT_IN_WITNESS_UTXO", "BIP174"],
    [0x02, "PSBT_IN_PARTIAL_SIG", "BIP174"],
    [0x03, "PSBT_IN_SIGHASH_TYPE", "BIP174"],
    [0x04, "PSBT_IN_REDEEM_SCRIPT", "BIP174"],
    [0x05, "PSBT_IN_WITNESS_SCRIPT", "BIP174"],
    [0x06, "PSBT_IN_BIP32_DERIVATION", "BIP174"],
    [0x07, "PSBT_IN_FINAL_SCRIPTSIG", "BIP174"],
    [0x08, "PSBT_IN_FINAL_SCRIPTWITNESS", "BIP174"],
    [0x09, "PSBT_IN_POR_COMMITMENT", "BIP127"],
    [0x0a, "PSBT_IN_RIPEMD160", "BIP174"],
    [0x0b, "PSBT_IN_SHA256", "BIP174"],
    [0x0c, "PSBT_IN_HASH160", "BIP174"],
    [0x0d, "PSBT_IN_HASH256", "BIP174"],
    [0x0e, "PSBT_IN_PREVIOUS_TXID", "BIP370"],
    [0x0f, "PSBT_IN_OUTPUT_INDEX", "BIP370"],
    [0x10, "PSBT_IN_SEQUENCE", "BIP370"],
    [0x11, "PSBT_IN_REQUIRED_TIME_LOCKTIME", "BIP370"],
    [0x12, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME", "BIP370"],
    [0x13, "PSBT_IN_TAP_KEY_SIG", "BIP371"],
    [0x14, "PSBT_IN_TAP_SCRIPT_SIG", "BIP371"],
    [0x15, "PSBT_IN_TAP_LEAF_SCRIPT", "BIP371"],
    [0x16, "PSBT_IN_TAP_BIP32_DERIVATION", "BIP371"],
    [0x17, "PSBT_IN_TAP_INTERNAL_KEY", "BIP371"],
    [0x18, "PSBT_IN_TAP_MERKLE_ROOT", "BIP371"],
    [0x1a, "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS", "BIP373"],
    [0x1b, "PSBT_IN_MUSIG2_PUB_NONCE", "BIP373"],
    [0x1c, "PSBT_IN_MUSIG2_PARTIAL_SIG", "BIP373"],
    [0x1d, "PSBT_IN_SP_ECDH_SHARE", "BIP375"],
    [0x1e, "PSBT_IN_SP_DLEQ", "BIP375"],
    [0x1f, "PSBT_IN_SP_SPEND_BIP32_DERIVATION", "BIP376"],
    [0x20, "PSBT_IN_SP_TWEAK", "BIP376"],
    [0xfc, "PSBT_IN_PROPRIETARY", "BIP174"],
  ],
  output: [
    [0x00, "PSBT_OUT_REDEEM_SCRIPT", "BIP174"],
    [0x01, "PSBT_OUT_WITNESS_SCRIPT", "BIP174"],
    [0x02, "PSBT_OUT_BIP32_DERIVATION", "BIP174"],
    [0x03, "PSBT_OUT_AMOUNT", "BIP370"],
    [0x04, "PSBT_OUT_SCRIPT", "BIP370"],
    [0x05, "PSBT_OUT_TAP_INTERNAL_KEY", "BIP371"],
    [0x06, "PSBT_OUT_TAP_TREE", "BIP371"],
    [0x07, "PSBT_OUT_TAP_BIP32_DERIVATION", "BIP371"],
    [0x08, "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS", "BIP373"],
    [0x09, "PSBT_OUT_SP_V0_INFO", "BIP375"],
    [0x0a, "PSBT_OUT_SP_V0_LABEL", "BIP375"],
    [0x35, "PSBT_OUT_DNSSEC_PROOF", "BIP353"],
    [0xfc, "PSBT_OUT_PROPRIETARY", "BIP174"],
  ],
} as const;

describe("PSBT field registry", () => {
  test("covers the official PSBT key type registry entries used by diagnostics", () => {
    expect(
      PSBT_FIELD_REGISTRY.map(({ scope, keyType, symbol, bip }) => [scope, keyType, symbol, bip]),
    ).toEqual(
      Object.entries(EXPECTED_FIELDS).flatMap(([scope, fields]) =>
        fields.map(([keyType, symbol, bip]) => [scope, keyType, symbol, bip]),
      ),
    );
    expect(
      new Set(PSBT_FIELD_REGISTRY.map((field) => `${field.scope}:${field.keyType}`)).size,
    ).toBe(PSBT_FIELD_REGISTRY.length);
  });

  test("describes a standard field in human-readable form", () => {
    expect(describePsbtField("input", 0x02)).toEqual({
      scope: "input",
      keyType: 0x02,
      keyTypeHex: "0x02",
      symbol: "PSBT_IN_PARTIAL_SIG",
      displayName: "Partial signature",
      bip: "BIP174",
      kind: "standard",
    });
  });

  test("returns deterministic proprietary and unknown fallbacks", () => {
    expect(describePsbtField("output", 0xfc)).toMatchObject({
      symbol: "PSBT_OUT_PROPRIETARY",
      displayName: "Proprietary output field",
      bip: "BIP174",
      kind: "proprietary",
    });
    expect(describePsbtField("input", 0x50)).toEqual({
      scope: "input",
      keyType: 0x50,
      keyTypeHex: "0x50",
      symbol: "PSBT_IN_UNKNOWN",
      displayName: "Unknown input field",
      kind: "unknown",
    });
  });
});
