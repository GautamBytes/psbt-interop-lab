import { describe, expect, test } from "vitest";
import { FIXTURE_DESCRIPTORS, FIXTURE_PROFILES } from "../../src/core/fixture-profiles.js";

describe("BIP376 regtest fixture", () => {
  test("funds the deterministic raw Silent Payment output key", () => {
    expect(FIXTURE_DESCRIPTORS["p2tr-silent-payment"]).toBe(
      "rawtr(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
    );
    expect(FIXTURE_PROFILES).toContainEqual(
      expect.objectContaining({
        id: "bip376-spend",
        scriptTypes: ["p2tr-keypath"],
        inputDescriptorIds: ["p2tr-silent-payment"],
      }),
    );
  });
});
