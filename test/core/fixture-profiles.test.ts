import { describe, expect, test } from "vitest";
import { FIXTURE_PROFILES, FIXTURE_PUBLIC_KEYS } from "../../src/core/fixture-profiles.js";

describe("fixture profile definitions", () => {
  test("uses only fixed public keys and declares each required profile", () => {
    expect(FIXTURE_PUBLIC_KEYS).toEqual({
      scalar1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      scalar2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      scalar3: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    });
    expect(JSON.stringify(FIXTURE_PUBLIC_KEYS)).not.toMatch(/priv|secret|["']0{63}[1-3]["']/i);
    expect(FIXTURE_PROFILES.map((profile) => profile.id)).toEqual([
      "p2wpkh",
      "p2wsh-single-key",
      "p2wsh-2-of-3",
      "p2tr-keypath",
      "mixed-p2wpkh-p2tr",
    ]);
  });

  test("declares exact descriptor requirements without secret material", () => {
    expect(FIXTURE_PROFILES).toMatchObject([
      {
        id: "p2wpkh",
        scriptTypes: ["p2wpkh"],
        inputDescriptorIds: ["p2wpkh"],
      },
      {
        id: "p2wsh-single-key",
        scriptTypes: ["p2wsh"],
        inputDescriptorIds: ["p2wsh-single-key"],
      },
      {
        id: "p2wsh-2-of-3",
        scriptTypes: ["p2wsh"],
        inputDescriptorIds: ["p2wsh-2-of-3"],
      },
      {
        id: "p2tr-keypath",
        scriptTypes: ["p2tr-keypath"],
        inputDescriptorIds: ["p2tr-keypath"],
      },
      {
        id: "mixed-p2wpkh-p2tr",
        scriptTypes: ["p2wpkh", "p2tr-keypath"],
        inputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
      },
    ]);

    const descriptors = FIXTURE_PROFILES.flatMap((profile) => profile.descriptors);
    expect(descriptors).toContain(`wpkh(${FIXTURE_PUBLIC_KEYS.scalar1})`);
    expect(descriptors).toContain(`wsh(pk(${FIXTURE_PUBLIC_KEYS.scalar1}))`);
    expect(descriptors).toContain(
      `wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3}))`,
    );
    expect(descriptors).toContain(`tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)})`);
    expect(descriptors.join("\n")).not.toMatch(/xprv|tprv|priv|secret/i);
  });
});
