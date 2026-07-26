import { describe, expect, test } from "vitest";
import {
  FIXTURE_DESCRIPTORS,
  FIXTURE_PROFILES,
  FIXTURE_PUBLIC_KEYS,
  MUSIG2_AGGREGATE_PUBLIC_KEY,
} from "../../src/core/fixture-profiles.js";

describe("fixture profile definitions", () => {
  test("uses only fixed public keys and declares each required profile", () => {
    expect(FIXTURE_PUBLIC_KEYS).toEqual({
      scalar1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      scalar2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      scalar3: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    });
    expect(JSON.stringify(FIXTURE_PUBLIC_KEYS)).not.toMatch(/priv|secret|["']0{63}[1-3]["']/i);
    expect(FIXTURE_PROFILES.map((profile) => profile.id)).toEqual([
      "p2pkh",
      "p2wpkh",
      "p2sh-p2wpkh",
      "p2sh-p2wsh-2-of-3",
      "p2wsh-single-key",
      "p2wsh-2-of-3",
      "p2tr-keypath",
      "p2tr-musig2",
      "p2tr-scriptpath",
      "mixed-p2wpkh-p2tr",
      "intent-rich-p2wpkh",
      "sighash-p2wpkh",
      "sighash-p2tr-keypath",
    ]);
  });

  test("declares exact descriptor requirements without secret material", () => {
    expect(FIXTURE_PROFILES).toMatchObject([
      {
        id: "p2pkh",
        scriptTypes: ["p2pkh"],
        inputDescriptorIds: ["p2pkh"],
      },
      {
        id: "p2wpkh",
        scriptTypes: ["p2wpkh"],
        inputDescriptorIds: ["p2wpkh"],
      },
      {
        id: "p2sh-p2wpkh",
        scriptTypes: ["p2sh-p2wpkh"],
        inputDescriptorIds: ["p2sh-p2wpkh"],
      },
      {
        id: "p2sh-p2wsh-2-of-3",
        scriptTypes: ["p2sh-p2wsh"],
        inputDescriptorIds: ["p2sh-p2wsh-2-of-3"],
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
        id: "p2tr-musig2",
        scriptTypes: ["p2tr-keypath"],
        inputDescriptorIds: ["p2tr-musig2"],
      },
      {
        id: "p2tr-scriptpath",
        scriptTypes: ["p2tr-scriptpath"],
        inputDescriptorIds: ["p2tr-scriptpath"],
      },
      {
        id: "mixed-p2wpkh-p2tr",
        scriptTypes: ["p2wpkh", "p2tr-keypath"],
        inputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
      },
      {
        id: "intent-rich-p2wpkh",
        scriptTypes: ["p2wpkh"],
        inputDescriptorIds: ["p2wpkh"],
        outputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
        sequences: [0xffff_fffc],
        locktime: 42,
        transactionVersion: 2,
      },
      {
        id: "sighash-p2wpkh",
        scriptTypes: ["p2wpkh"],
        inputDescriptorIds: ["p2wpkh", "p2wpkh"],
        outputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
      },
      {
        id: "sighash-p2tr-keypath",
        scriptTypes: ["p2tr-keypath"],
        inputDescriptorIds: ["p2tr-keypath", "p2tr-keypath"],
        outputDescriptorIds: ["p2tr-keypath", "p2wpkh"],
      },
    ]);

    const descriptors = FIXTURE_PROFILES.flatMap((profile) => profile.descriptors);
    expect(descriptors).toContain(`pkh(${FIXTURE_PUBLIC_KEYS.scalar1})`);
    expect(descriptors).toContain(`wpkh(${FIXTURE_PUBLIC_KEYS.scalar1})`);
    expect(descriptors).toContain(`sh(wpkh(${FIXTURE_PUBLIC_KEYS.scalar1}))`);
    expect(descriptors).toContain(
      `sh(wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3})))`,
    );
    expect(descriptors).toContain(`wsh(pk(${FIXTURE_PUBLIC_KEYS.scalar1}))`);
    expect(descriptors).toContain(
      `wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3}))`,
    );
    expect(descriptors).toContain(`tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)})`);
    expect(descriptors).toContain(`rawtr(${MUSIG2_AGGREGATE_PUBLIC_KEY.slice(2)})`);
    expect(descriptors).toContain(
      `tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)},pk(${FIXTURE_PUBLIC_KEYS.scalar2.slice(2)}))`,
    );
    expect(descriptors.join("\n")).not.toMatch(/xprv|tprv|priv|secret/i);
    expect(FIXTURE_DESCRIPTORS["p2tr-musig2"]).toBe(
      "rawtr(3b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec)",
    );
  });
});
