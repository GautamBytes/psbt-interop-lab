export type FixtureScriptType = "p2wpkh" | "p2wsh" | "p2tr-keypath";

export const FIXTURE_PUBLIC_KEYS = {
  scalar1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  scalar2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  scalar3: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
} as const;

export const FIXTURE_DESCRIPTORS = {
  p2wpkh: `wpkh(${FIXTURE_PUBLIC_KEYS.scalar1})`,
  "p2wsh-single-key": `wsh(pk(${FIXTURE_PUBLIC_KEYS.scalar1}))`,
  "p2wsh-2-of-3": `wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3}))`,
  "p2tr-keypath": `tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)})`,
} as const;

export type FixtureDescriptorId = keyof typeof FIXTURE_DESCRIPTORS;

export interface FixtureProfileDefinition {
  id: FixtureProfileId;
  scriptTypes: readonly FixtureScriptType[];
  inputDescriptorIds: readonly FixtureDescriptorId[];
  outputDescriptorId: FixtureDescriptorId;
  descriptors: readonly string[];
  feeSats: number;
}

export type FixtureProfileId =
  | "p2wpkh"
  | "p2wsh-single-key"
  | "p2wsh-2-of-3"
  | "p2tr-keypath"
  | "mixed-p2wpkh-p2tr";

export const FIXTURE_PROFILES = [
  {
    id: "p2wpkh",
    scriptTypes: ["p2wpkh"],
    inputDescriptorIds: ["p2wpkh"],
    outputDescriptorId: "p2wpkh",
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh],
    feeSats: 11_000,
  },
  {
    id: "p2wsh-single-key",
    scriptTypes: ["p2wsh"],
    inputDescriptorIds: ["p2wsh-single-key"],
    outputDescriptorId: "p2wsh-single-key",
    descriptors: [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
    feeSats: 12_000,
  },
  {
    id: "p2wsh-2-of-3",
    scriptTypes: ["p2wsh"],
    inputDescriptorIds: ["p2wsh-2-of-3"],
    outputDescriptorId: "p2wsh-2-of-3",
    descriptors: [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]],
    feeSats: 13_000,
  },
  {
    id: "p2tr-keypath",
    scriptTypes: ["p2tr-keypath"],
    inputDescriptorIds: ["p2tr-keypath"],
    outputDescriptorId: "p2tr-keypath",
    descriptors: [FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 14_000,
  },
  {
    id: "mixed-p2wpkh-p2tr",
    scriptTypes: ["p2wpkh", "p2tr-keypath"],
    inputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
    outputDescriptorId: "p2wpkh",
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 25_000,
  },
] as const satisfies readonly FixtureProfileDefinition[];
