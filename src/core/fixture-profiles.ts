export type FixtureScriptType =
  | "p2pkh"
  | "p2wpkh"
  | "p2sh-p2wpkh"
  | "p2sh-p2wsh"
  | "p2wsh"
  | "p2tr-keypath"
  | "p2tr-scriptpath";

export const FIXTURE_PUBLIC_KEYS = {
  scalar1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  scalar2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  scalar3: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
} as const;

export const MUSIG2_AGGREGATE_PUBLIC_KEY =
  "023b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec";

export const FIXTURE_DESCRIPTORS = {
  p2pkh: `pkh(${FIXTURE_PUBLIC_KEYS.scalar1})`,
  p2wpkh: `wpkh(${FIXTURE_PUBLIC_KEYS.scalar1})`,
  "p2sh-p2wpkh": `sh(wpkh(${FIXTURE_PUBLIC_KEYS.scalar1}))`,
  "p2sh-p2wsh-2-of-3": `sh(wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3})))`,
  "p2wsh-single-key": `wsh(pk(${FIXTURE_PUBLIC_KEYS.scalar1}))`,
  "p2wsh-2-of-3": `wsh(multi(2,${FIXTURE_PUBLIC_KEYS.scalar1},${FIXTURE_PUBLIC_KEYS.scalar2},${FIXTURE_PUBLIC_KEYS.scalar3}))`,
  "p2tr-keypath": `tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)})`,
  "p2tr-musig2": `rawtr(${MUSIG2_AGGREGATE_PUBLIC_KEY.slice(2)})`,
  "p2tr-scriptpath": `tr(${FIXTURE_PUBLIC_KEYS.scalar1.slice(2)},pk(${FIXTURE_PUBLIC_KEYS.scalar2.slice(2)}))`,
} as const;

export type FixtureDescriptorId = keyof typeof FIXTURE_DESCRIPTORS;

export const FIXTURE_DESCRIPTOR_SCRIPT_TYPES = {
  p2pkh: "p2pkh",
  p2wpkh: "p2wpkh",
  "p2sh-p2wpkh": "p2sh-p2wpkh",
  "p2sh-p2wsh-2-of-3": "p2sh-p2wsh",
  "p2wsh-single-key": "p2wsh",
  "p2wsh-2-of-3": "p2wsh",
  "p2tr-keypath": "p2tr-keypath",
  "p2tr-musig2": "p2tr-keypath",
  "p2tr-scriptpath": "p2tr-scriptpath",
} as const satisfies Record<FixtureDescriptorId, FixtureScriptType>;

export interface FixtureProfileDefinition {
  id: FixtureProfileId;
  scriptTypes: readonly FixtureScriptType[];
  inputDescriptorIds: readonly FixtureDescriptorId[];
  outputDescriptorIds: readonly FixtureDescriptorId[];
  sequences: readonly number[];
  locktime: number;
  transactionVersion: number;
  descriptors: readonly string[];
  feeSats: number;
}

export type FixtureProfileId =
  | "p2pkh"
  | "p2wpkh"
  | "p2sh-p2wpkh"
  | "p2sh-p2wsh-2-of-3"
  | "p2wsh-single-key"
  | "p2wsh-2-of-3"
  | "p2tr-keypath"
  | "p2tr-musig2"
  | "p2tr-scriptpath"
  | "sighash-p2wpkh"
  | "sighash-p2tr-keypath"
  | "mixed-p2wpkh-p2tr"
  | "intent-rich-p2wpkh";

export const FIXTURE_PROFILES = [
  {
    id: "p2pkh",
    scriptTypes: ["p2pkh"],
    inputDescriptorIds: ["p2pkh"],
    outputDescriptorIds: ["p2pkh"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS.p2pkh],
    feeSats: 10_500,
  },
  {
    id: "p2wpkh",
    scriptTypes: ["p2wpkh"],
    inputDescriptorIds: ["p2wpkh"],
    outputDescriptorIds: ["p2wpkh"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh],
    feeSats: 11_000,
  },
  {
    id: "p2sh-p2wpkh",
    scriptTypes: ["p2sh-p2wpkh"],
    inputDescriptorIds: ["p2sh-p2wpkh"],
    outputDescriptorIds: ["p2sh-p2wpkh"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2sh-p2wpkh"]],
    feeSats: 11_500,
  },
  {
    id: "p2sh-p2wsh-2-of-3",
    scriptTypes: ["p2sh-p2wsh"],
    inputDescriptorIds: ["p2sh-p2wsh-2-of-3"],
    outputDescriptorIds: ["p2sh-p2wsh-2-of-3"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2sh-p2wsh-2-of-3"]],
    feeSats: 12_500,
  },
  {
    id: "p2wsh-single-key",
    scriptTypes: ["p2wsh"],
    inputDescriptorIds: ["p2wsh-single-key"],
    outputDescriptorIds: ["p2wsh-single-key"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2wsh-single-key"]],
    feeSats: 12_000,
  },
  {
    id: "p2wsh-2-of-3",
    scriptTypes: ["p2wsh"],
    inputDescriptorIds: ["p2wsh-2-of-3"],
    outputDescriptorIds: ["p2wsh-2-of-3"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2wsh-2-of-3"]],
    feeSats: 13_000,
  },
  {
    id: "p2tr-keypath",
    scriptTypes: ["p2tr-keypath"],
    inputDescriptorIds: ["p2tr-keypath"],
    outputDescriptorIds: ["p2tr-keypath"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 14_000,
  },
  {
    id: "p2tr-musig2",
    scriptTypes: ["p2tr-keypath"],
    inputDescriptorIds: ["p2tr-musig2"],
    outputDescriptorIds: ["p2tr-musig2"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2tr-musig2"]],
    feeSats: 14_250,
  },
  {
    id: "p2tr-scriptpath",
    scriptTypes: ["p2tr-scriptpath"],
    inputDescriptorIds: ["p2tr-scriptpath"],
    outputDescriptorIds: ["p2tr-scriptpath"],
    sequences: [0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2tr-scriptpath"]],
    feeSats: 14_500,
  },
  {
    id: "mixed-p2wpkh-p2tr",
    scriptTypes: ["p2wpkh", "p2tr-keypath"],
    inputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
    outputDescriptorIds: ["p2wpkh"],
    sequences: [0xffff_fffd, 0xffff_fffd],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 25_000,
  },
  {
    id: "intent-rich-p2wpkh",
    scriptTypes: ["p2wpkh"],
    inputDescriptorIds: ["p2wpkh"],
    outputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
    sequences: [0xffff_fffc],
    locktime: 42,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 15_000,
  },
  {
    id: "sighash-p2wpkh",
    scriptTypes: ["p2wpkh"],
    inputDescriptorIds: ["p2wpkh", "p2wpkh"],
    outputDescriptorIds: ["p2wpkh", "p2tr-keypath"],
    sequences: [0xffff_fffd, 0xffff_fffc],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS.p2wpkh, FIXTURE_DESCRIPTORS["p2tr-keypath"]],
    feeSats: 22_000,
  },
  {
    id: "sighash-p2tr-keypath",
    scriptTypes: ["p2tr-keypath"],
    inputDescriptorIds: ["p2tr-keypath", "p2tr-keypath"],
    outputDescriptorIds: ["p2tr-keypath", "p2wpkh"],
    sequences: [0xffff_fffd, 0xffff_fffc],
    locktime: 0,
    transactionVersion: 2,
    descriptors: [FIXTURE_DESCRIPTORS["p2tr-keypath"], FIXTURE_DESCRIPTORS.p2wpkh],
    feeSats: 28_000,
  },
] as const satisfies readonly FixtureProfileDefinition[];
