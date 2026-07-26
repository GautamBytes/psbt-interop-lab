import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { type AdapterManifest, FIXTURE_COMMITMENTS_ENV } from "../conformance/manifest.js";
import { createExternalAdapterScenarios } from "../conformance/matrix.js";
import { createExternalAdapterRegistry, negotiateExternalAdapter } from "../conformance/runtime.js";
import {
  type BuiltInFixtureId,
  type PreparedFixtureSet,
  type PreparedFixtures,
  type PreparedPsbtFixture,
  type PsbtFixture,
  prepareFixtures,
} from "../core/fixtures.js";
import type { CoreRpc } from "../core/rpc.js";
import {
  type CompiledUserFixturePlan,
  compileUserFixturePlans,
  compileUserParserFixtures,
} from "../custom/fixtures.js";
import type { CustomSuiteManifest } from "../custom/manifest.js";
import { compileUserScenarios } from "../custom/scenarios.js";
import { AdapterProcess, type AdapterProcessOptions } from "../protocol/adapter-process.js";
import type { NegotiatedAdapter } from "../protocol/types.js";
import { ArtifactRun, type RunManifest } from "../runner/artifacts.js";
import {
  generateHtmlReport,
  generateJsonReport,
  generateMarkdownReport,
} from "../runner/report.js";
import { createAdversarialSignerScenario } from "./adversarial-signers.js";
import { classifyRegression, createBdkRegressionScenario } from "./bdk-regression.js";
import { createBip370VectorScenario } from "./bip370.js";
import { createBip371VectorScenario } from "./bip371.js";
import { createCombinerConflictScenario } from "./combiner-conflicts.js";
import { type CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import {
  assertAdapterHello,
  BDK_ADAPTER_CONTRACT,
  BDK_CURRENT_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  GO_ADAPTER_CONTRACT,
  LIBWALLY_ADAPTER_CONTRACT,
  PSBTV2_ADAPTER_CONTRACT,
  RUST_ADAPTER_CONTRACT,
} from "./contracts.js";
import type { ScenarioDefinition } from "./definition.js";
import { runScenarioCatalog } from "./engine.js";
import { classifyHappyPath, createHappyPathScenario } from "./happy-path.js";
import {
  createParallelCombineScenario,
  createRoundtripChainScenario,
  createSameInputMultisigScenario,
  createTransactionIntentScenario,
} from "./interop-matrix.js";
import { createInvalidInputScenario } from "./invalid-inputs.js";
import { createMetadataPreservationScenario } from "./metadata-preservation.js";
import {
  createPsbtv2ConstructorScenario,
  createPsbtv2LocktimeScenario,
} from "./psbtv2-constructor.js";
import {
  createMultisigPsbtv2InteropScenario,
  createP2wpkhPsbtv2InteropScenarios,
} from "./psbtv2-interop.js";
import { createPsbtv2TaprootHandoffScenarios } from "./psbtv2-taproot.js";
import { createScriptProfileRoundtripScenario } from "./script-profile-roundtrip.js";
import { createSighashMatrixScenario } from "./sighash-matrix.js";
import {
  createTaprootScriptPathCanaryScenario,
  createTaprootScriptPathHandoffScenarios,
} from "./taproot-script-path.js";

export { classifyHappyPath, classifyRegression };
export type PolicyResult = CorePolicyResult;

const RUST_IMAGE = "psbt-interop-lab/rust-bitcoin:0.1.0";
const GO_IMAGE = "psbt-interop-lab/btcsuite-go:1.2.0";
const BITCOINJS_IMAGE = "psbt-interop-lab/bitcoinjs-lib:7.0.1";
const BDK_IMAGE = "psbt-interop-lab/bdkpython:2.3.1";
const BDK_CURRENT_IMAGE = "psbt-interop-lab/bdk-wallet-current:3.1.0";
const PSBTV2_IMAGE = "psbt-interop-lab/rust-psbt-v2:0.1.0";
const LIBWALLY_IMAGE = "psbt-interop-lab/libwally:1.5.4";
const MAX_COMMITMENT_ENV_BYTES = 4 * 1024;
const SAFE_FIXTURE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const BUILT_IN_ADAPTER_IDS = [
  "rust-bitcoin",
  "btcsuite-go",
  "bitcoinjs-lib",
  "bdkpython",
  "bdk-wallet-current",
  "rust-psbt-v2",
  "libwally",
] as const;
export type BuiltInAdapterId = (typeof BUILT_IN_ADAPTER_IDS)[number];
const MODERN_ROUNDTRIP_ADAPTERS = [
  "rust-bitcoin",
  "btcsuite-go",
  "bitcoinjs-lib",
  "bdk-wallet-current",
] as const;

export interface ProofOptions {
  rpc: CoreRpc;
  artifactRoot: string;
  projectDirectory: string;
  adapterTimeoutMs?: number;
  adapterManifest?: AdapterManifest;
  customSuite?: CustomSuiteManifest;
  selectors?: ProofSelectors;
}

export interface ProofResult {
  artifactDirectory: string;
  manifest: RunManifest;
}

export interface ProofScenarioSummary {
  readonly id: string;
  readonly title: string;
  readonly category: string;
}

export interface ProofSelectors {
  readonly scenarios?: readonly string[];
  readonly category?: string;
  readonly externalOnly?: boolean;
}

export interface ProofScenarioResources {
  readonly core: boolean;
  readonly fixtures: readonly BuiltInFixtureId[];
  readonly adapters: readonly BuiltInAdapterId[];
}

export interface ResolvedProofSelection {
  readonly scenarioIds: readonly string[];
  readonly resources: ProofScenarioResources;
  readonly filtered: boolean;
  readonly externalOnly?: boolean;
}

export const PROOF_SCENARIOS: readonly ProofScenarioSummary[] = [
  {
    id: "happy-path",
    title: "Core to rust-bitcoin signing handoff",
    category: "cross-library-signing",
  },
  {
    id: "p2wsh-sign-btcsuite-go",
    title: "Core to btcsuite signing handoff",
    category: "cross-library-signing",
  },
  {
    id: "p2wsh-sign-bitcoinjs-lib",
    title: "Core to bitcoinjs-lib signing handoff",
    category: "cross-library-signing",
  },
  {
    id: "p2wpkh-sign-rust-bitcoin",
    title: "P2WPKH signing through rust-bitcoin",
    category: "cross-library-signing",
  },
  {
    id: "p2wpkh-sign-btcsuite-go",
    title: "P2WPKH signing through btcsuite",
    category: "cross-library-signing",
  },
  {
    id: "p2wpkh-sign-bitcoinjs-lib",
    title: "P2WPKH signing through bitcoinjs-lib",
    category: "cross-library-signing",
  },
  {
    id: "p2pkh-sign-rust-bitcoin",
    title: "Legacy P2PKH signing through rust-bitcoin",
    category: "legacy-signing",
  },
  {
    id: "p2tr-keypath-sign-rust-bitcoin",
    title: "Taproot key-path signing through rust-bitcoin",
    category: "taproot-key-path",
  },
  {
    id: "p2tr-keypath-sign-btcsuite-go",
    title: "Taproot key-path signing through btcsuite",
    category: "taproot-key-path",
  },
  {
    id: "p2tr-keypath-sign-bitcoinjs-lib",
    title: "Taproot key-path signing through bitcoinjs-lib",
    category: "taproot-key-path",
  },
  {
    id: "same-input-2-of-3-multisig",
    title: "Cross-library 2-of-3 multisig signing",
    category: "cross-library-multisig",
  },
  {
    id: "nested-p2sh-p2wsh-2-of-3-multisig",
    title: "Nested P2SH-P2WSH cross-library 2-of-3 signing",
    category: "cross-library-multisig",
  },
  {
    id: "ecdsa-sighash-matrix-rust-bitcoin",
    title: "ECDSA sighash matrix through rust-bitcoin",
    category: "sighash-safety",
  },
  {
    id: "taproot-sighash-matrix-rust-bitcoin",
    title: "Taproot sighash matrix through rust-bitcoin",
    category: "sighash-safety",
  },
  {
    id: "adversarial-signer-inputs-rust-bitcoin",
    title: "Adversarial signer inputs through rust-bitcoin",
    category: "signer-safety",
  },
  {
    id: "combiner-conflicts-bitcoinjs-lib",
    title: "Combiner conflict rejection through bitcoinjs-lib",
    category: "combiner-safety",
  },
  {
    id: "four-library-roundtrip-chain",
    title: "Four-library roundtrip and signing chain",
    category: "multi-library-handoff",
  },
  {
    id: "parallel-sign-and-combine",
    title: "Parallel rust-bitcoin and btcsuite signing",
    category: "parallel-signing",
  },
  {
    id: "transaction-intent-preservation",
    title: "Transaction intent preservation",
    category: "transaction-intent",
  },
  {
    id: "invalid-and-unsupported-inputs",
    title: "Invalid and unsupported PSBT rejection matrix",
    category: "invalid-inputs",
  },
  {
    id: "proprietary-metadata-preservation",
    title: "Unknown and proprietary field preservation",
    category: "metadata-preservation",
  },
  {
    id: "bdk-finalize-regression",
    title: "BDK mixed-input finalization regression",
    category: "historical-regression",
  },
  {
    id: "bdk-regression-btcsuite-go",
    title: "BDK regression through btcsuite finalization",
    category: "historical-regression",
  },
  {
    id: "bdk-regression-bitcoinjs-lib",
    title: "BDK regression through bitcoinjs-lib finalization",
    category: "historical-regression",
  },
  {
    id: "p2wsh-sign-bdk-wallet-current",
    title: "P2WSH signing through current BDK Wallet",
    category: "cross-library-signing",
  },
  {
    id: "p2wpkh-sign-bdk-wallet-current",
    title: "P2WPKH signing through current BDK Wallet",
    category: "cross-library-signing",
  },
  {
    id: "p2tr-keypath-sign-bdk-wallet-current",
    title: "Taproot key-path signing through current BDK Wallet",
    category: "taproot-key-path",
  },
  {
    id: "nested-segwit-roundtrip-matrix",
    title: "Nested SegWit roundtrip matrix",
    category: "script-profile-roundtrip",
  },
  {
    id: "taproot-scriptpath-roundtrip-matrix",
    title: "Taproot script-path roundtrip matrix",
    category: "script-profile-roundtrip",
  },
  {
    id: "taproot-scriptpath-rust-to-bdk",
    title: "Taproot script-path rust-bitcoin to BDK handoff",
    category: "taproot-scriptpath",
  },
  {
    id: "taproot-scriptpath-bdk-to-rust",
    title: "Taproot script-path BDK to rust-bitcoin handoff",
    category: "taproot-scriptpath",
  },
  {
    id: "taproot-scriptpath-negative-canaries",
    title: "Taproot script-path metadata rejection canaries",
    category: "taproot-scriptpath",
  },
  {
    id: "bip370-official-vectors-rust-psbt-v2",
    title: "Official BIP370 vectors through rust-psbt-v2",
    category: "psbtv2-conformance",
  },
  {
    id: "bip370-official-vectors-libwally",
    title: "Official BIP370 vectors through libwally",
    category: "psbtv2-conformance",
  },
  {
    id: "psbtv2-p2wpkh-rust-to-libwally",
    title: "PSBTv2 P2WPKH rust-psbt-v2 to libwally",
    category: "psbtv2-interop",
  },
  {
    id: "psbtv2-p2wpkh-libwally-to-rust",
    title: "PSBTv2 P2WPKH libwally to rust-psbt-v2",
    category: "psbtv2-interop",
  },
  {
    id: "psbtv2-2-of-3-cross-library",
    title: "PSBTv2 2-of-3 cross-library signing and finalization",
    category: "psbtv2-interop",
  },
  {
    id: "psbtv2-constructor-workflow",
    title: "PSBTv2 constructor add, remove, update, and seal workflow",
    category: "psbtv2-constructor",
  },
  {
    id: "psbtv2-locktime-workflow",
    title: "PSBTv2 BIP370 locktime selection workflow",
    category: "psbtv2-constructor",
  },
  ...(["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdk-wallet-current"] as const).map(
    (adapter) => ({
      id: `bip371-official-vectors-${adapter}`,
      title: `Official BIP371 vectors through ${adapter}`,
      category: "taproot-conformance",
    }),
  ),
  {
    id: "psbtv2-taproot-rust-to-libwally",
    title: "PSBTv2 Taproot rust-psbt-v2 to libwally",
    category: "psbtv2-taproot",
  },
  {
    id: "psbtv2-taproot-libwally-to-rust",
    title: "PSBTv2 Taproot libwally to rust-psbt-v2",
    category: "psbtv2-taproot",
  },
];

interface FixtureCommitment {
  readonly id: string;
  readonly unsignedTxSha256: `sha256:${string}`;
}

export interface DockerAdapterOptions {
  readonly platform?: string;
  readonly env?: Readonly<Record<string, string>>;
}

export interface ProofRuntimeAdapter {
  request: AdapterProcess["request"];
  restart?(): Promise<void>;
  close(): Promise<void>;
}

export interface ProofRuntimeArtifacts {
  readonly directory: string;
  checkpoint: ArtifactRun["checkpoint"];
  writeManifest: ArtifactRun["writeManifest"];
  writeReportJson: ArtifactRun["writeReportJson"];
  writeReportMarkdown: ArtifactRun["writeReportMarkdown"];
  writeReportHtml: ArtifactRun["writeReportHtml"];
}

export interface ProofDependencies {
  createArtifacts(root: string, runId: string): Promise<ProofRuntimeArtifacts>;
  prepareFixtures(
    rpc: CoreRpc,
    customPlans?: readonly CompiledUserFixturePlan[],
    requiredFixtureIds?: readonly BuiltInFixtureId[],
  ): Promise<PreparedFixtureSet>;
  createAdapter(
    image: string,
    projectDirectory: string,
    options?: DockerAdapterOptions,
  ): ProofRuntimeAdapter;
  createExternalAdapter?(options: AdapterProcessOptions): ProofRuntimeAdapter;
  createCatalog(
    fixtures: PreparedFixtureSet | undefined,
    externalAdapters?: ReadonlyMap<string, NegotiatedAdapter>,
    selectedIds?: readonly string[],
    externalOnly?: boolean,
  ): readonly ScenarioDefinition<ScenarioExecutionContext>[];
}

export interface ProofScenarioRegistration extends ProofScenarioSummary {
  readonly resources: ProofScenarioResources;
  create(fixtures: PreparedFixtureSet | undefined): ScenarioDefinition<ScenarioExecutionContext>;
}

function requiredFixture(
  fixtures: PreparedFixtureSet | undefined,
  id: BuiltInFixtureId,
): PreparedPsbtFixture {
  const fixture =
    id === "happy-path"
      ? fixtures?.happy
      : id === "bdk-finalize-regression"
        ? fixtures?.regression
        : fixtures?.profiles[id];
  if (!fixture) throw new Error(`Required fixture ${id} was not prepared`);
  return fixture;
}

function registerScenario(
  id: string,
  resources: ProofScenarioResources,
  create: ProofScenarioRegistration["create"],
): ProofScenarioRegistration {
  const summary = PROOF_SCENARIOS.find((scenario) => scenario.id === id);
  if (!summary) throw new Error(`Missing proof scenario summary for ${id}`);
  return { ...summary, resources, create };
}

function taprootScriptPathHandoff(
  fixtures: PreparedFixtureSet | undefined,
  id: "taproot-scriptpath-rust-to-bdk" | "taproot-scriptpath-bdk-to-rust",
): ScenarioDefinition<ScenarioExecutionContext> {
  const fixture = requiredFixture(fixtures, "p2tr-scriptpath");
  const scenario = createTaprootScriptPathHandoffScenarios(fixture).find(
    (candidate) => candidate.id === id,
  );
  if (!scenario) throw new Error(`Missing Taproot script-path scenario ${id}`);
  return scenario;
}

function p2wpkhPsbtv2Handoff(
  fixtures: PreparedFixtureSet | undefined,
  id: "psbtv2-p2wpkh-rust-to-libwally" | "psbtv2-p2wpkh-libwally-to-rust",
): ScenarioDefinition<ScenarioExecutionContext> {
  const fixture = requiredFixture(fixtures, "p2wpkh");
  const scenario = createP2wpkhPsbtv2InteropScenarios(fixture).find(
    (candidate) => candidate.id === id,
  );
  if (!scenario) throw new Error(`Missing PSBTv2 P2WPKH scenario ${id}`);
  return scenario;
}

function taprootPsbtv2Handoff(
  id: "psbtv2-taproot-rust-to-libwally" | "psbtv2-taproot-libwally-to-rust",
): ScenarioDefinition<ScenarioExecutionContext> {
  const scenario = createPsbtv2TaprootHandoffScenarios().find((candidate) => candidate.id === id);
  if (!scenario) throw new Error(`Missing PSBTv2 Taproot scenario ${id}`);
  return scenario;
}

export const PROOF_SCENARIO_REGISTRATIONS: readonly ProofScenarioRegistration[] = [
  registerScenario(
    "happy-path",
    { core: true, fixtures: ["happy-path"], adapters: ["rust-bitcoin"] },
    (fixtures) => createHappyPathScenario(requiredFixture(fixtures, "happy-path")),
  ),
  registerScenario(
    "p2wsh-sign-btcsuite-go",
    { core: true, fixtures: ["happy-path"], adapters: ["btcsuite-go"] },
    (fixtures) =>
      createHappyPathScenario(requiredFixture(fixtures, "happy-path"), {
        adapter: "btcsuite-go",
        id: "p2wsh-sign-btcsuite-go",
        title: "Core to btcsuite signing handoff",
      }),
  ),
  registerScenario(
    "p2wsh-sign-bitcoinjs-lib",
    { core: true, fixtures: ["happy-path"], adapters: ["bitcoinjs-lib"] },
    (fixtures) =>
      createHappyPathScenario(requiredFixture(fixtures, "happy-path"), {
        adapter: "bitcoinjs-lib",
        id: "p2wsh-sign-bitcoinjs-lib",
        title: "Core to bitcoinjs-lib signing handoff",
      }),
  ),
  ...(
    [
      ["p2wpkh-sign-rust-bitcoin", "rust-bitcoin", "P2WPKH signing through rust-bitcoin"],
      ["p2wpkh-sign-btcsuite-go", "btcsuite-go", "P2WPKH signing through btcsuite"],
      ["p2wpkh-sign-bitcoinjs-lib", "bitcoinjs-lib", "P2WPKH signing through bitcoinjs-lib"],
    ] as const
  ).map(([id, adapter, title]) =>
    registerScenario(id, { core: true, fixtures: ["p2wpkh"], adapters: [adapter] }, (fixtures) =>
      createHappyPathScenario(requiredFixture(fixtures, "p2wpkh"), {
        adapter,
        id,
        title,
        scriptType: "p2wpkh",
        signatureKeyTypes: [0x02],
      }),
    ),
  ),
  registerScenario(
    "p2pkh-sign-rust-bitcoin",
    { core: true, fixtures: ["p2pkh"], adapters: ["rust-bitcoin"] },
    (fixtures) =>
      createHappyPathScenario(requiredFixture(fixtures, "p2pkh"), {
        adapter: "rust-bitcoin",
        id: "p2pkh-sign-rust-bitcoin",
        title: "Legacy P2PKH signing through rust-bitcoin",
        category: "legacy-signing",
        scriptType: "p2pkh",
        signatureKeyTypes: [0x02],
      }),
  ),
  ...(
    [
      [
        "p2tr-keypath-sign-rust-bitcoin",
        "rust-bitcoin",
        "Taproot key-path signing through rust-bitcoin",
      ],
      ["p2tr-keypath-sign-btcsuite-go", "btcsuite-go", "Taproot key-path signing through btcsuite"],
      [
        "p2tr-keypath-sign-bitcoinjs-lib",
        "bitcoinjs-lib",
        "Taproot key-path signing through bitcoinjs-lib",
      ],
    ] as const
  ).map(([id, adapter, title]) =>
    registerScenario(
      id,
      { core: true, fixtures: ["p2tr-keypath"], adapters: [adapter] },
      (fixtures) =>
        createHappyPathScenario(requiredFixture(fixtures, "p2tr-keypath"), {
          adapter,
          id,
          title,
          category: "taproot-key-path",
          scriptType: "p2tr-keypath",
          signatureKeyTypes: [0x13],
        }),
    ),
  ),
  registerScenario(
    "same-input-2-of-3-multisig",
    {
      core: true,
      fixtures: ["p2wsh-2-of-3"],
      adapters: ["rust-bitcoin", "bitcoinjs-lib"],
    },
    (fixtures) => createSameInputMultisigScenario(requiredFixture(fixtures, "p2wsh-2-of-3")),
  ),
  registerScenario(
    "nested-p2sh-p2wsh-2-of-3-multisig",
    {
      core: true,
      fixtures: ["p2sh-p2wsh-2-of-3"],
      adapters: ["rust-bitcoin", "bitcoinjs-lib"],
    },
    (fixtures) => createSameInputMultisigScenario(requiredFixture(fixtures, "p2sh-p2wsh-2-of-3")),
  ),
  registerScenario(
    "ecdsa-sighash-matrix-rust-bitcoin",
    {
      core: true,
      fixtures: ["sighash-p2wpkh"],
      adapters: ["rust-bitcoin"],
    },
    (fixtures) =>
      createSighashMatrixScenario(requiredFixture(fixtures, "sighash-p2wpkh"), {
        adapter: "rust-bitcoin",
        family: "ecdsa",
      }),
  ),
  registerScenario(
    "taproot-sighash-matrix-rust-bitcoin",
    {
      core: true,
      fixtures: ["sighash-p2tr-keypath"],
      adapters: ["rust-bitcoin"],
    },
    (fixtures) =>
      createSighashMatrixScenario(requiredFixture(fixtures, "sighash-p2tr-keypath"), {
        adapter: "rust-bitcoin",
        family: "taproot",
      }),
  ),
  registerScenario(
    "adversarial-signer-inputs-rust-bitcoin",
    {
      core: true,
      fixtures: ["p2wpkh", "p2pkh", "p2sh-p2wsh-2-of-3", "p2wsh-2-of-3", "p2tr-keypath"],
      adapters: ["rust-bitcoin"],
    },
    (fixtures) =>
      createAdversarialSignerScenario(
        {
          p2wpkh: requiredFixture(fixtures, "p2wpkh"),
          p2pkh: requiredFixture(fixtures, "p2pkh"),
          nested: requiredFixture(fixtures, "p2sh-p2wsh-2-of-3"),
          p2wsh: requiredFixture(fixtures, "p2wsh-2-of-3"),
          taproot: requiredFixture(fixtures, "p2tr-keypath"),
        },
        "rust-bitcoin",
      ),
  ),
  registerScenario(
    "combiner-conflicts-bitcoinjs-lib",
    {
      core: true,
      fixtures: ["p2wpkh", "p2sh-p2wsh-2-of-3", "p2wsh-2-of-3", "p2tr-keypath"],
      adapters: ["bitcoinjs-lib"],
    },
    (fixtures) =>
      createCombinerConflictScenario(
        {
          p2wpkh: requiredFixture(fixtures, "p2wpkh"),
          nested: requiredFixture(fixtures, "p2sh-p2wsh-2-of-3"),
          p2wsh: requiredFixture(fixtures, "p2wsh-2-of-3"),
          taproot: requiredFixture(fixtures, "p2tr-keypath"),
        },
        "bitcoinjs-lib",
      ),
  ),
  registerScenario(
    "four-library-roundtrip-chain",
    {
      core: true,
      fixtures: ["happy-path"],
      adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"],
    },
    (fixtures) => createRoundtripChainScenario(requiredFixture(fixtures, "happy-path")),
  ),
  registerScenario(
    "parallel-sign-and-combine",
    {
      core: true,
      fixtures: ["bdk-finalize-regression"],
      adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"],
    },
    (fixtures) =>
      createParallelCombineScenario(requiredFixture(fixtures, "bdk-finalize-regression")),
  ),
  registerScenario(
    "transaction-intent-preservation",
    {
      core: true,
      fixtures: ["intent-rich-p2wpkh"],
      adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib"],
    },
    (fixtures) => createTransactionIntentScenario(requiredFixture(fixtures, "intent-rich-p2wpkh")),
  ),
  registerScenario(
    "invalid-and-unsupported-inputs",
    {
      core: true,
      fixtures: ["happy-path"],
      adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"],
    },
    (fixtures) => createInvalidInputScenario(requiredFixture(fixtures, "happy-path")),
  ),
  registerScenario(
    "proprietary-metadata-preservation",
    {
      core: true,
      fixtures: ["p2wsh-2-of-3"],
      adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdkpython"],
    },
    (fixtures) => createMetadataPreservationScenario(requiredFixture(fixtures, "p2wsh-2-of-3")),
  ),
  ...(
    [
      ["bdk-finalize-regression", "rust-bitcoin", "BDK mixed-input finalization regression"],
      ["bdk-regression-btcsuite-go", "btcsuite-go", "BDK regression through btcsuite finalization"],
      [
        "bdk-regression-bitcoinjs-lib",
        "bitcoinjs-lib",
        "BDK regression through bitcoinjs-lib finalization",
      ],
    ] as const
  ).map(([id, adapter, title]) =>
    registerScenario(
      id,
      {
        core: true,
        fixtures: ["bdk-finalize-regression"],
        adapters: [adapter, "bdkpython"],
      },
      (fixtures) =>
        createBdkRegressionScenario(requiredFixture(fixtures, "bdk-finalize-regression"), {
          adapter,
          id,
          title,
        }),
    ),
  ),
  ...(
    [
      ["p2wsh-sign-bdk-wallet-current", "happy-path", "P2WSH signing through current BDK Wallet"],
      ["p2wpkh-sign-bdk-wallet-current", "p2wpkh", "P2WPKH signing through current BDK Wallet"],
      [
        "p2tr-keypath-sign-bdk-wallet-current",
        "p2tr-keypath",
        "Taproot key-path signing through current BDK Wallet",
      ],
    ] as const
  ).map(([id, fixtureId, title]) =>
    registerScenario(
      id,
      { core: true, fixtures: [fixtureId], adapters: ["bdk-wallet-current"] },
      (fixtures) =>
        createHappyPathScenario(requiredFixture(fixtures, fixtureId), {
          adapter: "bdk-wallet-current",
          id,
          title,
          ...(fixtureId === "p2wpkh"
            ? { scriptType: "p2wpkh" as const, signatureKeyTypes: [0x02] }
            : fixtureId === "p2tr-keypath"
              ? {
                  category: "taproot-key-path",
                  scriptType: "p2tr-keypath" as const,
                  signatureKeyTypes: [0x13],
                }
              : {}),
        }),
    ),
  ),
  ...(
    [
      ["nested-segwit-roundtrip-matrix", "p2sh-p2wpkh", "Nested SegWit roundtrip matrix"],
      [
        "taproot-scriptpath-roundtrip-matrix",
        "p2tr-scriptpath",
        "Taproot script-path roundtrip matrix",
      ],
    ] as const
  ).map(([id, fixtureId, title]) =>
    registerScenario(
      id,
      {
        core: true,
        fixtures: [fixtureId],
        adapters: ["rust-bitcoin", "btcsuite-go", "bitcoinjs-lib", "bdk-wallet-current"],
      },
      (fixtures) =>
        createScriptProfileRoundtripScenario(requiredFixture(fixtures, fixtureId), {
          id,
          title,
          adapters: MODERN_ROUNDTRIP_ADAPTERS,
        }),
    ),
  ),
  ...(["taproot-scriptpath-rust-to-bdk", "taproot-scriptpath-bdk-to-rust"] as const).map((id) =>
    registerScenario(
      id,
      {
        core: true,
        fixtures: ["p2tr-scriptpath"],
        adapters: ["rust-bitcoin", "bdk-wallet-current"],
      },
      (fixtures) => taprootScriptPathHandoff(fixtures, id),
    ),
  ),
  registerScenario(
    "taproot-scriptpath-negative-canaries",
    {
      core: true,
      fixtures: ["p2tr-scriptpath"],
      adapters: ["rust-bitcoin", "bdk-wallet-current"],
    },
    (fixtures) =>
      createTaprootScriptPathCanaryScenario(requiredFixture(fixtures, "p2tr-scriptpath")),
  ),
  registerScenario(
    "bip370-official-vectors-rust-psbt-v2",
    { core: false, fixtures: [], adapters: ["rust-psbt-v2"] },
    () => createBip370VectorScenario("rust-psbt-v2"),
  ),
  registerScenario(
    "bip370-official-vectors-libwally",
    { core: false, fixtures: [], adapters: ["libwally"] },
    () => createBip370VectorScenario("libwally", "libwally-core"),
  ),
  ...(["psbtv2-p2wpkh-rust-to-libwally", "psbtv2-p2wpkh-libwally-to-rust"] as const).map((id) =>
    registerScenario(
      id,
      {
        core: true,
        fixtures: ["p2wpkh"],
        adapters: ["rust-psbt-v2", "libwally"],
      },
      (fixtures) => p2wpkhPsbtv2Handoff(fixtures, id),
    ),
  ),
  registerScenario(
    "psbtv2-2-of-3-cross-library",
    {
      core: true,
      fixtures: ["p2wsh-2-of-3"],
      adapters: ["rust-psbt-v2", "libwally"],
    },
    (fixtures) => createMultisigPsbtv2InteropScenario(requiredFixture(fixtures, "p2wsh-2-of-3")),
  ),
  registerScenario(
    "psbtv2-constructor-workflow",
    { core: false, fixtures: [], adapters: ["rust-psbt-v2"] },
    () => createPsbtv2ConstructorScenario(),
  ),
  registerScenario(
    "psbtv2-locktime-workflow",
    { core: false, fixtures: [], adapters: ["rust-psbt-v2"] },
    () => createPsbtv2LocktimeScenario(),
  ),
  ...MODERN_ROUNDTRIP_ADAPTERS.map((adapter) =>
    registerScenario(
      `bip371-official-vectors-${adapter}`,
      { core: false, fixtures: [], adapters: [adapter] },
      () =>
        createBip371VectorScenario(
          adapter,
          adapter === "bdk-wallet-current" ? "bdk_wallet::bitcoin::Psbt" : adapter,
        ),
    ),
  ),
  ...(["psbtv2-taproot-rust-to-libwally", "psbtv2-taproot-libwally-to-rust"] as const).map((id) =>
    registerScenario(
      id,
      {
        core: false,
        fixtures: [],
        adapters: ["rust-psbt-v2", "libwally"],
      },
      () => taprootPsbtv2Handoff(id),
    ),
  ),
];

export function resolveProofSelection(selectors: ProofSelectors = {}): ResolvedProofSelection {
  if (selectors.externalOnly) {
    if ((selectors.scenarios?.length ?? 0) > 0 || selectors.category !== undefined) {
      throw new TypeError("External-only execution cannot be combined with scenario selectors");
    }
    return {
      scenarioIds: [],
      resources: {
        core: true,
        fixtures: ["happy-path", "p2wpkh", "p2sh-p2wpkh", "p2tr-keypath", "p2tr-scriptpath"],
        adapters: [],
      },
      filtered: true,
      externalOnly: true,
    };
  }
  const requestedIds = [...new Set(selectors.scenarios ?? [])];
  const byId = new Map(
    PROOF_SCENARIO_REGISTRATIONS.map((registration) => [registration.id, registration]),
  );
  const unknownIds = requestedIds.filter((id) => !byId.has(id));
  if (unknownIds.length > 0) {
    throw new TypeError(
      `Unknown scenario${unknownIds.length === 1 ? "" : "s"} ${unknownIds.join(", ")}. Available scenarios: ${PROOF_SCENARIOS.map(({ id }) => id).join(", ")}`,
    );
  }
  const categories = [...new Set(PROOF_SCENARIOS.map(({ category }) => category))];
  if (selectors.category !== undefined && !categories.includes(selectors.category)) {
    throw new TypeError(
      `Unknown category ${selectors.category}. Available categories: ${categories.join(", ")}`,
    );
  }
  const selected = (
    requestedIds.length > 0
      ? requestedIds.map((id) => byId.get(id) as ProofScenarioRegistration)
      : [...PROOF_SCENARIO_REGISTRATIONS]
  ).filter((registration) =>
    selectors.category === undefined ? true : registration.category === selectors.category,
  );
  if (selected.length === 0) {
    throw new TypeError(
      `No requested scenarios match category ${selectors.category ?? "selection"}`,
    );
  }
  const fixtureIds = [
    ...new Set(selected.flatMap((registration) => registration.resources.fixtures)),
  ];
  const adapterIds = new Set(selected.flatMap((registration) => registration.resources.adapters));
  return {
    scenarioIds: selected.map(({ id }) => id),
    resources: {
      core: selected.some((registration) => registration.resources.core),
      fixtures: fixtureIds,
      adapters: BUILT_IN_ADAPTER_IDS.filter((id) => adapterIds.has(id)),
    },
    filtered: requestedIds.length > 0 || selectors.category !== undefined,
  };
}

export function assertProofSelectionCompatibility(
  selection: ResolvedProofSelection,
  manifests: { readonly adapter: boolean; readonly suite: boolean },
): void {
  if (selection.externalOnly && !manifests.adapter) {
    throw new Error("External-only execution requires an adapter manifest");
  }
  if (selection.externalOnly && manifests.suite) {
    throw new Error("External-only execution cannot be combined with a suite manifest");
  }
  if (selection.filtered && manifests.suite) {
    throw new Error(
      "Scenario selection cannot be combined with a suite manifest because custom scenarios are not statically registered",
    );
  }
  if (selection.filtered && manifests.adapter && !selection.externalOnly) {
    throw new Error(
      "Scenario selection cannot be combined with an adapter manifest because external scenarios require capability negotiation",
    );
  }
}

function runIdentifier(date = new Date()): string {
  const timestamp = date
    .toISOString()
    .replace(/[^0-9]/g, "")
    .slice(0, 14);
  return `${timestamp}-${randomBytes(4).toString("hex")}`;
}

export function serializeFixtureCommitments(fixtures: readonly FixtureCommitment[]): string {
  const commitments: Record<string, string> = {};
  for (const fixture of fixtures) {
    if (!SAFE_FIXTURE_ID.test(fixture.id)) {
      throw new TypeError(`Invalid fixture id ${fixture.id}`);
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(fixture.unsignedTxSha256)) {
      throw new TypeError(`Invalid unsigned transaction commitment for ${fixture.id}`);
    }
    if (commitments[fixture.id] !== undefined) {
      throw new TypeError(`Duplicate fixture id ${fixture.id}`);
    }
    commitments[fixture.id] = fixture.unsignedTxSha256;
  }
  const encoded = JSON.stringify(commitments);
  if (Buffer.byteLength(encoded, "utf8") > MAX_COMMITMENT_ENV_BYTES) {
    throw new TypeError("Fixture commitment configuration exceeds its size limit");
  }
  return encoded;
}

export function dockerAdapterProcessOptions(
  image: string,
  projectDirectory: string,
  options: DockerAdapterOptions = {},
): AdapterProcessOptions {
  const environment = options.env ?? {};
  const environmentKeys = Object.keys(environment).sort();
  const args = [
    "run",
    "--rm",
    "-i",
    "--pull",
    "never",
    ...(options.platform ? ["--platform", options.platform] : []),
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--pids-limit",
    "64",
    "--memory",
    "256m",
    "--security-opt",
    "no-new-privileges:true",
    ...environmentKeys.flatMap((key) => ["--env", key]),
    image,
  ];
  return {
    command: "docker",
    args,
    cwd: projectDirectory,
    env: { ...environment },
    maxLineBytes: 4 * 1024 * 1024,
    maxStderrBytes: 64 * 1024,
  };
}

function createDockerAdapter(
  image: string,
  projectDirectory: string,
  options: DockerAdapterOptions = {},
): AdapterProcess {
  return new AdapterProcess(dockerAdapterProcessOptions(image, projectDirectory, options));
}

function negotiatedMap(adapters: readonly NegotiatedAdapter[]): Map<string, NegotiatedAdapter> {
  return new Map(
    adapters.map((adapter) => [adapter.registryId ?? adapter.implementation.name, adapter]),
  );
}

export function createProofCatalog(
  fixtures: PreparedFixtureSet | undefined,
  externalAdapters: ReadonlyMap<string, NegotiatedAdapter> = new Map(),
  selectedIds?: readonly string[],
  externalOnly = false,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  if (externalOnly) {
    if (!fixtures) throw new Error("External adapter scenarios require prepared fixtures");
    return createExternalAdapterScenarios(fixtures as PreparedFixtures, externalAdapters);
  }
  const selected = selectedIds
    ? selectedIds.map((id) => {
        const registration = PROOF_SCENARIO_REGISTRATIONS.find((candidate) => candidate.id === id);
        if (!registration) throw new TypeError(`Unknown selected scenario ${id}`);
        return registration;
      })
    : PROOF_SCENARIO_REGISTRATIONS;
  const definitions = selected.map((registration) => registration.create(fixtures));
  for (const [index, definition] of definitions.entries()) {
    const registration = selected[index];
    if (
      !registration ||
      definition.id !== registration.id ||
      definition.title !== registration.title ||
      definition.category !== registration.category
    ) {
      throw new Error(`Proof scenario catalog metadata mismatch at index ${index}`);
    }
  }
  if (selectedIds || externalAdapters.size === 0) return definitions;
  if (!fixtures) throw new Error("External adapter scenarios require prepared fixtures");
  return [
    ...definitions,
    ...createExternalAdapterScenarios(fixtures as PreparedFixtures, externalAdapters),
  ];
}

const DEFAULT_DEPENDENCIES: ProofDependencies = {
  createArtifacts: ArtifactRun.create,
  prepareFixtures,
  createAdapter: createDockerAdapter,
  createExternalAdapter: (options) => new AdapterProcess(options),
  createCatalog: createProofCatalog,
};

const COMMON_COMMITMENT_FIXTURES: readonly BuiltInFixtureId[] = [
  "happy-path",
  "bdk-finalize-regression",
  "p2wpkh",
  "p2wsh-2-of-3",
  "p2tr-keypath",
];
const RUST_COMMITMENT_FIXTURES: readonly BuiltInFixtureId[] = [
  ...COMMON_COMMITMENT_FIXTURES,
  "p2pkh",
  "p2sh-p2wsh-2-of-3",
  "p2tr-scriptpath",
  "intent-rich-p2wpkh",
  "sighash-p2wpkh",
  "sighash-p2tr-keypath",
];
const BITCOINJS_COMMITMENT_FIXTURES: readonly BuiltInFixtureId[] = [
  ...COMMON_COMMITMENT_FIXTURES,
  "p2sh-p2wsh-2-of-3",
];
const BDK_CURRENT_COMMITMENT_FIXTURES: readonly BuiltInFixtureId[] = [
  "happy-path",
  "bdk-finalize-regression",
  "p2wpkh",
  "p2wsh-single-key",
  "p2wsh-2-of-3",
  "p2tr-keypath",
  "p2tr-scriptpath",
  "intent-rich-p2wpkh",
];
const PSBTV2_COMMITMENT_FIXTURES: readonly BuiltInFixtureId[] = [
  "p2wpkh",
  "intent-rich-p2wpkh",
  "p2wsh-2-of-3",
];

function preparedFixture(
  fixtures: PreparedFixtureSet | undefined,
  id: BuiltInFixtureId,
): PreparedPsbtFixture | undefined {
  return id === "happy-path"
    ? fixtures?.happy
    : id === "bdk-finalize-regression"
      ? fixtures?.regression
      : fixtures?.profiles[id];
}

function adapterImage(id: BuiltInAdapterId): string {
  switch (id) {
    case "rust-bitcoin":
      return RUST_IMAGE;
    case "btcsuite-go":
      return GO_IMAGE;
    case "bitcoinjs-lib":
      return BITCOINJS_IMAGE;
    case "bdkpython":
      return BDK_IMAGE;
    case "bdk-wallet-current":
      return BDK_CURRENT_IMAGE;
    case "rust-psbt-v2":
      return PSBTV2_IMAGE;
    case "libwally":
      return LIBWALLY_IMAGE;
  }
}

function adapterOptions(
  id: BuiltInAdapterId,
  fixtures: PreparedFixtureSet | undefined,
): DockerAdapterOptions {
  if (id === "bdkpython") return { platform: "linux/amd64" };
  const commitmentIds =
    id === "rust-bitcoin"
      ? RUST_COMMITMENT_FIXTURES
      : id === "bitcoinjs-lib"
        ? BITCOINJS_COMMITMENT_FIXTURES
        : id === "bdk-wallet-current"
          ? BDK_CURRENT_COMMITMENT_FIXTURES
          : id === "rust-psbt-v2" || id === "libwally"
            ? PSBTV2_COMMITMENT_FIXTURES
            : COMMON_COMMITMENT_FIXTURES;
  const commitments = commitmentIds.flatMap((fixtureId) => {
    const fixture = preparedFixture(fixtures, fixtureId);
    return fixture ? [fixture] : [];
  });
  if (commitments.length === 0) return {};
  return {
    env: { [FIXTURE_COMMITMENTS_ENV]: serializeFixtureCommitments(commitments) },
  };
}

async function negotiateBuiltInAdapter(
  id: BuiltInAdapterId,
  context: ScenarioExecutionContext,
): Promise<NegotiatedAdapter> {
  const response = await context.request(id, "hello", {});
  switch (id) {
    case "rust-bitcoin":
      return assertAdapterHello(response, RUST_ADAPTER_CONTRACT);
    case "btcsuite-go":
      return assertAdapterHello(response, GO_ADAPTER_CONTRACT);
    case "bitcoinjs-lib":
      return assertAdapterHello(response, BITCOINJS_ADAPTER_CONTRACT);
    case "bdkpython":
      return assertAdapterHello(response, BDK_ADAPTER_CONTRACT);
    case "bdk-wallet-current":
      return assertAdapterHello(response, BDK_CURRENT_ADAPTER_CONTRACT);
    case "rust-psbt-v2":
      return assertAdapterHello(response, PSBTV2_ADAPTER_CONTRACT);
    case "libwally":
      return assertAdapterHello(response, LIBWALLY_ADAPTER_CONTRACT);
  }
}

export async function runProofWithDependencies(
  options: ProofOptions,
  dependencies: ProofDependencies,
): Promise<ProofResult> {
  const selection = resolveProofSelection(options.selectors);
  assertProofSelectionCompatibility(selection, {
    adapter: options.adapterManifest !== undefined,
    suite: options.customSuite !== undefined,
  });
  const startedAt = new Date().toISOString();
  const runId = runIdentifier();
  const artifacts = await dependencies.createArtifacts(resolve(options.artifactRoot), runId);
  const customPlans =
    !selection.filtered && options.customSuite
      ? compileUserFixturePlans(options.customSuite.fixtures)
      : [];
  const fixtures = selection.resources.core
    ? selection.filtered
      ? await dependencies.prepareFixtures(options.rpc, customPlans, selection.resources.fixtures)
      : await dependencies.prepareFixtures(options.rpc, customPlans)
    : undefined;
  const timeoutMs = options.adapterTimeoutMs ?? 60_000;
  const projectDirectory = resolve(options.projectDirectory);
  const builtInRuntime = new Map<BuiltInAdapterId, ProofRuntimeAdapter>();
  for (const id of selection.resources.adapters) {
    builtInRuntime.set(
      id,
      dependencies.createAdapter(adapterImage(id), projectDirectory, adapterOptions(id, fixtures)),
    );
  }
  const externalCommitmentConfiguration =
    (!selection.filtered || selection.externalOnly) && options.adapterManifest && fixtures
      ? serializeFixtureCommitments([
          requiredFixture(fixtures, "happy-path"),
          requiredFixture(fixtures, "p2wpkh"),
          requiredFixture(fixtures, "p2sh-p2wpkh"),
          requiredFixture(fixtures, "p2tr-keypath"),
          requiredFixture(fixtures, "p2tr-scriptpath"),
          ...Object.values(fixtures.custom),
        ] satisfies readonly PsbtFixture[])
      : undefined;
  const externalRuntime =
    (!selection.filtered || selection.externalOnly) && options.adapterManifest
      ? createExternalAdapterRegistry(
          options.adapterManifest,
          externalCommitmentConfiguration as string,
          dependencies.createExternalAdapter ??
            ((processOptions) => new AdapterProcess(processOptions)),
          BUILT_IN_ADAPTER_IDS,
        )
      : new Map();
  const context = new ScenarioExecutionContext({
    rpc: options.rpc,
    artifacts,
    adapters: new Map([
      ...builtInRuntime,
      ...[...externalRuntime].map(([id, runtime]) => [id, runtime.process] as const),
    ]),
    adapterTimeoutMs: timeoutMs,
  });

  try {
    const builtInNegotiated: NegotiatedAdapter[] = [];
    for (const id of selection.resources.adapters) {
      try {
        builtInNegotiated.push({
          ...(await negotiateBuiltInAdapter(id, context)),
          registryId: id,
        });
      } catch {
        // Capability checks will mark scenarios that require this adapter as unsupported.
      }
    }
    const externalNegotiated = new Map<string, NegotiatedAdapter>();
    for (const [id, runtime] of externalRuntime) {
      externalNegotiated.set(id, await negotiateExternalAdapter(runtime));
    }
    const negotiated = [...builtInNegotiated, ...externalNegotiated.values()];
    const customScenarios =
      !selection.filtered && options.customSuite && fixtures
        ? compileUserScenarios(
            options.customSuite.scenarios,
            new Map([
              ...Object.entries(fixtures.custom),
              ...compileUserParserFixtures(options.customSuite.parserFixtures ?? []),
            ]),
          )
        : [];
    const builtInCatalog = dependencies.createCatalog(
      fixtures,
      externalNegotiated,
      selection.filtered && !selection.externalOnly ? selection.scenarioIds : undefined,
      selection.externalOnly,
    );
    const scenarios = await runScenarioCatalog(
      [...builtInCatalog, ...customScenarios],
      context,
      negotiatedMap(negotiated),
    );
    const outcome = scenarios.every((scenario) => scenario.outcome === "passed")
      ? "passed"
      : "failed";
    const manifest: RunManifest = {
      schema: "psbt-lab.run/0.1",
      runId,
      suite: "proof",
      startedAt,
      completedAt: new Date().toISOString(),
      outcome,
      ...(fixtures ? { core: fixtures.core } : {}),
      selectors: {
        requested: {
          ...(options.selectors?.scenarios?.length
            ? { scenarios: [...options.selectors.scenarios] }
            : {}),
          ...(options.selectors?.category !== undefined
            ? { category: options.selectors.category }
            : {}),
          ...(options.selectors?.externalOnly ? { externalOnly: true } : {}),
        },
        executed: {
          scenarios: scenarios.map(({ id }) => id),
          categories: [...new Set(scenarios.map(({ category }) => category))],
        },
      },
      adapters: negotiated.map((adapter) => ({
        ...adapter.implementation,
        capabilities: adapter.capabilities,
      })),
      scenarios,
      checkpoints: [...context.checkpoints],
    };
    await artifacts.writeManifest(manifest);
    await artifacts.writeReportJson(generateJsonReport(manifest));
    await artifacts.writeReportMarkdown(generateMarkdownReport(manifest));
    await artifacts.writeReportHtml(generateHtmlReport(manifest));
    return { artifactDirectory: artifacts.directory, manifest };
  } finally {
    await Promise.all([
      ...[...builtInRuntime.values()].map((runtime) => runtime.close()),
      ...[...externalRuntime.values()].map((runtime) => runtime.process.close()),
    ]);
  }
}

export async function runProof(options: ProofOptions): Promise<ProofResult> {
  return runProofWithDependencies(options, DEFAULT_DEPENDENCIES);
}
