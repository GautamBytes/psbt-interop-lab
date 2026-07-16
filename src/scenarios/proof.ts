import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { type PreparedFixtures, type PsbtFixture, prepareFixtures } from "../core/fixtures.js";
import type { CoreRpc } from "../core/rpc.js";
import { AdapterProcess, type AdapterProcessOptions } from "../protocol/adapter-process.js";
import type { NegotiatedAdapter } from "../protocol/types.js";
import { ArtifactRun, type RunManifest } from "../runner/artifacts.js";
import { generateHtmlReport, generateMarkdownReport, redactValue } from "../runner/report.js";
import { classifyRegression, createBdkRegressionScenario } from "./bdk-regression.js";
import { type CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import {
  assertAdapterHello,
  BDK_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  GO_ADAPTER_CONTRACT,
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

export { classifyHappyPath, classifyRegression };
export type PolicyResult = CorePolicyResult;

const RUST_IMAGE = "psbt-interop-lab/rust-bitcoin:0.1.0";
const GO_IMAGE = "psbt-interop-lab/btcsuite-go:1.2.0";
const BITCOINJS_IMAGE = "psbt-interop-lab/bitcoinjs-lib:7.0.1";
const BDK_IMAGE = "psbt-interop-lab/bdkpython:2.3.1";
const FIXTURE_COMMITMENTS_ENV = "PSBT_LAB_FIXTURE_COMMITMENTS";
const MAX_COMMITMENT_ENV_BYTES = 4 * 1024;
const SAFE_FIXTURE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface ProofOptions {
  rpc: CoreRpc;
  artifactRoot: string;
  projectDirectory: string;
  adapterTimeoutMs?: number;
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
  prepareFixtures(rpc: CoreRpc): Promise<PreparedFixtures>;
  createAdapter(
    image: string,
    projectDirectory: string,
    options?: DockerAdapterOptions,
  ): ProofRuntimeAdapter;
  createCatalog(
    fixtures: PreparedFixtures,
  ): readonly ScenarioDefinition<ScenarioExecutionContext>[];
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
  return new Map(adapters.map((adapter) => [adapter.implementation.name, adapter]));
}

export function createProofCatalog(
  fixtures: PreparedFixtures,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  const definitions = [
    createHappyPathScenario(fixtures.happy),
    createHappyPathScenario(fixtures.happy, {
      adapter: "btcsuite-go",
      id: "p2wsh-sign-btcsuite-go",
      title: "Core to btcsuite signing handoff",
    }),
    createHappyPathScenario(fixtures.happy, {
      adapter: "bitcoinjs-lib",
      id: "p2wsh-sign-bitcoinjs-lib",
      title: "Core to bitcoinjs-lib signing handoff",
    }),
    createHappyPathScenario(fixtures.profiles.p2wpkh, {
      adapter: "rust-bitcoin",
      id: "p2wpkh-sign-rust-bitcoin",
      title: "P2WPKH signing through rust-bitcoin",
      scriptType: "p2wpkh",
      signatureKeyTypes: [0x02],
    }),
    createHappyPathScenario(fixtures.profiles.p2wpkh, {
      adapter: "btcsuite-go",
      id: "p2wpkh-sign-btcsuite-go",
      title: "P2WPKH signing through btcsuite",
      scriptType: "p2wpkh",
      signatureKeyTypes: [0x02],
    }),
    createHappyPathScenario(fixtures.profiles.p2wpkh, {
      adapter: "bitcoinjs-lib",
      id: "p2wpkh-sign-bitcoinjs-lib",
      title: "P2WPKH signing through bitcoinjs-lib",
      scriptType: "p2wpkh",
      signatureKeyTypes: [0x02],
    }),
    createHappyPathScenario(fixtures.profiles["p2tr-keypath"], {
      adapter: "rust-bitcoin",
      id: "p2tr-keypath-sign-rust-bitcoin",
      title: "Taproot key-path signing through rust-bitcoin",
      category: "taproot-key-path",
      scriptType: "p2tr-keypath",
      signatureKeyTypes: [0x13],
    }),
    createHappyPathScenario(fixtures.profiles["p2tr-keypath"], {
      adapter: "btcsuite-go",
      id: "p2tr-keypath-sign-btcsuite-go",
      title: "Taproot key-path signing through btcsuite",
      category: "taproot-key-path",
      scriptType: "p2tr-keypath",
      signatureKeyTypes: [0x13],
    }),
    createHappyPathScenario(fixtures.profiles["p2tr-keypath"], {
      adapter: "bitcoinjs-lib",
      id: "p2tr-keypath-sign-bitcoinjs-lib",
      title: "Taproot key-path signing through bitcoinjs-lib",
      category: "taproot-key-path",
      scriptType: "p2tr-keypath",
      signatureKeyTypes: [0x13],
    }),
    createSameInputMultisigScenario(fixtures.profiles["p2wsh-2-of-3"]),
    createRoundtripChainScenario(fixtures.happy),
    createParallelCombineScenario(fixtures.regression),
    createTransactionIntentScenario(fixtures.profiles["intent-rich-p2wpkh"]),
    createInvalidInputScenario(fixtures.happy),
    createMetadataPreservationScenario(fixtures.happy),
    createBdkRegressionScenario(fixtures.regression),
    createBdkRegressionScenario(fixtures.regression, {
      adapter: "btcsuite-go",
      id: "bdk-regression-btcsuite-go",
      title: "BDK regression through btcsuite finalization",
    }),
    createBdkRegressionScenario(fixtures.regression, {
      adapter: "bitcoinjs-lib",
      id: "bdk-regression-bitcoinjs-lib",
      title: "BDK regression through bitcoinjs-lib finalization",
    }),
  ];
  for (const [index, definition] of definitions.entries()) {
    const declared = PROOF_SCENARIOS[index];
    if (
      !declared ||
      definition.id !== declared.id ||
      definition.title !== declared.title ||
      definition.category !== declared.category
    ) {
      throw new Error(`Proof scenario catalog metadata mismatch at index ${index}`);
    }
  }
  return definitions;
}

const DEFAULT_DEPENDENCIES: ProofDependencies = {
  createArtifacts: ArtifactRun.create,
  prepareFixtures,
  createAdapter: createDockerAdapter,
  createCatalog: createProofCatalog,
};

export async function runProofWithDependencies(
  options: ProofOptions,
  dependencies: ProofDependencies,
): Promise<ProofResult> {
  const startedAt = new Date().toISOString();
  const runId = runIdentifier();
  const artifacts = await dependencies.createArtifacts(resolve(options.artifactRoot), runId);
  const fixtures = await dependencies.prepareFixtures(options.rpc);
  const timeoutMs = options.adapterTimeoutMs ?? 60_000;
  const commonCommitmentConfiguration = serializeFixtureCommitments([
    fixtures.happy,
    fixtures.regression,
    fixtures.profiles.p2wpkh,
    fixtures.profiles["p2wsh-2-of-3"],
    fixtures.profiles["p2tr-keypath"],
  ] satisfies readonly PsbtFixture[]);
  const rustCommitmentConfiguration = serializeFixtureCommitments([
    fixtures.happy,
    fixtures.regression,
    fixtures.profiles.p2wpkh,
    fixtures.profiles["p2wsh-2-of-3"],
    fixtures.profiles["p2tr-keypath"],
    fixtures.profiles["intent-rich-p2wpkh"],
  ] satisfies readonly PsbtFixture[]);
  const projectDirectory = resolve(options.projectDirectory);
  const rust = dependencies.createAdapter(RUST_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: rustCommitmentConfiguration },
  });
  const go = dependencies.createAdapter(GO_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: commonCommitmentConfiguration },
  });
  const bitcoinjs = dependencies.createAdapter(BITCOINJS_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: commonCommitmentConfiguration },
  });
  const bdk = dependencies.createAdapter(BDK_IMAGE, projectDirectory, {
    platform: "linux/amd64",
  });
  const context = new ScenarioExecutionContext({
    rpc: options.rpc,
    artifacts,
    adapters: new Map([
      ["rust-bitcoin", rust],
      ["btcsuite-go", go],
      ["bitcoinjs-lib", bitcoinjs],
      ["bdkpython", bdk],
    ]),
    adapterTimeoutMs: timeoutMs,
  });

  try {
    const rustHello = assertAdapterHello(
      await context.request("rust-bitcoin", "hello", {}),
      RUST_ADAPTER_CONTRACT,
    );
    const bdkHello = assertAdapterHello(
      await context.request("bdkpython", "hello", {}),
      BDK_ADAPTER_CONTRACT,
    );
    const goHello = assertAdapterHello(
      await context.request("btcsuite-go", "hello", {}),
      GO_ADAPTER_CONTRACT,
    );
    const bitcoinjsHello = assertAdapterHello(
      await context.request("bitcoinjs-lib", "hello", {}),
      BITCOINJS_ADAPTER_CONTRACT,
    );
    const negotiated = [rustHello, goHello, bitcoinjsHello, bdkHello];
    const scenarios = await runScenarioCatalog(
      dependencies.createCatalog(fixtures),
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
      core: fixtures.core,
      adapters: negotiated.map((adapter) => adapter.implementation),
      scenarios,
      checkpoints: [...context.checkpoints],
    };
    await artifacts.writeManifest(manifest);
    await artifacts.writeReportJson(
      redactValue({
        ...manifest,
        note: "Raw PSBTs are intentionally stored only in private checkpoint files.",
      }),
    );
    await artifacts.writeReportMarkdown(generateMarkdownReport(manifest));
    await artifacts.writeReportHtml(generateHtmlReport(manifest));
    return { artifactDirectory: artifacts.directory, manifest };
  } finally {
    await Promise.all([rust.close(), go.close(), bitcoinjs.close(), bdk.close()]);
  }
}

export async function runProof(options: ProofOptions): Promise<ProofResult> {
  return runProofWithDependencies(options, DEFAULT_DEPENDENCIES);
}
