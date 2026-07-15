import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { type PsbtFixture, prepareFixtures } from "../core/fixtures.js";
import type { CoreRpc } from "../core/rpc.js";
import { AdapterProcess } from "../protocol/adapter-process.js";
import type { NegotiatedAdapter } from "../protocol/types.js";
import { ArtifactRun, type RunManifest } from "../runner/artifacts.js";
import { generateMarkdownReport, redactValue } from "../runner/report.js";
import { classifyRegression, createBdkRegressionScenario } from "./bdk-regression.js";
import { type CorePolicyResult, ScenarioExecutionContext } from "./context.js";
import {
  assertAdapterHello,
  BDK_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  GO_ADAPTER_CONTRACT,
  RUST_ADAPTER_CONTRACT,
} from "./contracts.js";
import { runScenarioCatalog } from "./engine.js";
import { classifyHappyPath, createHappyPathScenario } from "./happy-path.js";
import { createParallelCombineScenario, createRoundtripChainScenario } from "./interop-matrix.js";

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

interface FixtureCommitment {
  readonly id: string;
  readonly unsignedTxSha256: `sha256:${string}`;
}

interface DockerAdapterOptions {
  readonly platform?: string;
  readonly env?: Readonly<Record<string, string>>;
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

function createDockerAdapter(
  image: string,
  projectDirectory: string,
  options: DockerAdapterOptions = {},
): AdapterProcess {
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
  return new AdapterProcess({
    command: "docker",
    args,
    cwd: projectDirectory,
    env: { ...environment },
    maxLineBytes: 4 * 1024 * 1024,
    maxStderrBytes: 64 * 1024,
  });
}

function negotiatedMap(adapters: readonly NegotiatedAdapter[]): Map<string, NegotiatedAdapter> {
  return new Map(adapters.map((adapter) => [adapter.implementation.name, adapter]));
}

export async function runProof(options: ProofOptions): Promise<ProofResult> {
  const startedAt = new Date().toISOString();
  const runId = runIdentifier();
  const artifacts = await ArtifactRun.create(resolve(options.artifactRoot), runId);
  const fixtures = await prepareFixtures(options.rpc);
  const timeoutMs = options.adapterTimeoutMs ?? 60_000;
  const commitmentConfiguration = serializeFixtureCommitments([
    fixtures.happy,
    fixtures.regression,
  ] satisfies readonly PsbtFixture[]);
  const projectDirectory = resolve(options.projectDirectory);
  const rust = createDockerAdapter(RUST_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: commitmentConfiguration },
  });
  const go = createDockerAdapter(GO_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: commitmentConfiguration },
  });
  const bitcoinjs = createDockerAdapter(BITCOINJS_IMAGE, projectDirectory, {
    env: { [FIXTURE_COMMITMENTS_ENV]: commitmentConfiguration },
  });
  const bdk = createDockerAdapter(BDK_IMAGE, projectDirectory, { platform: "linux/amd64" });
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
      [
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
        createRoundtripChainScenario(fixtures.happy),
        createParallelCombineScenario(fixtures.happy),
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
      ],
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
    return { artifactDirectory: artifacts.directory, manifest };
  } finally {
    await Promise.all([rust.close(), go.close(), bitcoinjs.close(), bdk.close()]);
  }
}
