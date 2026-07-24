#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { detectorCanariesPassed, runDetectorCanaries } from "./canaries.js";
import {
  type DoctorCheck,
  doctorHasBlockingFailure,
  formatAdapterConformance,
  formatCanaryResults,
  formatDoctorChecks,
  formatProofSummary,
  formatReplaySummary,
  formatRunComparison,
  formatScenarioCatalog,
} from "./cli-output.js";
import { runAdapterConformance } from "./conformance/check.js";
import { loadAdapterManifest } from "./conformance/manifest.js";
import { CoreRpc } from "./core/rpc.js";
import { loadCustomSuiteManifest } from "./custom/manifest.js";
import { formatParseMatrix, runParseMatrix } from "./local/parse-matrix.js";
import { createLocalRuntimeProvider } from "./local/provider.js";
import { compareRuns } from "./runner/compare.js";
import { verifyReplay } from "./runner/replay.js";
import {
  assertProofSelectionCompatibility,
  type BuiltInAdapterId,
  PROOF_SCENARIOS,
  type ProofScenarioResources,
  resolveProofSelection,
  runProof,
} from "./scenarios/proof.js";
import { runCommand } from "./system/command.js";

const VERSION = "0.7.0";
const PROJECT_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_RPC_URL = "http://127.0.0.1:18443";
const DEFAULT_RPC_USER = "psbtlab";
const DEFAULT_RPC_PASSWORD = "psbtlab-regtest-only";
const LOCAL_RUNTIME_MANIFEST = resolve(PROJECT_DIRECTORY, "src/local/local-adapters.json");
export const QUICKSTART_SCENARIO = "happy-path";

const DOCTOR_IMAGES = [
  "psbt-interop-lab/core:31.1",
  "psbt-interop-lab/rust-bitcoin:0.1.0",
  "psbt-interop-lab/btcsuite-go:1.2.0",
  "psbt-interop-lab/bitcoinjs-lib:7.0.1",
  "psbt-interop-lab/bdkpython:2.3.1",
  "psbt-interop-lab/rust-psbt-v2:0.1.0",
  "psbt-interop-lab/bdk-wallet-current:3.1.0",
  "psbt-interop-lab/libwally:1.5.4",
] as const;

const QUICKSTART_IMAGES = DOCTOR_IMAGES.slice(0, 2);

interface RunOptions {
  suite: string;
  artifacts: string;
  rpcUrl: string;
  adapterManifest?: string;
  suiteManifest?: string;
  build: boolean;
  startCore: boolean;
  scenario: string[];
  category?: string;
}

export type BaselineOptions = Omit<RunOptions, "suite">;

interface BaselineRunRequest extends BaselineOptions {
  readonly suite: "proof";
}

export interface BaselineDependencies {
  readonly checkRuntime: () => Promise<DoctorCheck[]>;
  readonly execute: (options: BaselineRunRequest) => Promise<void>;
  readonly write: (value: string) => void;
}

export interface QuickstartOptions {
  readonly artifacts: string;
  readonly build: boolean;
  readonly keepCore: boolean;
}

interface QuickstartRunRequest {
  readonly suite: "proof";
  readonly artifacts: string;
  readonly rpcUrl: string;
  readonly build: boolean;
  readonly startCore: true;
  readonly scenario: string[];
}

export interface QuickstartDependencies {
  readonly checkRuntime: () => Promise<DoctorCheck[]>;
  readonly runCanaries: typeof runDetectorCanaries;
  readonly execute: (options: QuickstartRunRequest) => Promise<void>;
  readonly stopCore: () => Promise<void>;
  readonly write: (value: string) => void;
}

const ADAPTER_COMPOSE_SERVICES: Readonly<Record<BuiltInAdapterId, string>> = {
  "rust-bitcoin": "rust-adapter",
  "btcsuite-go": "go-adapter",
  "bitcoinjs-lib": "bitcoinjs-adapter",
  bdkpython: "bdk-adapter",
  "rust-psbt-v2": "psbt-v2-adapter",
  "bdk-wallet-current": "bdk-wallet-current-adapter",
  libwally: "libwally-adapter",
};

function nodeMajorVersion(): number {
  return Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
}

async function dockerCheck(name: string, args: string[], required = true): Promise<DoctorCheck> {
  try {
    const result = await runCommand("docker", args, {
      cwd: PROJECT_DIRECTORY,
      timeoutMs: 30_000,
    });
    return { name, ok: true, required, detail: result.stdout || "available" };
  } catch (error) {
    return {
      name,
      ok: false,
      required,
      detail: error instanceof Error ? error.message : "unknown error",
    };
  }
}

async function doctor(images: readonly string[] = DOCTOR_IMAGES): Promise<DoctorCheck[]> {
  const nodeMajor = nodeMajorVersion();
  const checks: DoctorCheck[] = [
    {
      name: "Node.js",
      ok: nodeMajor === 22 || nodeMajor === 24,
      required: true,
      detail: process.versions.node,
    },
    await dockerCheck("Docker", ["version", "--format", "{{.Server.Version}}"]),
    await dockerCheck("Docker Compose", ["compose", "version", "--short"]),
  ];
  for (const image of images) {
    const check = await dockerCheck(
      `Image ${image}`,
      ["image", "inspect", "--format", "{{.Id}}", image],
      false,
    );
    if (!check.ok) {
      check.detail = "not built (the run command builds it automatically)";
    }
    checks.push(check);
  }
  return checks;
}

async function prepareRuntime(
  options: RunOptions,
  resources: ProofScenarioResources,
): Promise<void> {
  if (options.build) {
    const services = [
      ...(resources.core ? ["core"] : []),
      ...resources.adapters.map((id) => ADAPTER_COMPOSE_SERVICES[id]),
    ];
    process.stderr.write("Building required pinned images...\n");
    await runCommand("docker", ["compose", "build", ...services], {
      cwd: PROJECT_DIRECTORY,
      timeoutMs: 10 * 60_000,
      maxOutputBytes: 8 * 1024 * 1024,
    });
  }
  if (options.startCore && resources.core) {
    process.stderr.write("Starting isolated Bitcoin Core regtest...\n");
    await runCommand("docker", ["compose", "up", "-d", "--wait", "core"], {
      cwd: PROJECT_DIRECTORY,
      timeoutMs: 2 * 60_000,
      maxOutputBytes: 2 * 1024 * 1024,
    });
  }
}

function addRuntimeOptions(command: Command): Command {
  return command
    .option(
      "--artifacts <directory>",
      "Artifact root directory",
      resolve(process.cwd(), "artifacts"),
    )
    .option("--rpc-url <url>", "Loopback Bitcoin Core RPC URL", DEFAULT_RPC_URL)
    .option("--adapter-manifest <path>", "Add trusted external adapters to the matrix")
    .option("--suite-manifest <path>", "Add deterministic fixtures and checked handoff scenarios")
    .option(
      "--scenario <id>",
      "Run one scenario (repeat for multiple scenarios)",
      (id: string, ids: string[]) => [...ids, id],
      [],
    )
    .option("--category <name>", "Run scenarios in one category")
    .option("--no-build", "Use existing Docker images without rebuilding")
    .option("--no-start-core", "Use an already-running Core instance");
}

async function executeProof(options: RunOptions): Promise<void> {
  if (options.suite !== "proof") {
    throw new Error(`Unknown suite ${options.suite}; the available suite is proof`);
  }
  const selectors = {
    ...(options.scenario.length > 0 ? { scenarios: options.scenario } : {}),
    ...(options.category !== undefined ? { category: options.category } : {}),
  };
  const selection = resolveProofSelection(selectors);
  assertProofSelectionCompatibility(selection, {
    adapter: options.adapterManifest !== undefined,
    suite: options.suiteManifest !== undefined,
  });
  const adapterManifest =
    options.adapterManifest === undefined
      ? undefined
      : await loadAdapterManifest(options.adapterManifest);
  const customSuite =
    options.suiteManifest === undefined
      ? undefined
      : await loadCustomSuiteManifest(options.suiteManifest);
  await prepareRuntime(options, selection.resources);
  const rpc = new CoreRpc({
    url: options.rpcUrl,
    username: process.env["PSBT_LAB_RPC_USER"] ?? DEFAULT_RPC_USER,
    password: process.env["PSBT_LAB_RPC_PASSWORD"] ?? DEFAULT_RPC_PASSWORD,
    timeoutMs: 60_000,
  });
  const result = await runProof({
    rpc,
    artifactRoot: resolve(options.artifacts),
    projectDirectory: PROJECT_DIRECTORY,
    ...(adapterManifest === undefined ? {} : { adapterManifest }),
    ...(customSuite === undefined ? {} : { customSuite }),
    selectors,
  });
  process.stdout.write(`${formatProofSummary(result)}\n`);
  if (result.manifest.outcome !== "passed") {
    process.exitCode = 1;
  }
}

async function stopCoreService(): Promise<void> {
  await runCommand("docker", ["compose", "stop", "core"], {
    cwd: PROJECT_DIRECTORY,
    timeoutMs: 60_000,
    maxOutputBytes: 1024 * 1024,
  });
}

function defaultQuickstartDependencies(): QuickstartDependencies {
  return {
    checkRuntime: () => doctor(QUICKSTART_IMAGES),
    runCanaries: runDetectorCanaries,
    execute: executeProof,
    stopCore: stopCoreService,
    write: (value) => process.stdout.write(value),
  };
}

function defaultBaselineDependencies(): BaselineDependencies {
  return {
    checkRuntime: () => doctor(),
    execute: executeProof,
    write: (value) => process.stdout.write(value),
  };
}

export async function runBaseline(
  options: BaselineOptions,
  dependencies: BaselineDependencies = defaultBaselineDependencies(),
): Promise<void> {
  dependencies.write("PSBT Interop Lab baseline\n\n[1/2] Checking the local runtime...\n");
  const checks = await dependencies.checkRuntime();
  dependencies.write(`${formatDoctorChecks(checks)}\n`);
  if (doctorHasBlockingFailure(checks)) {
    throw new Error("Baseline cannot continue because required runtime checks failed");
  }

  dependencies.write("\n[2/2] Running the complete proof matrix...\n");
  await dependencies.execute({ ...options, suite: "proof" });
}

export async function runQuickstart(
  options: QuickstartOptions,
  dependencies: QuickstartDependencies = defaultQuickstartDependencies(),
): Promise<void> {
  dependencies.write("PSBT Interop Lab quickstart\n\n[1/3] Checking the local runtime...\n");
  const checks = await dependencies.checkRuntime();
  dependencies.write(`${formatDoctorChecks(checks)}\n`);
  if (doctorHasBlockingFailure(checks)) {
    throw new Error("Quickstart cannot continue because required runtime checks failed");
  }

  dependencies.write("\n[2/3] Proving the semantic detectors...\n");
  const canaries = dependencies.runCanaries();
  dependencies.write(`${formatCanaryResults(canaries)}\n`);
  if (!detectorCanariesPassed(canaries)) {
    throw new Error("Quickstart cannot continue because the detector self-test failed");
  }

  dependencies.write("\n[3/3] Running one real Core -> rust-bitcoin -> Core handoff...\n");
  let executionError: unknown;
  try {
    await dependencies.execute({
      suite: "proof",
      artifacts: options.artifacts,
      rpcUrl: DEFAULT_RPC_URL,
      build: options.build,
      startCore: true,
      scenario: [QUICKSTART_SCENARIO],
    });
  } catch (error) {
    executionError = error;
  }

  let cleanupError: unknown;
  if (!options.keepCore) {
    try {
      await dependencies.stopCore();
      dependencies.write("\nCleanup: stopped the local Bitcoin Core regtest service.\n");
    } catch (error) {
      cleanupError = error;
    }
  }

  if (executionError !== undefined) {
    if (cleanupError !== undefined) {
      const detail = cleanupError instanceof Error ? cleanupError.message : "unknown error";
      dependencies.write(`\nWARN  Could not stop Bitcoin Core after the failed run: ${detail}\n`);
    }
    throw executionError;
  }
  if (cleanupError !== undefined) throw cleanupError;
}

export function createProgram(): Command {
  const program = new Command()
    .name("psbt-lab")
    .description("Deterministic PSBT interoperability proof for Bitcoin software")
    .version(VERSION)
    .showHelpAfterError();

  program
    .command("quickstart")
    .description("Check the runtime and run one real PSBT handoff with automatic cleanup")
    .option(
      "--artifacts <directory>",
      "Artifact root directory",
      resolve(process.cwd(), "artifacts"),
    )
    .option("--no-build", "Use existing Docker images without rebuilding")
    .option("--keep-core", "Leave the local Bitcoin Core regtest service running")
    .action(async (options: QuickstartOptions) => runQuickstart(options));

  addRuntimeOptions(
    program
      .command("baseline")
      .description("Check the runtime and run the complete active proof matrix"),
  ).action(async (options: BaselineOptions) => runBaseline(options));

  program
    .command("doctor")
    .description("Check the local runtime and pinned adapter images")
    .option("--json", "Print machine-readable output")
    .action(async (options: { json?: boolean }) => {
      const checks = await doctor();
      if (options.json) {
        process.stdout.write(`${JSON.stringify(checks, null, 2)}\n`);
      } else {
        process.stdout.write(`${formatDoctorChecks(checks)}\n`);
      }
      if (doctorHasBlockingFailure(checks)) {
        process.exitCode = 1;
      }
    });

  program
    .command("self-test")
    .description("Prove semantic detectors catch representative PSBT corruption")
    .action(() => {
      const results = runDetectorCanaries();
      process.stdout.write(`${formatCanaryResults(results)}\n`);
      if (!detectorCanariesPassed(results)) process.exitCode = 1;
    });

  program
    .command("list")
    .description("List the executable interoperability scenarios")
    .option("--json", "Print machine-readable output")
    .action((options: { json?: boolean }) => {
      process.stdout.write(
        options.json
          ? `${JSON.stringify(PROOF_SCENARIOS, null, 2)}\n`
          : `${formatScenarioCatalog(PROOF_SCENARIOS)}\n`,
      );
    });

  const adapter = program.command("adapter").description("Onboard external PSBT adapters");
  adapter
    .command("check <manifest>")
    .description("Run protocol and parser conformance checks from a trusted local manifest")
    .option("--json", "Print machine-readable output")
    .action(async (manifestPath: string, options: { json?: boolean }) => {
      const manifest = await loadAdapterManifest(manifestPath);
      const report = await runAdapterConformance(manifest);
      process.stdout.write(
        options.json
          ? `${JSON.stringify(report, null, 2)}\n`
          : `${formatAdapterConformance(report)}\n`,
      );
      if (!report.passed) process.exitCode = 1;
    });

  addRuntimeOptions(
    program
      .command("run")
      .description("Run an interoperability suite and write replayable artifacts")
      .option("--suite <name>", "Suite to run", "proof"),
  ).action(executeProof);

  addRuntimeOptions(
    program
      .command("matrix")
      .description("Run the complete active implementation compatibility matrix"),
  ).action(async (options: Omit<RunOptions, "suite">) => {
    await executeProof({ ...options, suite: "proof" });
  });

  program
    .command("parse-matrix")
    .description("Run deterministic parser and roundtrip fixtures without Docker or Bitcoin Core")
    .option("--runtime <runtime>", "Parser runtime provider", "local")
    .option("--json", "Print machine-readable output")
    .action(async (options: { runtime: string; json?: boolean }) => {
      if (options.runtime !== "local") {
        throw new Error(
          `Unknown parser runtime ${options.runtime}; the available runtime is local`,
        );
      }
      const provider = await createLocalRuntimeProvider({
        packageDirectory: PROJECT_DIRECTORY,
        manifestPath: LOCAL_RUNTIME_MANIFEST,
      });
      const report = await runParseMatrix(provider);
      process.stdout.write(
        options.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatParseMatrix(report)}\n`,
      );
      if (report.outcome === "failed") process.exitCode = 1;
    });

  program
    .command("stop")
    .description("Stop the bundled local Bitcoin Core regtest service")
    .action(async () => {
      await stopCoreService();
      process.stdout.write("Stopped the local Bitcoin Core regtest service.\n");
    });

  program
    .command("replay <artifact-directory>")
    .description("Verify checkpoint hashes and replay the recorded scenario outcomes")
    .action(async (directory: string) => {
      const summary = await verifyReplay(resolve(directory));
      process.stdout.write(`${formatReplaySummary(summary)}\n`);
      if (summary.outcome !== "passed") {
        process.exitCode = 1;
      }
    });

  program
    .command("compare <base-artifact-directory> <head-artifact-directory>")
    .description("Compare two replayable run artifact directories")
    .option("--json", "Print machine-readable output")
    .action(async (baseDirectory: string, headDirectory: string, options: { json?: boolean }) => {
      const comparison = await compareRuns(resolve(baseDirectory), resolve(headDirectory));
      process.stdout.write(
        options.json
          ? `${JSON.stringify(comparison, null, 2)}\n`
          : `${formatRunComparison(comparison)}\n`,
      );
      if (comparison.changed) {
        process.exitCode = 1;
      }
    });

  return program;
}

export async function main(argv = process.argv): Promise<void> {
  await createProgram().parseAsync(argv);
}

function isDirectExecution(argvEntry: string | undefined): boolean {
  if (!argvEntry) return false;

  try {
    return realpathSync(argvEntry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return resolve(argvEntry) === fileURLToPath(import.meta.url);
  }
}

if (isDirectExecution(process.argv[1])) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Unknown failure";
    process.stderr.write(`psbt-lab: ${message}\n`);
    process.exitCode = 1;
  });
}
