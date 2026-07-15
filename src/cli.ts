#!/usr/bin/env node

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import {
  type DoctorCheck,
  doctorHasBlockingFailure,
  formatDoctorChecks,
  formatProofSummary,
  formatReplaySummary,
} from "./cli-output.js";
import { CoreRpc } from "./core/rpc.js";
import { verifyReplay } from "./runner/replay.js";
import { runProof } from "./scenarios/proof.js";
import { runCommand } from "./system/command.js";

const VERSION = "0.0.1";
const PROJECT_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_RPC_URL = "http://127.0.0.1:18443";
const DEFAULT_RPC_USER = "psbtlab";
const DEFAULT_RPC_PASSWORD = "psbtlab-regtest-only";

interface RunOptions {
  suite: string;
  artifacts: string;
  rpcUrl: string;
  build: boolean;
  startCore: boolean;
}

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

async function doctor(): Promise<DoctorCheck[]> {
  const nodeMajor = nodeMajorVersion();
  const checks: DoctorCheck[] = [
    {
      name: "Node.js",
      ok: nodeMajor >= 22,
      required: true,
      detail: process.versions.node,
    },
    await dockerCheck("Docker", ["version", "--format", "{{.Server.Version}}"]),
    await dockerCheck("Docker Compose", ["compose", "version", "--short"]),
  ];
  for (const image of [
    "psbt-interop-lab/core:31.1",
    "psbt-interop-lab/rust-bitcoin:0.1.0",
    "psbt-interop-lab/btcsuite-go:1.2.0",
    "psbt-interop-lab/bitcoinjs-lib:7.0.1",
    "psbt-interop-lab/bdkpython:2.3.1",
  ]) {
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

async function prepareRuntime(options: RunOptions): Promise<void> {
  if (options.build) {
    process.stderr.write("Building pinned Core and adapter images...\n");
    await runCommand(
      "docker",
      [
        "compose",
        "build",
        "core",
        "rust-adapter",
        "go-adapter",
        "bitcoinjs-adapter",
        "bdk-adapter",
      ],
      {
        cwd: PROJECT_DIRECTORY,
        timeoutMs: 10 * 60_000,
        maxOutputBytes: 8 * 1024 * 1024,
      },
    );
  }
  if (options.startCore) {
    process.stderr.write("Starting isolated Bitcoin Core regtest...\n");
    await runCommand("docker", ["compose", "up", "-d", "--wait", "core"], {
      cwd: PROJECT_DIRECTORY,
      timeoutMs: 2 * 60_000,
      maxOutputBytes: 2 * 1024 * 1024,
    });
  }
}

export function createProgram(): Command {
  const program = new Command()
    .name("psbt-lab")
    .description("Deterministic PSBT interoperability proof for Bitcoin software")
    .version(VERSION)
    .showHelpAfterError();

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
    .command("run")
    .description("Run an interoperability suite and write replayable artifacts")
    .option("--suite <name>", "Suite to run", "proof")
    .option(
      "--artifacts <directory>",
      "Artifact root directory",
      resolve(PROJECT_DIRECTORY, "artifacts"),
    )
    .option("--rpc-url <url>", "Loopback Bitcoin Core RPC URL", DEFAULT_RPC_URL)
    .option("--no-build", "Use existing Docker images without rebuilding")
    .option("--no-start-core", "Use an already-running Core instance")
    .action(async (options: RunOptions) => {
      if (options.suite !== "proof") {
        throw new Error(`Unknown suite ${options.suite}; the available suite is proof`);
      }
      await prepareRuntime(options);
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
      });
      process.stdout.write(`${formatProofSummary(result)}\n`);
      if (result.manifest.outcome !== "passed") {
        process.exitCode = 1;
      }
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

  return program;
}

export async function main(argv = process.argv): Promise<void> {
  await createProgram().parseAsync(argv);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Unknown failure";
    process.stderr.write(`psbt-lab: ${message}\n`);
    process.exitCode = 1;
  });
}
