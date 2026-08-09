import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function required(value, input) {
  if (!value?.trim()) throw new TypeError(`${input} is required`);
  return value.trim();
}

function booleanInput(value, input, fallback) {
  const normalized = (value ?? fallback).trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new TypeError(`${input} must be true or false`);
}

export function actionConfiguration(environment = process.env) {
  const workspace = resolve(environment.GITHUB_WORKSPACE ?? process.cwd());
  const pathInput = (name, fallback) => resolve(workspace, environment[name] ?? fallback);
  return {
    workspace,
    adapterManifest: pathInput(
      "PSBT_LAB_ADAPTER_MANIFEST",
      required(environment.PSBT_LAB_ADAPTER_MANIFEST, "adapter-manifest"),
    ),
    artifacts: pathInput("PSBT_LAB_ARTIFACTS", "psbt-interop-artifacts"),
    packageSpec: required(
      environment.PSBT_LAB_PACKAGE_SPEC ?? "psbt-interop-lab@0.10.0",
      "package-spec",
    ),
    junit: pathInput("PSBT_LAB_JUNIT", "psbt-interop-junit.xml"),
    sarif: pathInput("PSBT_LAB_SARIF", "psbt-interop.sarif"),
    build: booleanInput(environment.PSBT_LAB_BUILD, "build", "true"),
  };
}

export function buildMatrixArguments(configuration) {
  return [
    "matrix",
    "--external-only",
    "--adapter-manifest",
    configuration.adapterManifest,
    "--artifacts",
    configuration.artifacts,
    "--junit",
    configuration.junit,
    "--sarif",
    configuration.sarif,
    ...(configuration.build ? [] : ["--no-build"]),
  ];
}

async function run(command, args, options) {
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdio: "inherit",
    shell: false,
  });
  const code = await new Promise((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", (status, signal) => {
      if (signal) reject(new Error(`${command} terminated by ${signal}`));
      else resolveExit(status ?? 1);
    });
  });
  if (code !== 0) throw new Error(`${command} exited with status ${code}`);
}

export async function runAction(environment = process.env) {
  const configuration = actionConfiguration(environment);
  const installRoot = await mkdtemp(
    resolve(environment.RUNNER_TEMP ?? tmpdir(), "psbt-interop-action-"),
  );
  try {
    await run(
      "npm",
      [
        "install",
        "--prefix",
        installRoot,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        configuration.packageSpec,
      ],
      { cwd: configuration.workspace },
    );
    const binDirectory = resolve(installRoot, "node_modules", ".bin");
    const executable = resolve(
      binDirectory,
      process.platform === "win32" ? "psbt-lab.cmd" : "psbt-lab",
    );
    const env = {
      ...environment,
      PATH: `${binDirectory}${delimiter}${environment.PATH ?? ""}`,
    };
    await run(executable, ["adapter", "check", configuration.adapterManifest], {
      cwd: configuration.workspace,
      env,
    });
    await run(executable, buildMatrixArguments(configuration), {
      cwd: configuration.workspace,
      env,
    });
  } finally {
    await rm(installRoot, { recursive: true, force: true });
  }
}

const directExecution =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (directExecution) {
  runAction().catch((error) => {
    process.stderr.write(
      `psbt-interop-action: ${error instanceof Error ? error.message : "unknown failure"}\n`,
    );
    process.exitCode = 1;
  });
}
