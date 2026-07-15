import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { prepareFixtures } from "../core/fixtures.js";
import type { CoreRpc } from "../core/rpc.js";
import { AdapterProcess } from "../protocol/adapter-process.js";
import {
  ADAPTER_PROTOCOL,
  type AdapterOperation,
  type AdapterRequest,
  type AdapterResponse,
  type JsonValue,
} from "../protocol/types.js";
import { ArtifactRun, type RunManifest, type ScenarioRecord } from "../runner/artifacts.js";
import { generateMarkdownReport, redactValue } from "../runner/report.js";

const RUST_IMAGE = "psbt-interop-lab/rust-bitcoin:0.1.0";
const BDK_IMAGE = "psbt-interop-lab/bdkpython:2.3.1";

export interface PolicyResult {
  allowed: boolean;
  txid?: string;
  rejectReason?: string;
}

interface FinalizeResult {
  complete: boolean;
  hex?: string;
}

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

function runIdentifier(date = new Date()): string {
  const timestamp = date
    .toISOString()
    .replace(/[^0-9]/g, "")
    .slice(0, 14);
  return `${timestamp}-${randomBytes(4).toString("hex")}`;
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid object`);
  }
  return value as Record<string, unknown>;
}

function parseFinalizeResult(value: unknown): FinalizeResult {
  const object = asObject(value, "finalizepsbt");
  if (typeof object["complete"] !== "boolean") {
    throw new Error("finalizepsbt omitted its completion status");
  }
  if (object["hex"] !== undefined && typeof object["hex"] !== "string") {
    throw new Error("finalizepsbt returned invalid transaction hex");
  }
  const result: FinalizeResult = { complete: object["complete"] };
  if (typeof object["hex"] === "string") {
    result.hex = object["hex"];
  }
  return result;
}

function parsePolicyResult(value: unknown): PolicyResult {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error("testmempoolaccept returned an unexpected result count");
  }
  const object = asObject(value[0], "testmempoolaccept");
  if (typeof object["allowed"] !== "boolean") {
    throw new Error("testmempoolaccept omitted its policy decision");
  }
  const result: PolicyResult = { allowed: object["allowed"] };
  if (typeof object["txid"] === "string") {
    result.txid = object["txid"];
  }
  if (typeof object["reject-reason"] === "string") {
    result.rejectReason = object["reject-reason"];
  }
  return result;
}

export function classifyHappyPath(complete: boolean, policy: PolicyResult): ScenarioRecord {
  const passed = complete && policy.allowed;
  return {
    id: "happy-path",
    outcome: passed ? "passed" : "failed",
    summary: passed
      ? "rust-bitcoin signed the Core-created PSBT; Bitcoin Core finalized it and accepted the transaction under current regtest mempool policy."
      : `The happy path did not produce a complete policy-accepted transaction${policy.rejectReason ? ` (${policy.rejectReason})` : ""}.`,
    policyAccepted: policy.allowed,
    ...(policy.txid ? { transactionId: policy.txid } : {}),
  };
}

export function classifyRegression(
  bdkResponse: AdapterResponse,
  coreComplete: boolean,
  policy: PolicyResult,
): ScenarioRecord {
  const reproduced =
    bdkResponse.status === "rejected" &&
    bdkResponse.implementation.name === "bdkpython" &&
    bdkResponse.implementation.version === "2.3.1" &&
    bdkResponse.error.class === "finalize.missing_witness_script";
  const passed = reproduced && coreComplete && policy.allowed;
  return {
    id: "bdk-finalize-regression",
    outcome: passed ? "passed" : "failed",
    summary: passed
      ? "BDK Python 2.3.1 reproduced issue #488 on an already-finalized first input, while Bitcoin Core finalized the same PSBT and accepted the extracted transaction under mempool policy."
      : "The historical BDK failure, Core finalization, and policy acceptance did not all match the expected regression behavior.",
    ...(reproduced
      ? {
          expectedFailure: {
            implementation: `${bdkResponse.implementation.name}@${bdkResponse.implementation.version}`,
            errorClass: bdkResponse.error.class,
          },
        }
      : {}),
    policyAccepted: policy.allowed,
    ...(policy.txid ? { transactionId: policy.txid } : {}),
  };
}

function createDockerAdapter(
  image: string,
  projectDirectory: string,
  platform?: string,
): AdapterProcess {
  const args = [
    "run",
    "--rm",
    "-i",
    "--pull",
    "never",
    ...(platform ? ["--platform", platform] : []),
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
    image,
  ];
  return new AdapterProcess({
    command: "docker",
    args,
    cwd: projectDirectory,
    maxLineBytes: 4 * 1024 * 1024,
    maxStderrBytes: 64 * 1024,
  });
}

function requireSuccess(
  response: AdapterResponse,
  operation: string,
): AdapterResponse & {
  status: "ok";
} {
  if (response.status !== "ok") {
    throw new Error(
      `${response.implementation.name} ${operation} failed: ${response.error.class}: ${response.error.message}`,
    );
  }
  return response;
}

function outputString(response: AdapterResponse, key: string): string {
  const success = requireSuccess(response, key);
  const value = success.output[key];
  if (typeof value !== "string") {
    throw new Error(`${success.implementation.name} omitted string output ${key}`);
  }
  return value;
}

function outputBoolean(response: AdapterResponse, key: string): boolean {
  const success = requireSuccess(response, key);
  const value = success.output[key];
  if (typeof value !== "boolean") {
    throw new Error(`${success.implementation.name} omitted boolean output ${key}`);
  }
  return value;
}

async function policyCheck(rpc: CoreRpc, finalized: FinalizeResult): Promise<PolicyResult> {
  if (!finalized.complete || !finalized.hex) {
    return { allowed: false, rejectReason: "PSBT was not complete" };
  }
  return parsePolicyResult(await rpc.call("testmempoolaccept", { rawtxs: [finalized.hex] }));
}

export async function runProof(options: ProofOptions): Promise<ProofResult> {
  const startedAt = new Date().toISOString();
  const runId = runIdentifier();
  const artifacts = await ArtifactRun.create(resolve(options.artifactRoot), runId);
  const fixtures = await prepareFixtures(options.rpc);
  const timeoutMs = options.adapterTimeoutMs ?? 60_000;
  const rust = createDockerAdapter(RUST_IMAGE, resolve(options.projectDirectory));
  const bdk = createDockerAdapter(BDK_IMAGE, resolve(options.projectDirectory), "linux/amd64");
  const checkpoints = [];
  let requestCounter = 0;
  const request = async (
    adapter: AdapterProcess,
    operation: AdapterOperation,
    payload: Record<string, JsonValue>,
  ): Promise<AdapterResponse> => {
    requestCounter += 1;
    const message: AdapterRequest = {
      protocol: ADAPTER_PROTOCOL,
      id: `request-${requestCounter}`,
      operation,
      payload,
    };
    return adapter.request(message, timeoutMs);
  };

  try {
    const rustHello = requireSuccess(await request(rust, "hello", {}), "hello");
    const bdkHello = requireSuccess(await request(bdk, "hello", {}), "hello");

    checkpoints.push(
      await artifacts.checkpoint("happy-path", "core-created", fixtures.happy.initialPsbt),
    );
    const happyRoundtrip = await request(rust, "roundtrip", {
      psbt: fixtures.happy.initialPsbt,
    });
    if (!outputBoolean(happyRoundtrip, "byteIdentical")) {
      throw new Error("rust-bitcoin changed the Core-created PSBT during roundtrip");
    }
    const signedHappy = await request(rust, "sign", {
      psbt: outputString(happyRoundtrip, "psbt"),
      network: "regtest",
      fixtureId: "happy-path",
    });
    const happySignedPsbt = outputString(signedHappy, "psbt");
    checkpoints.push(await artifacts.checkpoint("happy-path", "rust-signed", happySignedPsbt));
    const happyFinalized = parseFinalizeResult(
      await options.rpc.call("finalizepsbt", {
        psbt: happySignedPsbt,
        extract: true,
      }),
    );
    const happyPolicy = await policyCheck(options.rpc, happyFinalized);
    const happyScenario = classifyHappyPath(happyFinalized.complete, happyPolicy);

    checkpoints.push(
      await artifacts.checkpoint(
        "bdk-finalize-regression",
        "core-created",
        fixtures.regression.initialPsbt,
      ),
    );
    const bdkRoundtrip = await request(bdk, "roundtrip", {
      psbt: fixtures.regression.initialPsbt,
    });
    if (!outputBoolean(bdkRoundtrip, "byteIdentical")) {
      throw new Error("BDK Python changed the Core-created PSBT during roundtrip");
    }
    const signedRegression = await request(rust, "sign", {
      psbt: outputString(bdkRoundtrip, "psbt"),
      network: "regtest",
      fixtureId: "bdk-finalize-regression",
    });
    const regressionSignedPsbt = outputString(signedRegression, "psbt");
    checkpoints.push(
      await artifacts.checkpoint("bdk-finalize-regression", "rust-signed", regressionSignedPsbt),
    );
    const mixedResponse = await request(rust, "fixture-finalize-input", {
      psbt: regressionSignedPsbt,
      network: "regtest",
      fixtureId: "bdk-finalize-regression",
    });
    const mixedPsbt = outputString(mixedResponse, "psbt");
    checkpoints.push(
      await artifacts.checkpoint("bdk-finalize-regression", "input-0-finalized", mixedPsbt),
    );
    const bdkFinalize = await request(bdk, "finalize", {
      psbt: mixedPsbt,
      network: "regtest",
      fixtureId: "bdk-finalize-regression",
    });
    const regressionFinalized = parseFinalizeResult(
      await options.rpc.call("finalizepsbt", { psbt: mixedPsbt, extract: true }),
    );
    const regressionPolicy = await policyCheck(options.rpc, regressionFinalized);
    const regressionScenario = classifyRegression(
      bdkFinalize,
      regressionFinalized.complete,
      regressionPolicy,
    );

    const scenarios = [happyScenario, regressionScenario];
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
      adapters: [rustHello.implementation, bdkHello.implementation],
      scenarios,
      checkpoints,
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
    await Promise.all([rust.close(), bdk.close()]);
  }
}
