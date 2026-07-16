import { describe, expect, test, vi } from "vitest";
import type { PreparedFixtures, PsbtFixture } from "../../src/core/fixtures.js";
import type { AdapterRequest, AdapterResponse } from "../../src/protocol/types.js";
import type { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import {
  BDK_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  type ExpectedAdapterContract,
  GO_ADAPTER_CONTRACT,
  RUST_ADAPTER_CONTRACT,
} from "../../src/scenarios/contracts.js";
import type { ScenarioDefinition } from "../../src/scenarios/definition.js";
import {
  classifyHappyPath,
  classifyRegression,
  createProofCatalog,
  dockerAdapterProcessOptions,
  PROOF_SCENARIOS,
  type ProofDependencies,
  type ProofRuntimeAdapter,
  type ProofRuntimeArtifacts,
  runProofWithDependencies,
  serializeFixtureCommitments,
} from "../../src/scenarios/proof.js";

const expectedBdkFailure: AdapterResponse = {
  protocol: "psbt-lab.adapter/0.2",
  id: "reg-bdk",
  status: "rejected",
  implementation: {
    name: "bdkpython",
    version: "2.3.1",
    artifactDigest: `sha256:${"a".repeat(64)}`,
    sourceRevision: "bdk-ffi-v2.3.1",
  },
  error: {
    class: "finalize.missing_witness_script",
    message: "Expected historical failure",
  },
};

describe("proof scenario classification", () => {
  test("passes a complete policy-accepted happy path", () => {
    expect(classifyHappyPath(true, { allowed: true, txid: "abc" })).toMatchObject({
      policyAccepted: true,
      transactionId: "abc",
      summary: expect.stringMatching(/signed.*accepted/i),
    });
  });

  test("fails a happy path rejected by Core policy", () => {
    expect(
      classifyHappyPath(true, {
        allowed: false,
        rejectReason: "mandatory-script-verify-flag-failed",
      }),
    ).toMatchObject({
      policyAccepted: false,
      summary: expect.stringContaining("mandatory-script-verify-flag-failed"),
    });
  });

  test("passes when BDK reproduces issue 488 and Core accepts the same PSBT", () => {
    expect(
      classifyRegression(expectedBdkFailure, true, { allowed: true, txid: "def" }),
    ).toMatchObject({
      expectedFailure: {
        implementation: "bdkpython@2.3.1",
        errorClass: "finalize.missing_witness_script",
      },
      policyAccepted: true,
    });
  });

  test("fails when the historical BDK rejection is not reproduced", () => {
    const unexpectedSuccess: AdapterResponse = {
      ...expectedBdkFailure,
      status: "ok",
      output: {},
    };
    delete (unexpectedSuccess as Partial<AdapterResponse> & { error?: unknown }).error;

    expect(
      classifyRegression(unexpectedSuccess, true, { allowed: true, txid: "def" }),
    ).toMatchObject({
      summary: expect.stringMatching(/did not all match/i),
    });
  });

  test("serializes only bounded fixture ids and unsigned transaction commitments", () => {
    expect(
      serializeFixtureCommitments([
        { id: "happy-path", unsignedTxSha256: `sha256:${"b".repeat(64)}` },
        {
          id: "bdk-finalize-regression",
          unsignedTxSha256: `sha256:${"c".repeat(64)}`,
        },
      ]),
    ).toBe(
      JSON.stringify({
        "happy-path": `sha256:${"b".repeat(64)}`,
        "bdk-finalize-regression": `sha256:${"c".repeat(64)}`,
      }),
    );

    expect(() =>
      serializeFixtureCommitments([
        { id: "../unsafe", unsignedTxSha256: `sha256:${"b".repeat(64)}` },
      ]),
    ).toThrow(/fixture id/i);
  });
});

function fixture(id: PsbtFixture["id"]): PsbtFixture {
  const commitmentByte = id === "happy-path" ? "c" : "d";
  const scriptTypes =
    id === "p2wpkh" || id === "intent-rich-p2wpkh"
      ? (["p2wpkh"] as const)
      : id === "p2tr-keypath"
        ? (["p2tr-keypath"] as const)
        : id === "mixed-p2wpkh-p2tr"
          ? (["p2wpkh", "p2tr-keypath"] as const)
          : (["p2wsh"] as const);
  return {
    id,
    initialPsbt:
      "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=",
    outpoints: [],
    inputCount: id === "bdk-finalize-regression" ? 2 : 1,
    outputCount: id === "intent-rich-p2wpkh" ? 2 : 1,
    feeSats: 1_000,
    scriptTypes,
    inputDescriptors: ["wsh(pk(...))#fixture"],
    outputDescriptor: "wsh(pk(...))#fixture",
    psbtVersion: 0,
    transactionId: "a".repeat(64),
    psbtSha256: "b".repeat(64),
    unsignedTxSha256: `sha256:${commitmentByte.repeat(64)}`,
  };
}

function preparedFixtures(): PreparedFixtures {
  return {
    descriptor: "wsh(pk(...))#fixture",
    address: "bcrt1qfixture",
    core: { version: 310100, subversion: "/Satoshi:31.1.0/", blocks: 109, connections: 0 },
    happy: fixture("happy-path"),
    regression: fixture("bdk-finalize-regression"),
    profiles: {
      p2wpkh: fixture("p2wpkh"),
      "p2wsh-single-key": fixture("p2wsh-single-key"),
      "p2wsh-2-of-3": fixture("p2wsh-2-of-3"),
      "p2tr-keypath": fixture("p2tr-keypath"),
      "mixed-p2wpkh-p2tr": fixture("mixed-p2wpkh-p2tr"),
      "intent-rich-p2wpkh": fixture("intent-rich-p2wpkh"),
    },
  } as PreparedFixtures;
}

function runtimeAdapter(contract: ExpectedAdapterContract): ProofRuntimeAdapter & {
  close: ReturnType<typeof vi.fn>;
} {
  const close = vi.fn(async () => undefined);
  return {
    close,
    request: vi.fn(
      async (request: AdapterRequest): Promise<AdapterResponse> => ({
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "ok",
        implementation: {
          name: contract.name,
          version: contract.version,
          artifactDigest: `sha256:${"e".repeat(64)}`,
          sourceRevision: contract.sourceRevision,
        },
        output: {
          operations: [...contract.operations],
          roles: [...contract.roles],
          psbtVersions: [...contract.psbtVersions],
          scriptTypes: [...contract.scriptTypes],
          operationScriptTypes: Object.fromEntries(
            Object.entries(contract.operationScriptTypes).map(([operation, scriptTypes]) => [
              operation,
              [...scriptTypes],
            ]),
          ),
          features: [...(contract.features ?? [])],
        },
      }),
    ),
  };
}

function proofHarness(failScenario = false): {
  dependencies: ProofDependencies;
  adapters: ProofRuntimeAdapter[];
  artifacts: ProofRuntimeArtifacts;
  created: Array<{ image: string; options: { env?: Readonly<Record<string, string>> } }>;
} {
  const artifacts: ProofRuntimeArtifacts = {
    directory: "/tmp/psbt-lab-test/run",
    checkpoint: vi.fn(),
    writeManifest: vi.fn(),
    writeReportJson: vi.fn(),
    writeReportMarkdown: vi.fn(),
    writeReportHtml: vi.fn(),
  };
  const adapters: ProofRuntimeAdapter[] = [];
  const created: Array<{ image: string; options: { env?: Readonly<Record<string, string>> } }> = [];
  const contracts = [
    RUST_ADAPTER_CONTRACT,
    GO_ADAPTER_CONTRACT,
    BITCOINJS_ADAPTER_CONTRACT,
    BDK_ADAPTER_CONTRACT,
  ];
  let adapterIndex = 0;
  const scenario: ScenarioDefinition<ScenarioExecutionContext> = {
    id: "runtime-lifecycle",
    title: "Runtime lifecycle",
    category: "test",
    summary: "Runtime test",
    requirements: [],
    async run() {
      if (failScenario) throw new Error("Core unavailable");
      return {
        summary: "Runtime passed",
        assertions: [{ name: "runtime-completed", passed: true }],
      };
    },
  };
  return {
    adapters,
    artifacts,
    created,
    dependencies: {
      createArtifacts: vi.fn(async () => artifacts),
      prepareFixtures: vi.fn(async () => preparedFixtures()),
      createAdapter: vi.fn((image, _projectDirectory, options = {}) => {
        created.push({ image, options });
        const value = runtimeAdapter(contracts[adapterIndex] as ExpectedAdapterContract);
        adapterIndex += 1;
        adapters.push(value);
        return value;
      }),
      createCatalog: vi.fn(() => [scenario]),
    },
  };
}

describe("proof runtime", () => {
  test("publishes every pre-application coverage scenario", () => {
    expect(PROOF_SCENARIOS.map(({ id }) => id)).toEqual([
      "happy-path",
      "p2wsh-sign-btcsuite-go",
      "p2wsh-sign-bitcoinjs-lib",
      "p2wpkh-sign-rust-bitcoin",
      "p2wpkh-sign-btcsuite-go",
      "p2wpkh-sign-bitcoinjs-lib",
      "p2tr-keypath-sign-rust-bitcoin",
      "p2tr-keypath-sign-btcsuite-go",
      "p2tr-keypath-sign-bitcoinjs-lib",
      "same-input-2-of-3-multisig",
      "four-library-roundtrip-chain",
      "parallel-sign-and-combine",
      "transaction-intent-preservation",
      "invalid-and-unsupported-inputs",
      "proprietary-metadata-preservation",
      "bdk-finalize-regression",
      "bdk-regression-btcsuite-go",
      "bdk-regression-bitcoinjs-lib",
    ]);
  });

  test("keeps the public scenario listing synchronized with the executable catalog", () => {
    expect(
      createProofCatalog(preparedFixtures()).map(({ id, title, category }) => ({
        id,
        title,
        category,
      })),
    ).toEqual(PROOF_SCENARIOS);
  });

  test("passes commitments through environment values without placing them in Docker arguments", () => {
    const commitment = JSON.stringify({ "happy-path": `sha256:${"a".repeat(64)}` });
    const options = dockerAdapterProcessOptions("adapter:image", "/project", {
      env: { PSBT_LAB_FIXTURE_COMMITMENTS: commitment },
    });

    expect(options.args).toEqual(
      expect.arrayContaining([
        "--network",
        "none",
        "--read-only",
        "--env",
        "PSBT_LAB_FIXTURE_COMMITMENTS",
      ]),
    );
    expect(options.args).not.toContain(commitment);
    expect(options.env).toEqual({ PSBT_LAB_FIXTURE_COMMITMENTS: commitment });
  });

  test("closes every adapter exactly once after a successful run", async () => {
    const harness = proofHarness();
    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
      },
      harness.dependencies,
    );

    expect(result.manifest.outcome).toBe("passed");
    expect(harness.adapters).toHaveLength(4);
    for (const adapter of harness.adapters) expect(adapter.close).toHaveBeenCalledTimes(1);
    const commonCommitments = JSON.stringify({
      "happy-path": `sha256:${"c".repeat(64)}`,
      "bdk-finalize-regression": `sha256:${"d".repeat(64)}`,
      p2wpkh: `sha256:${"d".repeat(64)}`,
      "p2wsh-2-of-3": `sha256:${"d".repeat(64)}`,
      "p2tr-keypath": `sha256:${"d".repeat(64)}`,
    });
    const rustCommitments = JSON.stringify({
      "happy-path": `sha256:${"c".repeat(64)}`,
      "bdk-finalize-regression": `sha256:${"d".repeat(64)}`,
      p2wpkh: `sha256:${"d".repeat(64)}`,
      "p2wsh-2-of-3": `sha256:${"d".repeat(64)}`,
      "p2tr-keypath": `sha256:${"d".repeat(64)}`,
      "intent-rich-p2wpkh": `sha256:${"d".repeat(64)}`,
    });
    expect(harness.created).toEqual([
      {
        image: "psbt-interop-lab/rust-bitcoin:0.1.0",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: rustCommitments } },
      },
      {
        image: "psbt-interop-lab/btcsuite-go:1.2.0",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: commonCommitments } },
      },
      {
        image: "psbt-interop-lab/bitcoinjs-lib:7.0.1",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: commonCommitments } },
      },
      {
        image: "psbt-interop-lab/bdkpython:2.3.1",
        options: { platform: "linux/amd64" },
      },
    ]);
    expect(rustCommitments).not.toContain("cHNidP8");
    expect(commonCommitments).not.toContain("cHNidP8");
  });

  test("closes every adapter exactly once after an infrastructure failure", async () => {
    const harness = proofHarness(true);

    await expect(
      runProofWithDependencies(
        {
          rpc: {} as never,
          artifactRoot: "/tmp/psbt-lab-test",
          projectDirectory: "/project",
        },
        harness.dependencies,
      ),
    ).rejects.toThrow(/Core unavailable/);
    for (const adapter of harness.adapters) expect(adapter.close).toHaveBeenCalledTimes(1);
  });
});
