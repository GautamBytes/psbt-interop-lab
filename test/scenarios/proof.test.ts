import { describe, expect, test, vi } from "vitest";
import { parseAdapterManifest } from "../../src/conformance/manifest.js";
import type { PreparedFixtures, PsbtFixture } from "../../src/core/fixtures.js";
import { parseCustomSuiteManifest } from "../../src/custom/manifest.js";
import type { AdapterProcessOptions } from "../../src/protocol/adapter-process.js";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { BIP370_VALID_VECTORS } from "../../src/psbt/bip370-vectors.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import {
  BDK_ADAPTER_CONTRACT,
  BDK_CURRENT_ADAPTER_CONTRACT,
  BITCOINJS_ADAPTER_CONTRACT,
  type ExpectedAdapterContract,
  GO_ADAPTER_CONTRACT,
  LIBWALLY_ADAPTER_CONTRACT,
  PSBTV2_ADAPTER_CONTRACT,
  RUST_ADAPTER_CONTRACT,
} from "../../src/scenarios/contracts.js";
import type { ScenarioDefinition } from "../../src/scenarios/definition.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";
import {
  assertProofSelectionCompatibility,
  classifyHappyPath,
  classifyRegression,
  createProofCatalog,
  dockerAdapterProcessOptions,
  PROOF_SCENARIO_REGISTRATIONS,
  PROOF_SCENARIOS,
  type ProofDependencies,
  type ProofRuntimeAdapter,
  type ProofRuntimeArtifacts,
  resolveProofSelection,
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
      : id === "p2sh-p2wpkh"
        ? (["p2sh-p2wpkh"] as const)
        : id === "p2tr-keypath"
          ? (["p2tr-keypath"] as const)
          : id === "p2tr-scriptpath"
            ? (["p2tr-scriptpath"] as const)
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
      "p2sh-p2wpkh": fixture("p2sh-p2wpkh"),
      "p2wsh-single-key": fixture("p2wsh-single-key"),
      "p2wsh-2-of-3": fixture("p2wsh-2-of-3"),
      "p2tr-keypath": fixture("p2tr-keypath"),
      "p2tr-scriptpath": fixture("p2tr-scriptpath"),
      "mixed-p2wpkh-p2tr": fixture("mixed-p2wpkh-p2tr"),
      "intent-rich-p2wpkh": fixture("intent-rich-p2wpkh"),
    },
    custom: {},
  } as PreparedFixtures;
}

function runtimeAdapter(contract: ExpectedAdapterContract): ProofRuntimeAdapter & {
  close: ReturnType<typeof vi.fn>;
} {
  const close = vi.fn(async () => undefined);
  return {
    close,
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      const implementation = {
        name: contract.name,
        version: contract.version,
        artifactDigest: `sha256:${"e".repeat(64)}` as const,
        sourceRevision: contract.sourceRevision,
      };
      return request.operation === "hello"
        ? {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "ok",
            implementation,
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
          }
        : {
            protocol: "psbt-lab.adapter/0.2",
            id: request.id,
            status: "ok",
            implementation,
            output: { psbt: request.payload["psbt"] ?? null },
          };
    }),
  };
}

function proofHarness(
  failScenario = false,
  failHelloImage?: string,
): {
  dependencies: ProofDependencies;
  adapters: ProofRuntimeAdapter[];
  artifacts: ProofRuntimeArtifacts;
  created: Array<{ image: string; options: { env?: Readonly<Record<string, string>> } }>;
} {
  const artifacts: ProofRuntimeArtifacts = {
    directory: "/tmp/psbt-lab-test/run",
    checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
      scenario,
      stage,
      psbtPath: `${scenario}/${stage}.psbt`,
      factsPath: `${scenario}/${stage}.json`,
      facts: extractWireFacts(psbt),
    })),
    writeManifest: vi.fn(),
    writeReportJson: vi.fn(),
    writeReportMarkdown: vi.fn(),
    writeReportHtml: vi.fn(),
  };
  const adapters: ProofRuntimeAdapter[] = [];
  const created: Array<{ image: string; options: { env?: Readonly<Record<string, string>> } }> = [];
  const contracts = new Map<string, ExpectedAdapterContract>([
    ["psbt-interop-lab/rust-bitcoin:0.1.0", RUST_ADAPTER_CONTRACT],
    ["psbt-interop-lab/btcsuite-go:1.2.0", GO_ADAPTER_CONTRACT],
    ["psbt-interop-lab/bitcoinjs-lib:7.0.1", BITCOINJS_ADAPTER_CONTRACT],
    ["psbt-interop-lab/bdkpython:2.3.1", BDK_ADAPTER_CONTRACT],
    ["psbt-interop-lab/bdk-wallet-current:3.1.0", BDK_CURRENT_ADAPTER_CONTRACT],
    ["psbt-interop-lab/rust-psbt-v2:0.1.0", PSBTV2_ADAPTER_CONTRACT],
    ["psbt-interop-lab/libwally:1.5.4", LIBWALLY_ADAPTER_CONTRACT],
  ]);
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
        const contract = contracts.get(image);
        if (!contract) throw new Error(`Unexpected test adapter image ${image}`);
        const value = runtimeAdapter(contract);
        if (image === failHelloImage) {
          value.request = vi.fn(async () => {
            throw new Error("adapter exited during hello");
          });
        }
        adapters.push(value);
        return value;
      }),
      createCatalog: vi.fn(() => [scenario]),
    },
  };
}

describe("proof runtime", () => {
  test("resolves an external-only matrix without bundled adapter resources", () => {
    const selection = resolveProofSelection({ externalOnly: true });

    expect(selection).toEqual({
      scenarioIds: [],
      resources: {
        core: true,
        fixtures: ["happy-path", "p2wpkh", "p2sh-p2wpkh", "p2tr-keypath", "p2tr-scriptpath"],
        adapters: [],
      },
      filtered: true,
      externalOnly: true,
    });
    expect(() =>
      assertProofSelectionCompatibility(selection, { adapter: true, suite: false }),
    ).not.toThrow();
    expect(() =>
      assertProofSelectionCompatibility(selection, { adapter: false, suite: false }),
    ).toThrow(/external-only.*adapter manifest/i);
  });

  test.each(["valid-08", "valid-13"])(
    "does not allowlist libwally rejection of BIP370 %s",
    async (rejectedVectorId) => {
      const registration = PROOF_SCENARIO_REGISTRATIONS.find(
        ({ id }) => id === "bip370-official-vectors-libwally",
      );
      expect(registration).toBeDefined();
      if (!registration) return;

      const validIds = new Map<string, string>(
        BIP370_VALID_VECTORS.map((vector) => [vector.base64, vector.id]),
      );
      const implementation = {
        name: "libwally-core",
        version: "1.5.4",
        sourceRevision: "libwally-core-release_1.5.4",
        artifactDigest: `sha256:${"a".repeat(64)}`,
      };
      const adapter = {
        request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
          const encoded = request.payload["psbt"];
          const validId = typeof encoded === "string" ? validIds.get(encoded) : undefined;
          if (request.operation === "native-parse" && validId === rejectedVectorId) {
            return {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status: "rejected",
              implementation,
              error: {
                class: "psbt.native_parse_failed",
                message: "Native parser rejected the vector",
              },
            };
          }
          try {
            if (typeof encoded !== "string") throw new Error("missing psbt");
            parsePsbtDocument(encoded);
            return {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status: "ok",
              implementation,
              output:
                request.operation === "roundtrip"
                  ? { psbt: encoded, byteIdentical: true }
                  : { nativeParser: implementation.name },
            };
          } catch {
            return {
              protocol: "psbt-lab.adapter/0.2",
              id: request.id,
              status: "rejected",
              implementation,
              error: {
                class: "psbt.native_parse_failed",
                message: "Native parser rejected the vector",
              },
            };
          }
        }),
      };
      const context = new ScenarioExecutionContext({
        rpc: { call: vi.fn() } as never,
        artifacts: {
          checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => ({
            scenario,
            stage,
            psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
            factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
            facts: extractWireFacts(psbt),
          })),
        },
        adapters: new Map([["libwally", adapter]]),
        adapterTimeoutMs: 1_000,
      });
      const negotiated: NegotiatedAdapter = {
        registryId: "libwally",
        implementation,
        capabilities: {
          operations: ["hello", "native-parse", "roundtrip"],
          roles: ["parser"],
          psbtVersions: [2],
          scriptTypes: [],
        },
      };

      const [result] = await runScenarioCatalog(
        [registration.create(undefined)],
        context,
        new Map([["libwally", negotiated]]),
      );

      expect(result).toMatchObject({ outcome: "failed" });
      expect(result?.assertions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "bip370-valid-vectors", passed: false }),
        ]),
      );
      expect(result?.findings).toBeUndefined();
    },
  );

  test("publishes static resource metadata and resolves selectors without runtime state", async () => {
    const proofModule = (await import("../../src/scenarios/proof.js")) as unknown as {
      PROOF_SCENARIO_REGISTRATIONS?: ReadonlyArray<{
        id: string;
        resources: { core: boolean; fixtures: readonly string[]; adapters: readonly string[] };
      }>;
      resolveProofSelection?: (selectors: { scenarios?: readonly string[]; category?: string }) => {
        scenarioIds: readonly string[];
        resources: { core: boolean; fixtures: readonly string[]; adapters: readonly string[] };
      };
    };

    expect(proofModule.PROOF_SCENARIO_REGISTRATIONS).toBeDefined();
    expect(proofModule.resolveProofSelection).toBeDefined();
    if (!proofModule.PROOF_SCENARIO_REGISTRATIONS || !proofModule.resolveProofSelection) return;

    expect(
      proofModule.PROOF_SCENARIO_REGISTRATIONS.find(
        ({ id }) => id === "bip370-official-vectors-rust-psbt-v2",
      ),
    ).toMatchObject({
      resources: { core: false, fixtures: [], adapters: ["rust-psbt-v2"] },
    });
    expect(
      proofModule.PROOF_SCENARIO_REGISTRATIONS.find(
        ({ id }) => id === "taproot-scriptpath-rust-to-bdk",
      ),
    ).toMatchObject({
      resources: {
        core: true,
        fixtures: ["p2tr-scriptpath"],
        adapters: ["rust-bitcoin", "bdk-wallet-current"],
      },
    });
    expect(
      proofModule.PROOF_SCENARIO_REGISTRATIONS.find(
        ({ id }) => id === "psbtv2-p2wpkh-rust-to-libwally",
      ),
    ).toMatchObject({
      resources: {
        core: true,
        fixtures: ["p2wpkh"],
        adapters: ["rust-psbt-v2", "libwally"],
      },
    });
    expect(
      proofModule.resolveProofSelection({
        scenarios: ["happy-path", "happy-path", "p2wpkh-sign-rust-bitcoin"],
        category: "cross-library-signing",
      }),
    ).toMatchObject({
      scenarioIds: ["happy-path", "p2wpkh-sign-rust-bitcoin"],
      resources: {
        core: true,
        fixtures: ["happy-path", "p2wpkh"],
        adapters: ["rust-bitcoin"],
      },
    });
    expect(() => proofModule.resolveProofSelection?.({ category: "not-a-category" })).toThrow(
      /Unknown category.*cross-library-signing/i,
    );
  });

  test("runs a Core-free selected scenario with only its adapter and records selectors", async () => {
    const harness = proofHarness();
    const scenarioId = "bip370-official-vectors-rust-psbt-v2";
    const scenario: ScenarioDefinition<ScenarioExecutionContext> = {
      id: scenarioId,
      title: "Official BIP370 vectors through rust-psbt-v2",
      category: "psbtv2-conformance",
      summary: "Selected runtime test",
      requirements: [{ adapter: "rust-psbt-v2", operations: ["hello"] }],
      async run() {
        return { assertions: [{ name: "selected-runtime-completed", passed: true }] };
      },
    };
    harness.dependencies.createCatalog = vi.fn(
      (_fixtures, _external, selectedIds?: readonly string[]) => {
        expect(selectedIds).toEqual([scenarioId]);
        return [scenario];
      },
    ) as never;

    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
        selectors: { scenarios: [scenarioId] },
      } as never,
      harness.dependencies,
    );

    expect(harness.dependencies.prepareFixtures).not.toHaveBeenCalled();
    expect(harness.created).toEqual([
      { image: "psbt-interop-lab/rust-psbt-v2:0.1.0", options: {} },
    ]);
    expect(result.manifest).not.toHaveProperty("core");
    expect(result.manifest).toMatchObject({
      selectors: {
        requested: { scenarios: [scenarioId] },
        executed: { scenarios: [scenarioId], categories: ["psbtv2-conformance"] },
      },
    });
    expect(harness.adapters).toHaveLength(1);
    expect(harness.adapters[0]?.close).toHaveBeenCalledOnce();
  });

  test("rejects filtered runs that would silently omit manifest scenarios", async () => {
    const harness = proofHarness();
    const selected = { scenarios: ["happy-path"] };

    await expect(
      runProofWithDependencies(
        {
          rpc: {} as never,
          artifactRoot: "/tmp/psbt-lab-test",
          projectDirectory: "/project",
          selectors: selected,
          customSuite: { fixtures: [], scenarios: [] } as never,
        },
        harness.dependencies,
      ),
    ).rejects.toThrow(/scenario selection.*suite manifest/i);

    await expect(
      runProofWithDependencies(
        {
          rpc: {} as never,
          artifactRoot: "/tmp/psbt-lab-test",
          projectDirectory: "/project",
          selectors: selected,
          adapterManifest: { adapters: [] } as never,
        },
        harness.dependencies,
      ),
    ).rejects.toThrow(/scenario selection.*adapter manifest/i);
    expect(harness.dependencies.prepareFixtures).not.toHaveBeenCalled();
    expect(harness.created).toEqual([]);
  });

  test("compiles and runs deterministic fixtures and scenarios from a suite manifest", async () => {
    const harness = proofHarness();
    const prepared = preparedFixtures();
    const customFixture = {
      ...fixture("merchant-refund"),
      specSha256: `sha256:${"f".repeat(64)}` as const,
      transactionIntent: {
        version: 2,
        locktime: 42,
        sequences: [0xffff_fffc],
        outputCount: 1,
        outputs: [{ descriptor: "wpkh(...)#fixture", amountSats: 4_999_985_000 }],
      },
    };
    prepared.custom = { "merchant-refund": customFixture };
    const prepare = vi.fn(async () => prepared);
    harness.dependencies.prepareFixtures = prepare;
    const customSuite = parseCustomSuiteManifest({
      schema: "psbt-lab.suite/0.1",
      fixtures: [
        {
          id: "merchant-refund",
          inputs: [{ descriptor: "p2wpkh", sequence: 0xffff_fffc }],
          outputs: [{ descriptor: "p2wpkh", remainder: true }],
          feeSats: 15_000,
          locktime: 42,
          transactionVersion: 2,
        },
      ],
      scenarios: [
        {
          id: "merchant-refund-roundtrip",
          title: "Merchant refund roundtrip",
          fixture: "merchant-refund",
          steps: [
            {
              id: "rust-roundtrip",
              adapter: "rust-bitcoin",
              operation: "roundtrip",
              input: "fixture",
            },
          ],
        },
      ],
    });

    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
        customSuite,
      },
      harness.dependencies,
    );

    expect(prepare).toHaveBeenCalledWith(
      expect.anything(),
      expect.arrayContaining([expect.objectContaining({ id: "merchant-refund" })]),
    );
    expect(result.manifest.scenarios.map(({ id }) => id)).toContain("merchant-refund-roundtrip");
  });

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
      "p2wsh-sign-bdk-wallet-current",
      "p2wpkh-sign-bdk-wallet-current",
      "p2tr-keypath-sign-bdk-wallet-current",
      "nested-segwit-roundtrip-matrix",
      "taproot-scriptpath-roundtrip-matrix",
      "taproot-scriptpath-rust-to-bdk",
      "taproot-scriptpath-bdk-to-rust",
      "taproot-scriptpath-negative-canaries",
      "bip370-official-vectors-rust-psbt-v2",
      "bip370-official-vectors-libwally",
      "psbtv2-p2wpkh-rust-to-libwally",
      "psbtv2-p2wpkh-libwally-to-rust",
      "psbtv2-2-of-3-cross-library",
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

  test("appends external scenarios without changing the 18 built-in definitions", () => {
    const external: NegotiatedAdapter = {
      registryId: "wallet-alias",
      implementation: {
        name: "actual-wallet-library",
        version: "2.0.0",
        sourceRevision: "actual-wallet-v2.0.0",
        artifactDigest: `sha256:${"f".repeat(64)}`,
      },
      capabilities: {
        operations: ["hello", "native-parse", "roundtrip", "sign"],
        roles: ["parser", "signer"],
        psbtVersions: [0],
        scriptTypes: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
        operationScriptTypes: {
          roundtrip: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
          sign: ["p2wpkh", "p2sh-p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"],
        },
        features: ["fixture-commitment-sha256"],
      },
    };

    const catalog = createProofCatalog(preparedFixtures(), new Map([["wallet-alias", external]]));

    expect(
      catalog.slice(0, PROOF_SCENARIOS.length).map(({ id, title, category }) => ({
        id,
        title,
        category,
      })),
    ).toEqual(PROOF_SCENARIOS);
    expect(catalog).toHaveLength(PROOF_SCENARIOS.length + 10);
    expect(
      catalog
        .slice(PROOF_SCENARIOS.length)
        .every(({ requirements }) => requirements[0]?.adapter === "wallet-alias"),
    ).toBe(true);
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
    expect(harness.adapters).toHaveLength(7);
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
      "p2tr-scriptpath": `sha256:${"d".repeat(64)}`,
      "intent-rich-p2wpkh": `sha256:${"d".repeat(64)}`,
    });
    const bdkCommitments = JSON.stringify({
      "happy-path": `sha256:${"c".repeat(64)}`,
      "bdk-finalize-regression": `sha256:${"d".repeat(64)}`,
      p2wpkh: `sha256:${"d".repeat(64)}`,
      "p2wsh-single-key": `sha256:${"d".repeat(64)}`,
      "p2wsh-2-of-3": `sha256:${"d".repeat(64)}`,
      "p2tr-keypath": `sha256:${"d".repeat(64)}`,
      "p2tr-scriptpath": `sha256:${"d".repeat(64)}`,
      "intent-rich-p2wpkh": `sha256:${"d".repeat(64)}`,
    });
    const psbtv2Commitments = JSON.stringify({
      p2wpkh: `sha256:${"d".repeat(64)}`,
      "intent-rich-p2wpkh": `sha256:${"d".repeat(64)}`,
      "p2wsh-2-of-3": `sha256:${"d".repeat(64)}`,
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
      {
        image: "psbt-interop-lab/bdk-wallet-current:3.1.0",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: bdkCommitments } },
      },
      {
        image: "psbt-interop-lab/rust-psbt-v2:0.1.0",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: psbtv2Commitments } },
      },
      {
        image: "psbt-interop-lab/libwally:1.5.4",
        options: { env: { PSBT_LAB_FIXTURE_COMMITMENTS: psbtv2Commitments } },
      },
    ]);
    expect(rustCommitments).not.toContain("cHNidP8");
    expect(commonCommitments).not.toContain("cHNidP8");
    expect(bdkCommitments).not.toContain("cHNidP8");
    expect(psbtv2Commitments).not.toContain("cHNidP8");
  });

  test("closes every adapter exactly once after an infrastructure failure", async () => {
    const harness = proofHarness(true);

    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
      },
      harness.dependencies,
    );

    expect(result.manifest).toMatchObject({
      outcome: "failed",
      scenarios: [
        {
          id: "runtime-lifecycle",
          outcome: "failed",
          infrastructureError: {
            errorClass: "Error",
            message: "Core unavailable",
          },
        },
      ],
    });
    for (const adapter of harness.adapters) expect(adapter.close).toHaveBeenCalledTimes(1);
  });

  test("continues the proof matrix when a built-in hello negotiation fails", async () => {
    const harness = proofHarness(false, "psbt-interop-lab/bitcoinjs-lib:7.0.1");
    const catalog: readonly ScenarioDefinition<ScenarioExecutionContext>[] = [
      {
        id: "bitcoinjs-required-runtime",
        title: "BitcoinJS required runtime",
        category: "test",
        summary: "Requires bitcoinjs-lib",
        requirements: [{ adapter: "bitcoinjs-lib", operations: ["sign"] }],
        async run() {
          return { assertions: [{ name: "unexpected-run", passed: true }] };
        },
      },
      {
        id: "rust-runtime",
        title: "Rust runtime",
        category: "test",
        summary: "Requires rust-bitcoin",
        requirements: [{ adapter: "rust-bitcoin", operations: ["roundtrip"] }],
        async run() {
          return { assertions: [{ name: "rust-ran", passed: true }] };
        },
      },
    ];
    harness.dependencies.createCatalog = vi.fn(() => catalog);

    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
      },
      harness.dependencies,
    );

    expect(result.manifest).toMatchObject({
      outcome: "failed",
      scenarios: [
        {
          id: "bitcoinjs-required-runtime",
          outcome: "unsupported",
          adapterCells: [
            expect.objectContaining({
              adapter: "bitcoinjs-lib",
              operation: "sign",
              status: "unsupported",
              errorClass: "capability.adapter.missing",
            }),
          ],
        },
        { id: "rust-runtime", outcome: "passed" },
      ],
    });
    expect(result.manifest.adapters.map(({ name }) => name)).not.toContain("bitcoinjs-lib");
    for (const adapter of harness.adapters) expect(adapter.close).toHaveBeenCalledTimes(1);
  });

  test("registers, negotiates, runs, reports, and closes a manifest adapter by id", async () => {
    const harness = proofHarness();
    const externalContract: ExpectedAdapterContract = {
      name: "actual-wallet-library",
      version: "2.0.0",
      sourceRevision: "actual-wallet-v2.0.0",
      operations: ["hello", "native-parse", "roundtrip", "sign"],
      roles: ["parser", "signer"],
      psbtVersions: [0],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
        sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      },
      features: ["fixture-commitment-sha256"],
    };
    const externalAdapter = runtimeAdapter(externalContract);
    const createExternalAdapter = vi.fn((_options: AdapterProcessOptions) => externalAdapter);
    const externalScenario: ScenarioDefinition<ScenarioExecutionContext> = {
      id: "external-runtime",
      title: "External runtime",
      category: "test",
      summary: "External runtime test",
      requirements: [{ adapter: "wallet-alias", operations: ["hello"] }],
      async run(context) {
        const response = await context.request("wallet-alias", "hello", {});
        return {
          assertions: [{ name: "external-request-completed", passed: response.status === "ok" }],
        };
      },
    };
    const createCatalog = vi.fn(
      (_fixtures: PreparedFixtures, external: ReadonlyMap<string, NegotiatedAdapter>) => {
        expect([...external.keys()]).toEqual(["wallet-alias"]);
        return [externalScenario];
      },
    );
    const dependencies = {
      ...harness.dependencies,
      createExternalAdapter,
      createCatalog,
    } as unknown as ProofDependencies;
    const adapterManifest = parseAdapterManifest(
      {
        schema: "psbt-lab.adapters/0.1",
        adapters: [
          {
            id: "wallet-alias",
            command: "/usr/bin/example-adapter",
            env: { EXAMPLE_NETWORK: "regtest" },
            expected: {
              name: "actual-wallet-library",
              version: "2.0.0",
              sourceRevision: "actual-wallet-v2.0.0",
            },
          },
        ],
      },
      "/project",
    );

    const result = await runProofWithDependencies(
      {
        rpc: {} as never,
        artifactRoot: "/tmp/psbt-lab-test",
        projectDirectory: "/project",
        adapterManifest,
      } as never,
      dependencies,
    );

    expect(result.manifest.outcome).toBe("passed");
    expect(result.manifest.adapters).toHaveLength(8);
    expect(result.manifest.adapters[7]).toMatchObject({ name: "actual-wallet-library" });
    expect(result.manifest.adapters[7]?.capabilities).toEqual({
      operations: ["hello", "native-parse", "roundtrip", "sign"],
      roles: ["parser", "signer"],
      psbtVersions: [0],
      scriptTypes: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      operationScriptTypes: {
        roundtrip: ["p2wpkh", "p2wsh", "p2tr-keypath"],
        sign: ["p2wpkh", "p2wsh", "p2tr-keypath"],
      },
      features: ["fixture-commitment-sha256"],
    });
    expect(createExternalAdapter).toHaveBeenCalledOnce();
    const processOptions = createExternalAdapter.mock.calls[0]?.[0];
    expect(processOptions).toMatchObject({
      command: "/usr/bin/example-adapter",
      env: { EXAMPLE_NETWORK: "regtest" },
    });
    const commitments = JSON.parse(processOptions?.env?.["PSBT_LAB_FIXTURE_COMMITMENTS"] ?? "{}");
    expect(commitments).toEqual({
      "happy-path": `sha256:${"c".repeat(64)}`,
      p2wpkh: `sha256:${"d".repeat(64)}`,
      "p2sh-p2wpkh": `sha256:${"d".repeat(64)}`,
      "p2tr-keypath": `sha256:${"d".repeat(64)}`,
      "p2tr-scriptpath": `sha256:${"d".repeat(64)}`,
    });
    expect(externalAdapter.close).toHaveBeenCalledOnce();
  });
});
