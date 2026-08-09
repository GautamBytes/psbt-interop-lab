import { describe, expect, test, vi } from "vitest";
import type {
  AdapterRequest,
  AdapterResponse,
  NegotiatedAdapter,
} from "../../src/protocol/types.js";
import { parsePsbtDocument } from "../../src/psbt/document.js";
import { applyPsbtMutations } from "../../src/psbt/mutation.js";
import { extractWireFacts } from "../../src/psbt/wire-facts.js";
import {
  BIP375_ADVANCED_FIXTURE_IDS,
  bip375AdvancedFixture,
  createBip375AdvancedSenderScenario,
} from "../../src/scenarios/bip375.js";
import { ScenarioExecutionContext } from "../../src/scenarios/context.js";
import { runScenarioCatalog } from "../../src/scenarios/engine.js";

const implementation = {
  name: "rust-psbt-v2",
  version: "0.3.0",
  sourceRevision: "psbt-v2-0.3.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
};

const negotiated: NegotiatedAdapter = {
  implementation,
  capabilities: {
    operations: ["hello", "silent-payment-send-advanced"],
    roles: ["updater", "signer"],
    psbtVersions: [2],
    scriptTypes: ["p2wpkh"],
    operationScriptTypes: { "silent-payment-send-advanced": ["p2wpkh"] },
    features: ["bip375-advanced-sender-workflows"],
  },
};

function removePartialSignatures(psbt: string): string {
  const recipes = parsePsbtDocument(psbt).maps.flatMap((map) =>
    map.location.kind === "input"
      ? map.entries
          .filter(({ keyType }) => keyType === 0x02)
          .map((entry) => ({
            kind: "delete-entry" as const,
            location: map.location,
            keyType: entry.keyType,
            keyDataHex: entry.keyData.toString("hex"),
          }))
      : [],
  );
  return applyPsbtMutations(psbt, recipes);
}

async function runAdvancedScenario(
  outputPsbt: (fixtureId: (typeof BIP375_ADVANCED_FIXTURE_IDS)[number]) => string,
  failFixture?: (typeof BIP375_ADVANCED_FIXTURE_IDS)[number],
) {
  const checkpoints: string[] = [];
  const adapter = {
    request: vi.fn(async (request: AdapterRequest): Promise<AdapterResponse> => {
      const fixtureId = request.payload["fixtureId"] as
        | (typeof BIP375_ADVANCED_FIXTURE_IDS)[number]
        | undefined;
      if (!fixtureId || !BIP375_ADVANCED_FIXTURE_IDS.includes(fixtureId)) {
        throw new Error("Unexpected advanced fixture request");
      }
      if (fixtureId === failFixture) {
        return {
          protocol: "psbt-lab.adapter/0.2",
          id: request.id,
          status: "rejected",
          implementation,
          error: {
            class: "policy.fixture_commitment_mismatch",
            message: "deliberate adapter failure",
          },
        };
      }
      return {
        protocol: "psbt-lab.adapter/0.2",
        id: request.id,
        status: "ok",
        implementation,
        output: {
          psbt: outputPsbt(fixtureId),
          finalized: false,
          finalizationAvailable: false,
          finalizationReason: "Official fixture funding scripts use unrelated keys",
          // These values are deliberately dishonest. The scenario must inspect the PSBT itself.
          signedInputs: 999,
          silentPaymentOutputs: 999,
          outputScripts: ["adapter-controlled"],
        },
      };
    }),
  };
  const context = new ScenarioExecutionContext({
    rpc: { call: vi.fn() } as never,
    artifacts: {
      checkpoint: vi.fn(async (scenario: string, stage: string, psbt: string) => {
        checkpoints.push(stage);
        return {
          scenario,
          stage,
          psbtPath: `checkpoints/${scenario}/${stage}.psbt`,
          factsPath: `checkpoints/${scenario}/${stage}.facts.json`,
          facts: extractWireFacts(psbt),
        };
      }),
    },
    adapters: new Map([[implementation.name, adapter]]),
    adapterTimeoutMs: 1_000,
  });
  const [result] = await runScenarioCatalog(
    [createBip375AdvancedSenderScenario(implementation.name)],
    context,
    new Map([[implementation.name, negotiated]]),
  );
  return { checkpoints, result };
}

function workflowEntries(psbt: string): number {
  return parsePsbtDocument(psbt).maps.reduce(
    (count, map) =>
      count +
      map.entries.filter(({ keyType }) =>
        map.location.kind === "global"
          ? [0x07, 0x08].includes(keyType)
          : map.location.kind === "input"
            ? [0x02, 0x1d, 0x1e].includes(keyType)
            : false,
      ).length,
    0,
  );
}

describe("advanced BIP375 sender fixtures", () => {
  test("derive unsigned workflow seeds from pinned official vectors", () => {
    expect(BIP375_ADVANCED_FIXTURE_IDS).toEqual([
      "valid-02",
      "valid-03",
      "valid-06",
      "valid-07",
      "valid-13",
    ]);

    for (const id of BIP375_ADVANCED_FIXTURE_IDS) {
      const fixture = bip375AdvancedFixture(id);
      const document = parsePsbtDocument(fixture.inProgressPsbt);
      expect(document.psbtVersion, id).toBe(2);
      expect(workflowEntries(fixture.inProgressPsbt), id).toBe(0);
      expect(
        document.maps
          .filter(({ location }) => location.kind === "output")
          .filter((map) => map.entries.some(({ keyType }) => keyType === 0x09))
          .every((map) => !map.entries.some(({ keyType }) => keyType === 0x04)),
        id,
      ).toBe(true);
      expect(fixture.expectedOutputScripts.length, id).toBeGreaterThan(0);
    }
  });

  test("covers global, per-input, multi-recipient, label/change, and k ordering workflows", () => {
    expect(bip375AdvancedFixture("valid-02")).toMatchObject({
      shareScope: "global",
      inputCount: 2,
      silentPaymentOutputCount: 1,
    });
    expect(bip375AdvancedFixture("valid-03")).toMatchObject({
      shareScope: "per-input",
      inputCount: 2,
      signerCount: 2,
    });
    expect(bip375AdvancedFixture("valid-06")).toMatchObject({
      shareScope: "global",
      silentPaymentOutputCount: 3,
      scanKeyCount: 3,
    });
    expect(bip375AdvancedFixture("valid-07")).toMatchObject({
      labelCount: 1,
      ordinaryOutputCount: 1,
    });
    expect(bip375AdvancedFixture("valid-13")).toMatchObject({
      silentPaymentOutputCount: 3,
      scanKeyCount: 1,
    });
  });

  test("declares one bounded executable scenario for the advanced native workflow", () => {
    expect(createBip375AdvancedSenderScenario("rust-psbt-v2")).toMatchObject({
      id: "bip375-advanced-sender-workflows-rust-psbt-v2",
      category: "silent-payment-interop",
      requirements: [
        {
          adapter: "rust-psbt-v2",
          operations: ["silent-payment-send-advanced"],
          psbtVersions: [2],
          scriptTypes: ["p2wpkh"],
          features: ["bip375-advanced-sender-workflows"],
        },
      ],
    });
  });

  test("checks all five returned PSBTs independently and records replay checkpoints", async () => {
    const { checkpoints, result } = await runAdvancedScenario(
      (fixtureId) => bip375AdvancedFixture(fixtureId).completedPsbt,
    );

    expect(result?.outcome).toBe("passed");
    expect(checkpoints).toEqual(BIP375_ADVANCED_FIXTURE_IDS.map((id) => `${id}-completed`));
  });

  test("rejects an adapter claim when the returned PSBT lacks partial signatures", async () => {
    const { result } = await runAdvancedScenario((fixtureId) => {
      const psbt = bip375AdvancedFixture(fixtureId).completedPsbt;
      return fixtureId === "valid-02" ? removePartialSignatures(psbt) : psbt;
    });

    expect(result?.outcome).toBe("failed");
    expect(result?.assertions[0]).toMatchObject({
      name: "bip375-advanced-workflow-coverage",
      passed: false,
    });
  });

  test("does not report the finalization boundary as passed after an adapter failure", async () => {
    const { result } = await runAdvancedScenario(
      (fixtureId) => bip375AdvancedFixture(fixtureId).completedPsbt,
      "valid-02",
    );

    expect(result?.outcome).toBe("failed");
    expect(result?.assertions).toContainEqual({
      name: "bip375-advanced-finalization-boundary",
      passed: false,
      summary:
        "The finalization boundary was verified for 4 of 5 advanced workflows; failed or incomplete workflows cannot prove this boundary",
    });
  });
});
