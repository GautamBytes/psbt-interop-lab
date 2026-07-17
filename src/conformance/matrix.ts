import { createHash } from "node:crypto";
import type { FixtureScriptType } from "../core/fixture-profiles.js";
import type { PreparedFixtures, PsbtFixture } from "../core/fixtures.js";
import type { NegotiatedAdapter } from "../protocol/types.js";
import type { ScenarioExecutionContext } from "../scenarios/context.js";
import type { ScenarioDefinition } from "../scenarios/definition.js";
import { createHappyPathScenario } from "../scenarios/happy-path.js";

interface ExternalFixtureProfile {
  readonly fixture: PsbtFixture;
  readonly scriptType: FixtureScriptType;
  readonly signatureKeyTypes: readonly number[];
}

function scenarioId(adapterId: string, scriptType: FixtureScriptType, operation: string): string {
  const suffix = `${scriptType}-${operation}`;
  const candidate = `external-${adapterId}-${suffix}`;
  if (candidate.length <= 64) return candidate;
  const digest = createHash("sha256").update(adapterId).digest("hex").slice(0, 8);
  const fixedLength = "external---".length + digest.length + suffix.length;
  const shortened = adapterId.slice(0, 64 - fixedLength);
  return `external-${shortened}-${digest}-${suffix}`;
}

function supportsSigning(adapter: NegotiatedAdapter, scriptType: FixtureScriptType): boolean {
  const capabilities = adapter.capabilities;
  return (
    capabilities.operations.includes("roundtrip") &&
    capabilities.operations.includes("sign") &&
    capabilities.roles.includes("parser") &&
    capabilities.roles.includes("signer") &&
    capabilities.psbtVersions.includes(0) &&
    capabilities.scriptTypes.includes(scriptType) &&
    (capabilities.operationScriptTypes?.roundtrip?.includes(scriptType) ?? false) &&
    (capabilities.operationScriptTypes?.sign?.includes(scriptType) ?? false) &&
    (capabilities.features?.includes("fixture-commitment-sha256") ?? false)
  );
}

function createParseRoundtripScenario(
  adapterId: string,
  implementationName: string,
  profile: ExternalFixtureProfile,
): ScenarioDefinition<ScenarioExecutionContext> {
  const id = scenarioId(adapterId, profile.scriptType, "roundtrip");
  return {
    id,
    title: `${adapterId} ${profile.scriptType} native parse and roundtrip`,
    category: "external-adapter-roundtrip",
    summary: `${adapterId} parses and semantically preserves the built-in ${profile.scriptType} PSBT fixture.`,
    requirements: [
      {
        adapter: adapterId,
        operations: ["native-parse", "roundtrip"],
        roles: ["parser"],
        psbtVersions: [0],
        scriptTypes: [profile.scriptType],
      },
    ],
    async run(context) {
      await context.checkpoint(id, "source", profile.fixture.initialPsbt);
      const parsed = await context.request(adapterId, "native-parse", {
        psbt: profile.fixture.initialPsbt,
      });
      const nativeParser = context.outputString(parsed, "nativeParser", "native-parse");
      const roundtrip = await context.request(adapterId, "roundtrip", {
        psbt: profile.fixture.initialPsbt,
      });
      const roundtripPsbt = context.outputString(roundtrip, "psbt", "roundtrip");
      const transition = context.requireTransition(
        "roundtrip",
        `${adapterId}-${profile.scriptType}-roundtrip`,
        profile.fixture.initialPsbt,
        roundtripPsbt,
      );
      await context.checkpoint(id, "roundtrip", roundtripPsbt);
      return {
        summary: `${adapterId} parsed and preserved the ${profile.scriptType} fixture.`,
        assertions: [
          {
            name: `${adapterId}-${profile.scriptType}-native-parser`,
            passed: nativeParser === implementationName,
            summary:
              nativeParser === implementationName
                ? "The native parser identity matched the negotiated implementation"
                : `The adapter reported native parser ${nativeParser}`,
          },
          transition,
        ],
      };
    },
  };
}

export function createExternalAdapterScenarios(
  fixtures: PreparedFixtures,
  adapters: ReadonlyMap<string, NegotiatedAdapter>,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  const profiles: readonly ExternalFixtureProfile[] = [
    {
      fixture: fixtures.profiles.p2wpkh,
      scriptType: "p2wpkh",
      signatureKeyTypes: [0x02],
    },
    { fixture: fixtures.happy, scriptType: "p2wsh", signatureKeyTypes: [0x02] },
    {
      fixture: fixtures.profiles["p2tr-keypath"],
      scriptType: "p2tr-keypath",
      signatureKeyTypes: [0x13],
    },
  ];
  const definitions: ScenarioDefinition<ScenarioExecutionContext>[] = [];
  for (const [adapterId, adapter] of adapters) {
    for (const profile of profiles) {
      definitions.push(
        createParseRoundtripScenario(adapterId, adapter.implementation.name, profile),
      );
      if (supportsSigning(adapter, profile.scriptType)) {
        definitions.push(
          createHappyPathScenario(profile.fixture, {
            adapter: adapterId,
            id: scenarioId(adapterId, profile.scriptType, "sign"),
            title: `${adapterId} ${profile.scriptType} signing handoff`,
            category: "external-adapter-signing",
            scriptType: profile.scriptType,
            signatureKeyTypes: profile.signatureKeyTypes,
          }),
        );
      }
    }
  }
  return definitions;
}
