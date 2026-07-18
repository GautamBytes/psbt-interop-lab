import type { PsbtFixture } from "../core/fixtures.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export interface ScriptProfileRoundtripOptions {
  readonly id: string;
  readonly title: string;
  readonly adapters: readonly string[];
}

export function createScriptProfileRoundtripScenario(
  fixture: PsbtFixture,
  options: ScriptProfileRoundtripOptions,
): ScenarioDefinition<ScenarioExecutionContext> {
  if (options.adapters.length === 0 || new Set(options.adapters).size !== options.adapters.length) {
    throw new TypeError("Script profile roundtrip adapters must be a non-empty unique list");
  }
  return {
    id: options.id,
    title: options.title,
    category: "script-profile-roundtrip",
    summary: `Checks that ${fixture.scriptTypes.join(", ")} PSBT fields survive every selected implementation.`,
    requirements: options.adapters.map((adapter) => ({
      adapter,
      operations: ["roundtrip"],
      roles: ["parser"],
      psbtVersions: [fixture.psbtVersion],
      scriptTypes: fixture.scriptTypes,
    })),
    async run(context) {
      const assertions: ScenarioAssertionEvidence[] = [];
      let current = fixture.initialPsbt;
      await context.checkpoint(options.id, "core-created", current);
      for (const adapter of options.adapters) {
        const before = current;
        const response = await context.request(adapter, "roundtrip", { psbt: before });
        current = context.outputString(response, "psbt", "roundtrip");
        assertions.push(
          context.requireTransition(
            "roundtrip",
            `${adapter}-preserved-${fixture.id}`,
            before,
            current,
            adapter,
          ),
        );
        await context.checkpoint(options.id, `${adapter}-roundtrip`, current);
      }
      return {
        summary: `${fixture.id} survived ${options.adapters.length} checked roundtrip handoffs.`,
        assertions,
      };
    },
  };
}
