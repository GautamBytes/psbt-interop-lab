import { performance } from "node:perf_hooks";
import type { NegotiatedAdapter } from "../protocol/types.js";
import type {
  AdapterCapabilityRequirement,
  MissingCapability,
  ScenarioAssertionEvidence,
  ScenarioDefinition,
  ScenarioExecutionOutput,
  ScenarioResult,
} from "./definition.js";

export class ScenarioAssertionError extends Error {
  override readonly name = "ScenarioAssertionError";

  constructor(
    message: string,
    readonly assertions: readonly ScenarioAssertionEvidence[],
  ) {
    super(message);
  }
}

function appendMissing<T extends string | number>(
  output: MissingCapability[],
  adapter: string,
  kind: MissingCapability["kind"],
  required: readonly T[] | undefined,
  declared: readonly T[],
): void {
  for (const value of required ?? []) {
    if (!declared.includes(value)) {
      output.push({ adapter, kind, value });
    }
  }
}

function missingForRequirement(
  requirement: AdapterCapabilityRequirement,
  adapters: ReadonlyMap<string, NegotiatedAdapter>,
): MissingCapability[] {
  const negotiated = adapters.get(requirement.adapter);
  if (!negotiated) {
    return [{ adapter: requirement.adapter, kind: "adapter", value: requirement.adapter }];
  }

  const missing: MissingCapability[] = [];
  const capabilities = negotiated.capabilities;
  appendMissing(
    missing,
    requirement.adapter,
    "operation",
    requirement.operations,
    capabilities.operations,
  );
  appendMissing(missing, requirement.adapter, "role", requirement.roles, capabilities.roles);
  appendMissing(
    missing,
    requirement.adapter,
    "psbtVersion",
    requirement.psbtVersions,
    capabilities.psbtVersions,
  );
  appendMissing(
    missing,
    requirement.adapter,
    "scriptType",
    requirement.scriptTypes,
    capabilities.scriptTypes,
  );
  appendMissing(
    missing,
    requirement.adapter,
    "feature",
    requirement.features,
    capabilities.features ?? [],
  );
  return missing;
}

export function findMissingCapabilities(
  requirements: readonly AdapterCapabilityRequirement[],
  adapters: ReadonlyMap<string, NegotiatedAdapter>,
): MissingCapability[] {
  return requirements.flatMap((requirement) => missingForRequirement(requirement, adapters));
}

function elapsedMilliseconds(startedAt: number): number {
  return Math.max(0, Math.round((performance.now() - startedAt) * 1000) / 1000);
}

function completedResult<Context>(
  definition: ScenarioDefinition<Context>,
  output: ScenarioExecutionOutput,
  startedAt: number,
): ScenarioResult {
  const passed = output.assertions.every((assertion) => assertion.passed);
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    outcome: passed ? "passed" : "failed",
    summary: output.summary ?? definition.summary,
    durationMs: elapsedMilliseconds(startedAt),
    assertions: output.assertions,
    ...(output.expectedFailure ? { expectedFailure: output.expectedFailure } : {}),
    ...(output.policyAccepted !== undefined ? { policyAccepted: output.policyAccepted } : {}),
    ...(output.transactionId ? { transactionId: output.transactionId } : {}),
  };
}

export async function runScenarioCatalog<Context>(
  catalog: readonly ScenarioDefinition<Context>[],
  context: Context,
  adapters: ReadonlyMap<string, NegotiatedAdapter>,
): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];

  for (const definition of catalog) {
    const startedAt = performance.now();
    const missingCapabilities = findMissingCapabilities(definition.requirements, adapters);
    if (missingCapabilities.length > 0) {
      results.push({
        id: definition.id,
        title: definition.title,
        category: definition.category,
        outcome: "unsupported",
        summary: `${definition.title} is unsupported by the negotiated adapter capabilities.`,
        durationMs: elapsedMilliseconds(startedAt),
        assertions: [],
        missingCapabilities,
      });
      continue;
    }

    const skipReason = await definition.skip?.(context);
    if (skipReason !== undefined) {
      results.push({
        id: definition.id,
        title: definition.title,
        category: definition.category,
        outcome: "skipped",
        summary: `${definition.title} was skipped: ${skipReason}.`,
        durationMs: elapsedMilliseconds(startedAt),
        assertions: [],
        skipReason,
      });
      continue;
    }

    try {
      const output = await definition.run(context);
      results.push(completedResult(definition, output, startedAt));
    } catch (error) {
      if (!(error instanceof ScenarioAssertionError)) {
        throw error;
      }
      results.push({
        id: definition.id,
        title: definition.title,
        category: definition.category,
        outcome: "failed",
        summary: error.message,
        durationMs: elapsedMilliseconds(startedAt),
        assertions: error.assertions,
      });
    }
  }

  return results;
}
