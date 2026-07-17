import { performance } from "node:perf_hooks";
import type { NegotiatedAdapter } from "../protocol/types.js";
import type { PsbtTransitionFailure } from "../psbt/invariants.js";
import { redactSensitiveText } from "../runner/report.js";
import type {
  AdapterCapabilityRequirement,
  MissingCapability,
  ScenarioAssertionEvidence,
  ScenarioDefinition,
  ScenarioExecutionOutput,
  ScenarioFinding,
  ScenarioResult,
} from "./definition.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

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
  const negotiatedRegistryId = negotiated.registryId ?? negotiated.implementation.name;
  if (negotiatedRegistryId !== requirement.adapter) {
    return [
      {
        adapter: requirement.adapter,
        kind: "identity",
        value: negotiated.implementation.name,
      },
    ];
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
  for (const operation of requirement.operations ?? []) {
    if (
      operation === "hello" ||
      operation === "native-parse" ||
      !capabilities.operations.includes(operation)
    )
      continue;
    for (const scriptType of requirement.scriptTypes ?? []) {
      if (!capabilities.scriptTypes.includes(scriptType)) continue;
      if (!(capabilities.operationScriptTypes?.[operation]?.includes(scriptType) ?? false)) {
        missing.push({
          adapter: requirement.adapter,
          kind: "operationScriptType",
          value: `${operation}:${scriptType}`,
        });
      }
    }
  }
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

function copyFailure(failure: PsbtTransitionFailure): PsbtTransitionFailure {
  const location =
    failure.location.kind === "global"
      ? { kind: "global" as const }
      : { kind: failure.location.kind, index: failure.location.index };
  return {
    code: failure.code,
    location,
    keyType: failure.keyType,
    completeKeySha256: failure.completeKeySha256,
    keyBytes: failure.keyBytes,
    ...(failure.before
      ? {
          before: {
            valueSha256: failure.before.valueSha256,
            valueBytes: failure.before.valueBytes,
          },
        }
      : {}),
    ...(failure.after
      ? {
          after: {
            valueSha256: failure.after.valueSha256,
            valueBytes: failure.after.valueBytes,
          },
        }
      : {}),
  };
}

function copyAssertion(assertion: ScenarioAssertionEvidence): ScenarioAssertionEvidence {
  return {
    name: assertion.name,
    passed: assertion.passed,
    ...(assertion.policy !== undefined ? { policy: assertion.policy } : {}),
    ...(assertion.exactBytesEqual !== undefined
      ? { exactBytesEqual: assertion.exactBytesEqual }
      : {}),
    ...(assertion.failures !== undefined
      ? { failures: assertion.failures.map((failure) => copyFailure(failure)) }
      : {}),
    ...(assertion.summary !== undefined ? { summary: redactSensitiveText(assertion.summary) } : {}),
  };
}

function copyAssertions(
  assertions: readonly ScenarioAssertionEvidence[],
): ScenarioAssertionEvidence[] {
  return assertions.map((assertion) => copyAssertion(assertion));
}

function copyFindings(findings: readonly ScenarioFinding[] | undefined): ScenarioFinding[] {
  return (findings ?? []).map((finding) => ({
    id: finding.id,
    implementation: redactSensitiveText(finding.implementation),
    summary: redactSensitiveText(finding.summary),
  }));
}

function assertValidCatalog<Context>(catalog: readonly ScenarioDefinition<Context>[]): void {
  const identifiers = new Set<string>();
  for (const [index, definition] of catalog.entries()) {
    if (!SAFE_IDENTIFIER.test(definition.id)) {
      throw new TypeError(
        `Scenario identifier at catalog index ${index} must be a safe identifier`,
      );
    }
    if (identifiers.has(definition.id)) {
      throw new TypeError(`Duplicate scenario identifier: ${definition.id}`);
    }
    identifiers.add(definition.id);
  }
}

function redactErrorMessage(error: Error): Error {
  const redacted = redactSensitiveText(error.message);
  if (redacted !== error.message) {
    error.message = redacted;
  }
  return error;
}

function completedResult<Context>(
  definition: ScenarioDefinition<Context>,
  output: ScenarioExecutionOutput,
  startedAt: number,
): ScenarioResult {
  const assertions = copyAssertions(output.assertions);
  const passed =
    assertions.length > 0 &&
    assertions.every((assertion) => assertion.passed && (assertion.failures?.length ?? 0) === 0);
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    outcome: passed ? "passed" : "failed",
    summary: redactSensitiveText(output.summary ?? definition.summary),
    durationMs: elapsedMilliseconds(startedAt),
    assertions,
    ...(output.findings?.length ? { findings: copyFindings(output.findings) } : {}),
    ...(output.expectedFailure
      ? {
          expectedFailure: {
            implementation: output.expectedFailure.implementation,
            errorClass: output.expectedFailure.errorClass,
          },
        }
      : {}),
    ...(output.policyAccepted !== undefined ? { policyAccepted: output.policyAccepted } : {}),
    ...(output.transactionId ? { transactionId: output.transactionId } : {}),
  };
}

export async function runScenarioCatalog<Context>(
  catalog: readonly ScenarioDefinition<Context>[],
  context: Context,
  adapters: ReadonlyMap<string, NegotiatedAdapter>,
): Promise<ScenarioResult[]> {
  assertValidCatalog(catalog);
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
        summary: redactSensitiveText(
          `${definition.title} is unsupported by the negotiated adapter capabilities.`,
        ),
        durationMs: elapsedMilliseconds(startedAt),
        assertions: [],
        missingCapabilities,
      });
      continue;
    }

    const requestedSkipReason = await definition.skip?.(context);
    if (requestedSkipReason !== undefined) {
      const skipReason = redactSensitiveText(requestedSkipReason);
      results.push({
        id: definition.id,
        title: definition.title,
        category: definition.category,
        outcome: "skipped",
        summary: redactSensitiveText(`${definition.title} was skipped: ${skipReason}.`),
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
        throw error instanceof Error ? redactErrorMessage(error) : error;
      }
      results.push({
        id: definition.id,
        title: definition.title,
        category: definition.category,
        outcome: "failed",
        summary: redactSensitiveText(error.message),
        durationMs: elapsedMilliseconds(startedAt),
        assertions: copyAssertions(error.assertions),
      });
    }
  }

  return results;
}
