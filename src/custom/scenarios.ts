import type { PsbtFixture } from "../core/fixtures.js";
import {
  classifyAdapterParserResponse,
  classifyLabParser,
  type ParserOutcome,
} from "../fuzz/differential.js";
import type { AdapterOperation, AdapterRole } from "../protocol/types.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { CoreFinalizeResult, ScenarioExecutionContext } from "../scenarios/context.js";
import type {
  AdapterCapabilityRequirement,
  ScenarioAssertionEvidence,
  ScenarioDefinition,
} from "../scenarios/definition.js";
import { exactFieldUnionEvidence } from "../scenarios/interop-matrix.js";
import type { UserScenarioSpec, UserScenarioStepSpec } from "./manifest.js";

type RuntimeValue =
  | { readonly kind: "psbt"; readonly value: string }
  | { readonly kind: "finalized"; readonly value: CoreFinalizeResult }
  | { readonly kind: "terminal" };

interface MutableRequirement {
  readonly adapter: string;
  readonly operations: AdapterOperation[];
  readonly roles: AdapterRole[];
  readonly features: string[];
}

function uniquePush<T>(target: T[], value: T): void {
  if (!target.includes(value)) target.push(value);
}

function adapterRole(operation: UserScenarioStepSpec["operation"]): AdapterRole | undefined {
  switch (operation) {
    case "roundtrip":
      return "parser";
    case "sign":
      return "signer";
    case "combine":
      return "combiner";
    case "finalize-inputs":
      return "finalizer";
    default:
      return undefined;
  }
}

function compileRequirements(
  scenario: UserScenarioSpec,
  fixture: PsbtFixture,
): AdapterCapabilityRequirement[] {
  const requirements = new Map<string, MutableRequirement>();
  for (const step of scenario.steps) {
    if (step.operation === "compare-parsers") {
      for (const adapter of step.adapters) {
        const requirement = requirements.get(adapter) ?? {
          adapter,
          operations: [],
          roles: [],
          features: [],
        };
        uniquePush(requirement.operations, "native-parse");
        uniquePush(requirement.roles, "parser");
        requirements.set(adapter, requirement);
      }
      continue;
    }
    if (!("adapter" in step)) continue;
    const requirement = requirements.get(step.adapter) ?? {
      adapter: step.adapter,
      operations: [],
      roles: [],
      features: [],
    };
    uniquePush(requirement.operations, step.operation);
    const role = adapterRole(step.operation);
    if (role) uniquePush(requirement.roles, role);
    if (step.operation === "sign" || step.operation === "finalize-inputs") {
      uniquePush(requirement.features, "fixture-commitment-sha256");
      if (fixture.specSha256) uniquePush(requirement.features, "user-fixture-template-v1");
    }
    requirements.set(step.adapter, requirement);
  }
  return [...requirements.values()].map((requirement) => ({
    adapter: requirement.adapter,
    operations: requirement.operations,
    roles: requirement.roles,
    psbtVersions: [fixture.psbtVersion],
    scriptTypes: fixture.scriptTypes,
    ...(requirement.features.length > 0 ? { features: requirement.features } : {}),
  }));
}

function validateTypedDataflow(scenario: UserScenarioSpec): void {
  const values = new Map<string, RuntimeValue["kind"]>([["fixture", "psbt"]]);
  for (const step of scenario.steps) {
    if (values.has(step.id)) {
      throw new TypeError(`Custom scenario ${scenario.id} repeats step id ${step.id}`);
    }
    const inputs = "inputs" in step ? step.inputs : [step.input];
    const expectedKind = step.operation === "core-policy-check" ? "finalized" : "psbt";
    for (const input of inputs) {
      const actualKind = values.get(input);
      if (!actualKind) {
        throw new TypeError(
          `Custom scenario ${scenario.id} step ${step.id} references unavailable input ${input}`,
        );
      }
      if (actualKind !== expectedKind) {
        throw new TypeError(
          `Custom scenario ${scenario.id} step ${step.id} requires a ${
            expectedKind === "finalized" ? "core-finalize" : "PSBT"
          } input`,
        );
      }
    }
    values.set(
      step.id,
      step.operation === "core-finalize"
        ? "finalized"
        : step.operation === "core-policy-check" || step.operation === "compare-parsers"
          ? "terminal"
          : "psbt",
    );
  }
}

function psbtValue(values: ReadonlyMap<string, RuntimeValue>, id: string): string {
  const value = values.get(id);
  if (value?.kind !== "psbt") throw new Error(`Custom step input ${id} is not a PSBT`);
  return value.value;
}

function finalizedValue(values: ReadonlyMap<string, RuntimeValue>, id: string): CoreFinalizeResult {
  const value = values.get(id);
  if (value?.kind !== "finalized") {
    throw new Error(`Custom step input ${id} is not a Core finalization result`);
  }
  return value.value;
}

function signatureKeyTypes(fixture: PsbtFixture): readonly number[] {
  return fixture.scriptTypes.includes("p2tr-keypath") ? [0x13, 0x14] : [0x02];
}

async function executeAdapterStep(
  scenario: UserScenarioSpec,
  fixture: PsbtFixture,
  step: Extract<UserScenarioStepSpec, { readonly adapter: string; readonly input: string }>,
  context: ScenarioExecutionContext,
  values: Map<string, RuntimeValue>,
  assertions: ScenarioAssertionEvidence[],
): Promise<void> {
  const before = psbtValue(values, step.input);
  const payload =
    step.operation === "roundtrip"
      ? { psbt: before }
      : {
          psbt: before,
          network: "regtest",
          fixtureId: fixture.id,
          ...(fixture.specSha256 ? { fixtureSpecSha256: fixture.specSha256 } : {}),
          ...(step.operation === "finalize-inputs"
            ? { inputIndexes: Array.from({ length: fixture.inputCount }, (_, index) => index) }
            : {}),
        };
  const response = await context.request(step.adapter, step.operation, payload);
  const after = context.outputString(response, "psbt", step.operation);
  const policy =
    step.operation === "roundtrip" ? "roundtrip" : step.operation === "sign" ? "sign" : "finalize";
  assertions.push(
    context.requireTransition(
      policy,
      `${step.id}-${step.adapter}-${step.operation}`,
      before,
      after,
      step.adapter,
    ),
  );
  if (step.operation === "sign") {
    assertions.push(
      context.requireAddedInputField(
        `${step.id}-${step.adapter}-added-signature`,
        before,
        after,
        signatureKeyTypes(fixture),
      ),
    );
  } else if (step.operation === "finalize-inputs") {
    assertions.push(
      context.requireAddedInputField(
        `${step.id}-${step.adapter}-added-final-fields`,
        before,
        after,
        [0x07, 0x08],
      ),
    );
  }
  values.set(step.id, { kind: "psbt", value: after });
  await context.checkpoint(scenario.id, step.id, after);
}

async function executeScenario(
  scenario: UserScenarioSpec,
  fixture: PsbtFixture,
  context: ScenarioExecutionContext,
) {
  const values = new Map<string, RuntimeValue>([
    ["fixture", { kind: "psbt", value: fixture.initialPsbt }],
  ]);
  const assertions: ScenarioAssertionEvidence[] = [];
  let policyAccepted: boolean | undefined;
  let transactionId: string | undefined;
  await context.checkpoint(scenario.id, "fixture", fixture.initialPsbt);

  for (const step of scenario.steps) {
    if (step.operation === "mutate") {
      const before = psbtValue(values, step.input);
      const mutated = applyPsbtMutations(before, step.recipes);
      assertions.push({
        name: step.id,
        passed: mutated !== before,
        summary:
          mutated !== before
            ? `Applied ${step.recipes.length} deterministic PSBT mutation recipe(s)`
            : "Mutation recipes did not change the PSBT",
      });
      values.set(step.id, { kind: "psbt", value: mutated });
      await context.checkpoint(scenario.id, step.id, mutated);
      continue;
    }
    if (step.operation === "compare-parsers") {
      const psbt = psbtValue(values, step.input);
      const outcomes: Record<string, ParserOutcome> = { lab: classifyLabParser(psbt) };
      for (const adapter of step.adapters) {
        outcomes[adapter] = classifyAdapterParserResponse(
          await context.request(adapter, "native-parse", { psbt }),
        );
      }
      for (const [implementation, expected] of Object.entries(step.expected)) {
        const actual = outcomes[implementation];
        assertions.push({
          name: `${step.id}-${implementation}`,
          passed: actual?.classification === expected,
          likelyImplementation: implementation,
          summary: actual
            ? `${implementation} returned ${actual.classification}; expected ${expected}`
            : `${implementation} produced no parser outcome`,
        });
      }
      values.set(step.id, { kind: "terminal" });
      continue;
    }
    if (
      step.operation === "roundtrip" ||
      step.operation === "sign" ||
      step.operation === "finalize-inputs"
    ) {
      await executeAdapterStep(scenario, fixture, step, context, values, assertions);
      continue;
    }
    if (step.operation === "combine") {
      const sources = step.inputs.map((input) => psbtValue(values, input));
      const response = await context.request(step.adapter, "combine", { psbts: sources });
      const combined = context.outputString(response, "psbt", "combine");
      for (const [index, source] of sources.entries()) {
        assertions.push(
          context.requireTransition(
            "combine",
            `${step.id}-source-${index + 1}`,
            source,
            combined,
            step.adapter,
          ),
        );
      }
      assertions.push(exactFieldUnionEvidence(sources, combined));
      values.set(step.id, { kind: "psbt", value: combined });
      await context.checkpoint(scenario.id, step.id, combined);
      continue;
    }
    if (step.operation === "core-finalize") {
      const finalized = await context.finalizeWithCore(psbtValue(values, step.input));
      assertions.push({
        name: step.id,
        passed: finalized.complete && typeof finalized.hex === "string",
        summary: finalized.complete
          ? "Bitcoin Core finalized the custom scenario PSBT"
          : "Bitcoin Core could not finalize the custom scenario PSBT",
      });
      values.set(step.id, { kind: "finalized", value: finalized });
      continue;
    }
    const policy = await context.policyCheck(finalizedValue(values, step.input));
    policyAccepted = policy.allowed;
    transactionId = policy.txid;
    assertions.push({
      name: step.id,
      passed: policy.allowed,
      summary: policy.allowed
        ? "Bitcoin Core accepted the custom scenario transaction under regtest policy"
        : `Bitcoin Core rejected the custom scenario transaction${
            policy.rejectReason ? `: ${policy.rejectReason}` : ""
          }`,
    });
    values.set(step.id, { kind: "terminal" });
  }

  return {
    summary: `Executed ${scenario.steps.length} checked custom handoff steps for fixture ${fixture.id}.`,
    assertions,
    ...(policyAccepted !== undefined ? { policyAccepted } : {}),
    ...(transactionId ? { transactionId } : {}),
  };
}

export function compileUserScenarios(
  scenarios: readonly UserScenarioSpec[],
  fixtures: ReadonlyMap<string, PsbtFixture>,
): readonly ScenarioDefinition<ScenarioExecutionContext>[] {
  return scenarios.map((scenario) => {
    const fixture = fixtures.get(scenario.fixture);
    if (!fixture) {
      throw new TypeError(
        `Custom scenario ${scenario.id} references unknown fixture ${scenario.fixture}`,
      );
    }
    validateTypedDataflow(scenario);
    return {
      id: scenario.id,
      title: scenario.title,
      category: "custom-handoff",
      summary: `A user-defined deterministic handoff for fixture ${fixture.id}.`,
      requirements: compileRequirements(scenario, fixture),
      run: (context) => executeScenario(scenario, fixture, context),
    };
  });
}
