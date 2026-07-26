import type {
  CustomSuiteManifest,
  UserCompareParsersStepSpec,
  UserMutateStepSpec,
  UserScenarioSpec,
} from "../custom/manifest.js";
import { applyPsbtMutations } from "../psbt/mutation.js";
import type { RuntimeProvider } from "../runtime/provider.js";
import { compareRuntimeParsers, type ParserClassification } from "./differential.js";

export interface ParserRegressionAssertion {
  readonly name: string;
  readonly expected: ParserClassification;
  readonly actual?: ParserClassification;
  readonly passed: boolean;
}

export interface ParserRegressionScenarioResult {
  readonly id: string;
  readonly title: string;
  readonly outcome: "passed" | "failed";
  readonly assertions: readonly ParserRegressionAssertion[];
}

export interface ParserRegressionReport {
  readonly schema: "psbt-lab.parser-regression-report/0.1";
  readonly runtime: string;
  readonly outcome: "passed" | "failed";
  readonly scenarios: readonly ParserRegressionScenarioResult[];
}

export interface RunParserRegressionOptions {
  readonly manifest: CustomSuiteManifest;
  readonly createProvider: () => Promise<RuntimeProvider>;
}

type ParserRegressionStep = UserMutateStepSpec | UserCompareParsersStepSpec;

function parserOnlyScenario(
  scenario: UserScenarioSpec,
): asserts scenario is UserScenarioSpec & { readonly steps: readonly ParserRegressionStep[] } {
  if (
    scenario.steps.some(
      ({ operation }) => operation !== "mutate" && operation !== "compare-parsers",
    )
  ) {
    throw new TypeError(
      `Parser regression scenario ${scenario.id} contains a Core or signing operation`,
    );
  }
  if (!scenario.steps.some(({ operation }) => operation === "compare-parsers")) {
    throw new TypeError(`Parser regression scenario ${scenario.id} has no parser comparison`);
  }
}

export async function runParserRegressionSuite(
  options: RunParserRegressionOptions,
): Promise<ParserRegressionReport> {
  const parserFixtures = new Map(
    (options.manifest.parserFixtures ?? []).map((fixture) => [fixture.id, fixture.psbt] as const),
  );
  const scenarios: ParserRegressionScenarioResult[] = [];
  let runtime = "local";

  for (const scenario of options.manifest.scenarios) {
    parserOnlyScenario(scenario);
    const initialPsbt = parserFixtures.get(scenario.fixture);
    if (!initialPsbt) {
      throw new TypeError(
        `Parser regression scenario ${scenario.id} must reference a parser fixture`,
      );
    }
    const values = new Map<string, string>([["fixture", initialPsbt]]);
    const assertions: ParserRegressionAssertion[] = [];

    for (const step of scenario.steps) {
      const input = values.get(step.input);
      if (!input) {
        throw new TypeError(
          `Parser regression scenario ${scenario.id} step ${step.id} has no PSBT input`,
        );
      }
      if (step.operation === "mutate") {
        values.set(step.id, applyPsbtMutations(input, step.recipes));
        continue;
      }

      const provider = await options.createProvider();
      runtime = provider.runtime;
      const outcomes = await compareRuntimeParsers(provider, input);
      for (const [implementation, expected] of Object.entries(step.expected)) {
        const actual = outcomes[implementation]?.classification;
        assertions.push({
          name: `${step.id}-${implementation}`,
          expected,
          ...(actual ? { actual } : {}),
          passed: actual === expected,
        });
      }
    }

    scenarios.push({
      id: scenario.id,
      title: scenario.title,
      outcome: assertions.every(({ passed }) => passed) ? "passed" : "failed",
      assertions,
    });
  }

  return {
    schema: "psbt-lab.parser-regression-report/0.1",
    runtime,
    outcome: scenarios.every(({ outcome }) => outcome === "passed") ? "passed" : "failed",
    scenarios,
  };
}
