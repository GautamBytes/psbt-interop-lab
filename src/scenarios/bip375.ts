import { validateBip375ReferencePsbt } from "../psbt/bip375-validator.js";
import {
  BIP375_INVALID_VECTORS,
  BIP375_VALID_VECTORS,
  type Bip375VectorStage,
} from "../psbt/bip375-vectors.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

const INVALID_STAGES = [
  "psbt structure",
  "ecdh coverage",
  "input eligibility",
  "output scripts",
] as const satisfies readonly Bip375VectorStage[];

function invalidStageAssertion(stage: Bip375VectorStage): ScenarioAssertionEvidence {
  const failures = BIP375_INVALID_VECTORS.filter(
    (vector) => vector.expectedStage === stage,
  ).flatMap((vector) => {
    const result = validateBip375ReferencePsbt(vector.base64);
    return !result.valid && result.stage === stage
      ? []
      : [`${vector.id}: expected ${stage}, got ${result.valid ? "accepted" : result.stage}`];
  });

  return {
    name: `bip375-invalid-${stage.replaceAll(" ", "-")}`,
    passed: failures.length === 0,
    summary:
      failures.length === 0
        ? `All invalid ${stage} vectors failed at the expected stage`
        : `Mismatches: ${failures.join(", ")}`,
  };
}

export function createBip375ReferenceScenario(): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: "bip375-official-reference-vectors",
    title: "Official BIP375 Silent Payment reference vectors",
    category: "silent-payment-conformance",
    summary:
      "The complete official BIP375 corpus is checked with local cryptographic and structural validation.",
    requirements: [],
    async run() {
      const validFailures = BIP375_VALID_VECTORS.flatMap((vector) => {
        const result = validateBip375ReferencePsbt(vector.base64);
        return result.valid ? [] : [`${vector.id}: ${result.stage}: ${result.message}`];
      });
      const assertions: ScenarioAssertionEvidence[] = [
        {
          name: "bip375-valid-vectors",
          passed: validFailures.length === 0,
          summary:
            validFailures.length === 0
              ? `All ${BIP375_VALID_VECTORS.length} valid vectors passed`
              : `Failures: ${validFailures.join(", ")}`,
        },
        ...INVALID_STAGES.map(invalidStageAssertion),
      ];
      const passed = assertions.every((assertion) => assertion.passed);

      return {
        summary: passed
          ? `All ${BIP375_VALID_VECTORS.length + BIP375_INVALID_VECTORS.length} official BIP375 vectors matched their expected outcomes.`
          : "The local validator disagreed with the official BIP375 corpus.",
        assertions,
      };
    },
  };
}
