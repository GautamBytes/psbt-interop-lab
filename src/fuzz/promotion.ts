import { createHash } from "node:crypto";
import type { LocalParseFixture } from "../local/fixtures.js";
import type { PsbtMutationRecipe } from "../psbt/mutation.js";
import type { ParserExpectedOutcome, ParserOutcome } from "./differential.js";

export interface DifferentialPromotionInput {
  readonly fixture: LocalParseFixture;
  readonly seed: number;
  readonly caseIndex: number;
  readonly recipes: readonly PsbtMutationRecipe[];
  readonly outcomes: Readonly<Record<string, ParserOutcome>>;
}

export interface PromotedDifferentialSuite {
  readonly schema: "psbt-lab.suite/0.2";
  readonly fixtures: readonly [];
  readonly parserFixtures: readonly [
    {
      readonly id: string;
      readonly psbt: string;
      readonly sha256: `sha256:${string}`;
    },
  ];
  readonly scenarios: readonly [
    {
      readonly id: string;
      readonly title: string;
      readonly fixture: string;
      readonly steps: readonly [
        {
          readonly id: "mutated";
          readonly operation: "mutate";
          readonly input: "fixture";
          readonly recipes: readonly PsbtMutationRecipe[];
        },
        {
          readonly id: "compare";
          readonly operation: "compare-parsers";
          readonly input: "mutated";
          readonly adapters: readonly string[];
          readonly expected: Readonly<Record<string, ParserExpectedOutcome>>;
        },
      ];
    },
  ];
}

export function promoteDifferentialCase(
  input: DifferentialPromotionInput,
): PromotedDifferentialSuite {
  if (!Number.isSafeInteger(input.seed) || input.seed < 0 || input.seed > 0xffff_ffff) {
    throw new RangeError("Promotion seed must be an unsigned 32-bit integer");
  }
  if (!Number.isSafeInteger(input.caseIndex) || input.caseIndex < 0) {
    throw new RangeError("Promotion case index must be a non-negative safe integer");
  }
  if (input.recipes.length === 0) throw new TypeError("Promotion requires a mutation recipe");
  const id = `fuzz-${input.seed}-${input.caseIndex}`;
  const fixtureId = `${id}-base`;
  const adapters = Object.keys(input.outcomes).filter((adapter) => adapter !== "lab");
  const expected = Object.fromEntries(
    Object.entries(input.outcomes).map(([adapter, outcome]) => [
      adapter,
      {
        classification: outcome.classification,
        ...(outcome.facts ? { facts: outcome.facts } : {}),
      },
    ]),
  );
  return {
    schema: "psbt-lab.suite/0.2",
    fixtures: [],
    parserFixtures: [
      {
        id: fixtureId,
        psbt: input.fixture.psbt,
        sha256: `sha256:${createHash("sha256")
          .update(Buffer.from(input.fixture.psbt, "base64"))
          .digest("hex")}`,
      },
    ],
    scenarios: [
      {
        id,
        title: `Differential parser regression seed ${input.seed} case ${input.caseIndex}`,
        fixture: fixtureId,
        steps: [
          {
            id: "mutated",
            operation: "mutate",
            input: "fixture",
            recipes: input.recipes,
          },
          {
            id: "compare",
            operation: "compare-parsers",
            input: "mutated",
            adapters,
            expected,
          },
        ],
      },
    ],
  };
}
