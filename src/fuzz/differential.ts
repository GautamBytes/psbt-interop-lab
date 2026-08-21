import type { LocalParseFixture } from "../local/fixtures.js";
import { AdapterTimeoutError } from "../protocol/adapter-process.js";
import { parseAdapterHelloCapabilities } from "../protocol/schema.js";
import {
  ADAPTER_PROTOCOL,
  type AdapterHelloCapabilities,
  type AdapterImplementation,
  type AdapterResponse,
} from "../protocol/types.js";
import { parsePsbtDocument } from "../psbt/document.js";
import { minimizeMutationRecipes } from "../psbt/minimize.js";
import {
  applyPsbtMutations,
  generateBoundedMutations,
  type PsbtMutationRecipe,
} from "../psbt/mutation.js";
import {
  assessOutputAmountSemantics,
  type OutputAmountSemanticAssessment,
} from "../psbt/output-amount-semantics.js";
import type { AvailableRuntimeAdapter, RuntimeProvider } from "../runtime/provider.js";

export type ParserClassification = "accepted" | "rejected" | "unsupported" | "crashed" | "timeout";

export interface ParserFacts {
  readonly psbtVersion: number;
  readonly inputs: number;
  readonly outputs: number;
}

export interface ParserOutcome {
  readonly classification: ParserClassification;
  readonly detail: string;
  readonly facts?: ParserFacts;
}

export type ParserExpectedOutcome =
  | ParserClassification
  | {
      readonly classification: ParserClassification;
      readonly facts?: ParserFacts;
    };

export interface DifferentialFuzzCase {
  readonly index: number;
  readonly recipes: readonly PsbtMutationRecipe[];
  readonly mutatedPsbt: string;
  readonly outcomes: Readonly<Record<string, ParserOutcome>>;
  readonly outputAmountSemantics: OutputAmountSemanticAssessment;
}

export interface InterestingDifferentialCase extends DifferentialFuzzCase {
  readonly minimizedRecipes: readonly PsbtMutationRecipe[];
  readonly minimizedPsbt: string;
  readonly minimizedOutcomes: Readonly<Record<string, ParserOutcome>>;
  readonly minimizedOutputAmountSemantics: OutputAmountSemanticAssessment;
}

export interface DifferentialFuzzResult {
  readonly runtime: string;
  readonly implementations: Readonly<Record<string, AdapterImplementation>>;
  readonly fixture: Pick<LocalParseFixture, "id" | "psbtVersion" | "sha256">;
  readonly seed: number;
  readonly requestedCases: number;
  readonly cases: readonly DifferentialFuzzCase[];
  readonly interesting: readonly InterestingDifferentialCase[];
}

export interface DifferentialFuzzOptions {
  readonly provider: RuntimeProvider;
  readonly fixture: LocalParseFixture;
  readonly seed: number;
  readonly cases: number;
}

interface ReadyParser {
  readonly adapter: AvailableRuntimeAdapter;
  readonly capabilities: AdapterHelloCapabilities;
  readonly implementation: AdapterImplementation;
}

interface ParserEvaluator {
  readonly implementations: Readonly<Record<string, AdapterImplementation>>;
  readonly evaluate: (psbt: string) => Promise<CandidateEvaluation>;
}

interface CandidateEvaluation {
  readonly outcomes: Readonly<Record<string, ParserOutcome>>;
  readonly outputAmountSemantics: OutputAmountSemanticAssessment;
}

interface LabEvaluation {
  readonly outcome: ParserOutcome;
  readonly outputAmountSemantics: OutputAmountSemanticAssessment;
}

function identityMatches(adapter: AvailableRuntimeAdapter, response: AdapterResponse): boolean {
  return (
    response.implementation.name === adapter.expected.name &&
    response.implementation.version === adapter.expected.version &&
    response.implementation.sourceRevision === adapter.expected.sourceRevision &&
    (adapter.expected.artifactDigest === undefined ||
      response.implementation.artifactDigest === adapter.expected.artifactDigest)
  );
}

function evaluateLabCandidate(psbt: string): LabEvaluation {
  let document: ReturnType<typeof parsePsbtDocument>;
  try {
    document = parsePsbtDocument(psbt);
  } catch (error) {
    return {
      outcome: {
        classification: "rejected",
        detail: error instanceof Error ? error.message : "lab parser rejected the PSBT",
      },
      outputAmountSemantics: { status: "not-evaluated", findings: [] },
    };
  }
  return {
    outcome: {
      classification: "accepted",
      detail: "lab parser accepted the PSBT",
      facts: {
        psbtVersion: document.psbtVersion,
        inputs: document.inputCount,
        outputs: document.outputCount,
      },
    },
    outputAmountSemantics: assessOutputAmountSemantics(document),
  };
}

export function classifyLabParser(psbt: string): ParserOutcome {
  return evaluateLabCandidate(psbt).outcome;
}

export function classifyAdapterParserResponse(response: AdapterResponse): ParserOutcome {
  if (response.status !== "ok") {
    return {
      classification: response.status,
      detail: `${response.error.class}: ${response.error.message}`,
    };
  }
  const { psbtVersion, inputs, outputs } = response.output;
  if (
    !Number.isSafeInteger(psbtVersion) ||
    (psbtVersion !== 0 && psbtVersion !== 2) ||
    !Number.isSafeInteger(inputs) ||
    (inputs as number) < 0 ||
    !Number.isSafeInteger(outputs) ||
    (outputs as number) < 0
  ) {
    return {
      classification: "crashed",
      detail: "adapter accepted the PSBT without normalized parser facts",
    };
  }
  return {
    classification: "accepted",
    detail: "adapter parser accepted the PSBT",
    facts: {
      psbtVersion: psbtVersion as number,
      inputs: inputs as number,
      outputs: outputs as number,
    },
  };
}

function unavailableOutcome(detail: string): ParserOutcome {
  return { classification: "unsupported", detail };
}

function processFailureOutcome(error: unknown, fallback: string): ParserOutcome {
  return {
    classification: error instanceof AdapterTimeoutError ? "timeout" : "crashed",
    detail: error instanceof Error ? error.message : fallback,
  };
}

function factKey(outcome: ParserOutcome): string {
  return outcome.facts
    ? `${outcome.facts.psbtVersion}:${outcome.facts.inputs}:${outcome.facts.outputs}`
    : "";
}

function parserOutcomeKey(outcome: ParserOutcome): string {
  return `${outcome.classification}:${factKey(outcome)}`;
}

export function parserOutcomeMatches(
  actual: ParserOutcome | undefined,
  expected: ParserExpectedOutcome,
): boolean {
  if (!actual) return false;
  const normalized = typeof expected === "string" ? { classification: expected } : expected;
  return (
    actual.classification === normalized.classification &&
    (normalized.facts === undefined ||
      (actual.facts !== undefined &&
        actual.facts.psbtVersion === normalized.facts.psbtVersion &&
        actual.facts.inputs === normalized.facts.inputs &&
        actual.facts.outputs === normalized.facts.outputs))
  );
}

export function hasSameParserOutcomes(
  left: Readonly<Record<string, ParserOutcome>>,
  right: Readonly<Record<string, ParserOutcome>>,
): boolean {
  const leftIds = Object.keys(left).sort();
  const rightIds = Object.keys(right).sort();
  return (
    leftIds.length === rightIds.length &&
    leftIds.every(
      (id, index) =>
        id === rightIds[index] &&
        right[id] !== undefined &&
        parserOutcomeKey(left[id] as ParserOutcome) ===
          parserOutcomeKey(right[id] as ParserOutcome),
    )
  );
}

export function hasParserDifferential(outcomes: Readonly<Record<string, ParserOutcome>>): boolean {
  const comparable = Object.values(outcomes).filter(
    ({ classification }) => classification !== "unsupported",
  );
  if (new Set(comparable.map(({ classification }) => classification)).size > 1) return true;
  const accepted = comparable.filter(({ classification }) => classification === "accepted");
  return new Set(accepted.map(factKey)).size > 1;
}

async function negotiateParser(
  adapter: AvailableRuntimeAdapter,
  index: number,
): Promise<ReadyParser | ParserOutcome> {
  try {
    const response = await adapter.process.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: `fuzz-${index}-hello`,
        operation: "hello",
        payload: {},
      },
      adapter.timeoutMs,
    );
    if (!identityMatches(adapter, response)) {
      return { classification: "crashed", detail: "adapter identity did not match manifest" };
    }
    if (response.status !== "ok") return classifyAdapterParserResponse(response);
    const capabilities = parseAdapterHelloCapabilities(response.output);
    if (
      !capabilities.roles.includes("parser") ||
      !capabilities.operations.includes("native-parse")
    ) {
      return unavailableOutcome("adapter does not declare native parser support");
    }
    return { adapter, capabilities, implementation: response.implementation };
  } catch (error) {
    await adapter.process.restart?.().catch(() => undefined);
    return processFailureOutcome(error, "adapter negotiation failed");
  }
}

function isReadyParser(value: ReadyParser | ParserOutcome): value is ReadyParser {
  return "adapter" in value;
}

async function adapterOutcome(
  parser: ReadyParser,
  psbt: string,
  requestId: string,
): Promise<ParserOutcome> {
  if (!parser.capabilities.psbtVersions.some((version) => version === 0 || version === 2)) {
    return unavailableOutcome("adapter declares no supported PSBT version");
  }
  try {
    const response = await parser.adapter.process.request(
      {
        protocol: ADAPTER_PROTOCOL,
        id: requestId,
        operation: "native-parse",
        payload: { psbt },
      },
      parser.adapter.timeoutMs,
    );
    if (!identityMatches(parser.adapter, response)) {
      return { classification: "crashed", detail: "adapter identity changed during fuzzing" };
    }
    if (response.status === "crashed" || response.status === "timeout") {
      await parser.adapter.process.restart?.().catch(() => undefined);
    }
    return classifyAdapterParserResponse(response);
  } catch (error) {
    await parser.adapter.process.restart?.().catch(() => undefined);
    return processFailureOutcome(error, "adapter parser failed");
  }
}

async function createParserEvaluator(provider: RuntimeProvider): Promise<ParserEvaluator> {
  const runtimeAdapters = await provider.adapters();
  const negotiated = new Map<string, ReadyParser | ParserOutcome>();
  const implementations: Record<string, AdapterImplementation> = {};
  for (const [index, adapter] of runtimeAdapters.entries()) {
    const parser =
      adapter.availability === "unsupported"
        ? unavailableOutcome(adapter.reason)
        : await negotiateParser(adapter, index);
    negotiated.set(adapter.id, parser);
    if (isReadyParser(parser)) implementations[adapter.id] = parser.implementation;
  }

  let requestCounter = 0;
  return {
    implementations,
    async evaluate(psbt) {
      const lab = evaluateLabCandidate(psbt);
      const outcomes: Record<string, ParserOutcome> = { lab: lab.outcome };
      for (const [id, parser] of negotiated) {
        requestCounter += 1;
        outcomes[id] = isReadyParser(parser)
          ? await adapterOutcome(parser, psbt, `parser-compare-${requestCounter}`)
          : parser;
      }
      return { outcomes, outputAmountSemantics: lab.outputAmountSemantics };
    },
  };
}

export async function compareRuntimeParsers(
  provider: RuntimeProvider,
  psbt: string,
): Promise<Readonly<Record<string, ParserOutcome>>> {
  try {
    const evaluator = await createParserEvaluator(provider);
    const evaluation = await evaluator.evaluate(psbt);
    return evaluation.outcomes;
  } finally {
    await provider.close();
  }
}

export async function runDifferentialFuzz(
  options: DifferentialFuzzOptions,
): Promise<DifferentialFuzzResult> {
  const generated = generateBoundedMutations(options.fixture.psbt, options.seed, options.cases);
  try {
    const evaluator = await createParserEvaluator(options.provider);

    const cases: DifferentialFuzzCase[] = [];
    const interesting: InterestingDifferentialCase[] = [];
    for (const generatedCase of generated) {
      const evaluation = await evaluator.evaluate(generatedCase.mutatedPsbt);
      const fuzzCase: DifferentialFuzzCase = {
        index: generatedCase.index,
        recipes: generatedCase.recipes,
        mutatedPsbt: generatedCase.mutatedPsbt,
        outcomes: evaluation.outcomes,
        outputAmountSemantics: evaluation.outputAmountSemantics,
      };
      cases.push(fuzzCase);
      if (!hasParserDifferential(evaluation.outcomes)) continue;
      const minimizedRecipes = await minimizeMutationRecipes(
        options.fixture.psbt,
        generatedCase.recipes,
        async (candidate) =>
          hasSameParserOutcomes(
            evaluation.outcomes,
            (await evaluator.evaluate(candidate)).outcomes,
          ),
      );
      const minimizedPsbt = applyPsbtMutations(options.fixture.psbt, minimizedRecipes);
      const minimized = await evaluator.evaluate(minimizedPsbt);
      interesting.push({
        ...fuzzCase,
        minimizedRecipes,
        minimizedPsbt,
        minimizedOutcomes: minimized.outcomes,
        minimizedOutputAmountSemantics: minimized.outputAmountSemantics,
      });
    }
    return {
      runtime: options.provider.runtime,
      implementations: evaluator.implementations,
      fixture: {
        id: options.fixture.id,
        psbtVersion: options.fixture.psbtVersion,
        sha256: options.fixture.sha256,
      },
      seed: options.seed,
      requestedCases: options.cases,
      cases,
      interesting,
    };
  } finally {
    await options.provider.close();
  }
}
