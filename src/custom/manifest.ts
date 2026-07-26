import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import type { FixtureDescriptorId } from "../core/fixture-profiles.js";
import type { ParserExpectedOutcome } from "../fuzz/differential.js";
import { validateCustomSuiteManifest as generatedValidateManifest } from "../generated/validators.js";
import { type PsbtDocument, parsePsbtDocument } from "../psbt/document.js";
import type { PsbtMutationRecipe } from "../psbt/mutation.js";

export const CUSTOM_SUITE_SCHEMA = "psbt-lab.suite/0.2" as const;
export const LEGACY_CUSTOM_SUITE_SCHEMA = "psbt-lab.suite/0.1" as const;
const MAX_MANIFEST_BYTES = 1024 * 1024;

export interface UserFixtureInputSpec {
  readonly descriptor: FixtureDescriptorId;
  readonly sequence: number;
}

export type UserFixtureOutputSpec =
  | { readonly descriptor: FixtureDescriptorId; readonly amountSats: number }
  | { readonly descriptor: FixtureDescriptorId; readonly remainder: true };

export interface UserFixtureSpec {
  readonly id: string;
  readonly inputs: readonly UserFixtureInputSpec[];
  readonly outputs: readonly UserFixtureOutputSpec[];
  readonly feeSats: number;
  readonly locktime: number;
  readonly transactionVersion: 2;
}

export interface UserParserFixtureSpec {
  readonly id: string;
  readonly psbt: string;
  readonly sha256: `sha256:${string}`;
}

export interface UserAdapterStepSpec {
  readonly id: string;
  readonly adapter: string;
  readonly operation: "roundtrip" | "sign" | "finalize-inputs";
  readonly input: string;
}

export interface UserCombineStepSpec {
  readonly id: string;
  readonly adapter: string;
  readonly operation: "combine";
  readonly inputs: readonly string[];
}

export interface UserCoreStepSpec {
  readonly id: string;
  readonly operation: "core-finalize" | "core-policy-check";
  readonly input: string;
}

export interface UserMutateStepSpec {
  readonly id: string;
  readonly operation: "mutate";
  readonly input: string;
  readonly recipes: readonly PsbtMutationRecipe[];
}

export interface UserCompareParsersStepSpec {
  readonly id: string;
  readonly operation: "compare-parsers";
  readonly input: string;
  readonly adapters: readonly string[];
  readonly expected: Readonly<Record<string, ParserExpectedOutcome>>;
}

export type UserScenarioStepSpec =
  | UserAdapterStepSpec
  | UserCombineStepSpec
  | UserCoreStepSpec
  | UserMutateStepSpec
  | UserCompareParsersStepSpec;

export interface UserScenarioSpec {
  readonly id: string;
  readonly title: string;
  readonly fixture: string;
  readonly steps: readonly UserScenarioStepSpec[];
}

export interface CustomSuiteManifest {
  readonly schema: typeof CUSTOM_SUITE_SCHEMA | typeof LEGACY_CUSTOM_SUITE_SCHEMA;
  readonly fixtures: readonly UserFixtureSpec[];
  readonly parserFixtures?: readonly UserParserFixtureSpec[];
  readonly scenarios: readonly UserScenarioSpec[];
}

interface GeneratedValidationError {
  readonly instancePath: string;
  readonly message?: string;
}

interface GeneratedValidator<T> {
  (value: unknown): value is T;
  readonly errors?: readonly GeneratedValidationError[] | null;
}

const validateManifest = generatedValidateManifest as GeneratedValidator<CustomSuiteManifest>;

function manifestError(detail: string): TypeError {
  return new TypeError(`Invalid custom suite manifest: ${detail}`);
}

function requireUniqueIds(values: readonly { readonly id: string }[], label: string): void {
  const ids = new Set<string>();
  for (const value of values) {
    if (ids.has(value.id)) throw manifestError(`duplicate ${label} id ${value.id}`);
    ids.add(value.id);
  }
}

function validateFixtureSemantics(fixtures: readonly UserFixtureSpec[]): void {
  for (const fixture of fixtures) {
    const remainderCount = fixture.outputs.filter((output) => "remainder" in output).length;
    if (remainderCount > 1) {
      throw manifestError(`fixture ${fixture.id} declares more than one remainder output`);
    }
  }
}

function validateParserFixtures(fixtures: readonly UserParserFixtureSpec[]): void {
  for (const fixture of fixtures) {
    let document: PsbtDocument;
    try {
      document = parsePsbtDocument(fixture.psbt);
    } catch {
      throw manifestError(`parser fixture ${fixture.id} is not a valid base PSBT`);
    }
    const digest = `sha256:${createHash("sha256").update(document.bytes).digest("hex")}`;
    if (digest !== fixture.sha256) {
      throw manifestError(`parser fixture ${fixture.id} does not match its sha256 commitment`);
    }
  }
}

function validateScenarioDataflow(scenarios: readonly UserScenarioSpec[]): void {
  for (const scenario of scenarios) {
    const available = new Set(["fixture"]);
    for (const step of scenario.steps) {
      if (available.has(step.id)) {
        throw manifestError(`scenario ${scenario.id} has duplicate step id ${step.id}`);
      }
      const inputs = "inputs" in step ? step.inputs : [step.input];
      if (new Set(inputs).size !== inputs.length) {
        throw manifestError(`scenario ${scenario.id} step ${step.id} repeats an input`);
      }
      for (const input of inputs) {
        if (!available.has(input)) {
          throw manifestError(
            `scenario ${scenario.id} step ${step.id} references unavailable input ${input}`,
          );
        }
      }
      if (step.operation === "compare-parsers") {
        if (new Set(step.adapters).size !== step.adapters.length) {
          throw manifestError(`scenario ${scenario.id} step ${step.id} repeats an adapter`);
        }
        const expectedAdapters = new Set(["lab", ...step.adapters]);
        if (
          Object.keys(step.expected).some((adapter) => !expectedAdapters.has(adapter)) ||
          [...expectedAdapters].some((adapter) => step.expected[adapter] === undefined)
        ) {
          throw manifestError(
            `scenario ${scenario.id} step ${step.id} expected outcomes must match lab and adapters`,
          );
        }
      }
      available.add(step.id);
    }
  }
}

function validateParserScenarioIsolation(
  scenarios: readonly UserScenarioSpec[],
  parserFixtureIds: ReadonlySet<string>,
): void {
  for (const scenario of scenarios) {
    if (!parserFixtureIds.has(scenario.fixture)) continue;
    if (
      scenario.steps.some(
        ({ operation }) => operation !== "mutate" && operation !== "compare-parsers",
      )
    ) {
      throw manifestError(
        `scenario ${scenario.id} uses parser fixture ${scenario.fixture} outside parser-only operations`,
      );
    }
  }
}

export function parseCustomSuiteManifest(value: unknown): CustomSuiteManifest {
  if (!validateManifest(value)) {
    const details = (validateManifest.errors ?? [])
      .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
      .join("; ");
    throw manifestError(details);
  }
  if (
    value.schema === LEGACY_CUSTOM_SUITE_SCHEMA &&
    (value.parserFixtures !== undefined ||
      value.scenarios.some((scenario) =>
        scenario.steps.some(
          (step) => step.operation === "mutate" || step.operation === "compare-parsers",
        ),
      ))
  ) {
    throw manifestError("schema 0.1 cannot contain parser regression features");
  }
  const parserFixtures = value.parserFixtures ?? [];
  requireUniqueIds([...value.fixtures, ...parserFixtures], "fixture");
  requireUniqueIds(value.scenarios, "scenario");
  validateFixtureSemantics(value.fixtures);
  validateParserFixtures(parserFixtures);
  validateScenarioDataflow(value.scenarios);
  validateParserScenarioIsolation(value.scenarios, new Set(parserFixtures.map(({ id }) => id)));
  const fixtureIds = new Set([...value.fixtures, ...parserFixtures].map(({ id }) => id));
  for (const scenario of value.scenarios) {
    if (!fixtureIds.has(scenario.fixture)) {
      throw manifestError(`scenario ${scenario.id} references unknown fixture ${scenario.fixture}`);
    }
  }
  return value;
}

export async function loadCustomSuiteManifest(path: string): Promise<CustomSuiteManifest> {
  const absolutePath = resolve(path);
  const handle = await open(absolutePath, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_MANIFEST_BYTES) {
      throw manifestError("file must be a regular file no larger than 1 MiB");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_MANIFEST_BYTES) {
      throw manifestError("file grew beyond the 1 MiB limit while reading");
    }
    try {
      return parseCustomSuiteManifest(JSON.parse(bytes.toString("utf8")));
    } catch (error) {
      if (
        error instanceof TypeError &&
        error.message.startsWith("Invalid custom suite manifest:")
      ) {
        throw error;
      }
      throw manifestError("file is not valid JSON");
    }
  } finally {
    await handle.close();
  }
}
