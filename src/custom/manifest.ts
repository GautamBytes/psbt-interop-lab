import { open } from "node:fs/promises";
import { resolve } from "node:path";
import type { FixtureDescriptorId } from "../core/fixture-profiles.js";
import { validateCustomSuiteManifest as generatedValidateManifest } from "../generated/validators.js";

export const CUSTOM_SUITE_SCHEMA = "psbt-lab.suite/0.1" as const;
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

export type UserScenarioStepSpec = UserAdapterStepSpec | UserCombineStepSpec | UserCoreStepSpec;

export interface UserScenarioSpec {
  readonly id: string;
  readonly title: string;
  readonly fixture: string;
  readonly steps: readonly UserScenarioStepSpec[];
}

export interface CustomSuiteManifest {
  readonly schema: typeof CUSTOM_SUITE_SCHEMA;
  readonly fixtures: readonly UserFixtureSpec[];
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
      available.add(step.id);
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
  requireUniqueIds(value.fixtures, "fixture");
  requireUniqueIds(value.scenarios, "scenario");
  validateFixtureSemantics(value.fixtures);
  validateScenarioDataflow(value.scenarios);
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
