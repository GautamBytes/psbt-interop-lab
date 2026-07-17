import { createHash } from "node:crypto";
import {
  FIXTURE_DESCRIPTOR_SCRIPT_TYPES,
  FIXTURE_PROFILES,
  type FixtureDescriptorId,
  type FixtureScriptType,
} from "../core/fixture-profiles.js";
import type { UserFixtureOutputSpec, UserFixtureSpec } from "./manifest.js";

const BUILT_IN_FIXTURE_IDS = new Set([
  "happy-path",
  "bdk-finalize-regression",
  ...FIXTURE_PROFILES.map(({ id }) => id),
]);

export interface CompiledUserFixturePlan {
  readonly id: string;
  readonly inputDescriptorIds: readonly FixtureDescriptorId[];
  readonly outputDescriptorIds: readonly FixtureDescriptorId[];
  readonly scriptTypes: readonly FixtureScriptType[];
  readonly sequences: readonly number[];
  readonly locktime: number;
  readonly transactionVersion: 2;
  readonly feeSats: number;
  readonly outputAmounts: readonly (number | null)[];
  readonly specSha256: `sha256:${string}`;
}

function canonicalOutput(output: UserFixtureOutputSpec): Record<string, unknown> {
  return "amountSats" in output
    ? { descriptor: output.descriptor, amountSats: output.amountSats }
    : { descriptor: output.descriptor, remainder: true };
}

function specificationHash(spec: UserFixtureSpec): `sha256:${string}` {
  const canonical = JSON.stringify({
    id: spec.id,
    inputs: spec.inputs.map((input) => ({
      descriptor: input.descriptor,
      sequence: input.sequence,
    })),
    outputs: spec.outputs.map(canonicalOutput),
    feeSats: spec.feeSats,
    locktime: spec.locktime,
    transactionVersion: spec.transactionVersion,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function compileUserFixturePlan(spec: UserFixtureSpec): CompiledUserFixturePlan {
  if (BUILT_IN_FIXTURE_IDS.has(spec.id)) {
    throw new TypeError(`Custom fixture ${spec.id} collides with a built-in fixture id`);
  }
  const remainderCount = spec.outputs.filter((output) => "remainder" in output).length;
  if (remainderCount !== 1) {
    throw new TypeError(`Custom fixture ${spec.id} must contain exactly one remainder output`);
  }
  const inputDescriptorIds = spec.inputs.map(({ descriptor }) => descriptor);
  return {
    id: spec.id,
    inputDescriptorIds,
    outputDescriptorIds: spec.outputs.map(({ descriptor }) => descriptor),
    scriptTypes: inputDescriptorIds.map(
      (descriptor) => FIXTURE_DESCRIPTOR_SCRIPT_TYPES[descriptor],
    ),
    sequences: spec.inputs.map(({ sequence }) => sequence),
    locktime: spec.locktime,
    transactionVersion: spec.transactionVersion,
    feeSats: spec.feeSats,
    outputAmounts: spec.outputs.map((output) =>
      "amountSats" in output ? output.amountSats : null,
    ),
    specSha256: specificationHash(spec),
  };
}

export function compileUserFixturePlans(
  specs: readonly UserFixtureSpec[],
): readonly CompiledUserFixturePlan[] {
  return [...specs]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(compileUserFixturePlan);
}
