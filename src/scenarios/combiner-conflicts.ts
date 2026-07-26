import { FIXTURE_PUBLIC_KEYS, type FixtureScriptType } from "../core/fixture-profiles.js";
import type { PsbtFixture } from "../core/fixtures.js";
import type { AdapterResponse } from "../protocol/types.js";
import { diffPsbtDocuments, extractTransactionIdentity } from "../psbt/diff.js";
import { parsePsbtDocument, requireUniquePsbtEntryValue } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export interface CombinerConflictFixtureSet {
  readonly p2wpkh: PsbtFixture;
  readonly nested: PsbtFixture;
  readonly p2wsh: PsbtFixture;
  readonly taproot: PsbtFixture;
}

export interface CombinerConflictCase {
  readonly id: string;
  readonly description: string;
  readonly fixture: PsbtFixture;
  readonly left: string;
  readonly right: string;
}

export type CombinerConflictClassification =
  | "rejected-conflict"
  | "left-selected"
  | "right-selected"
  | "merged-invalid"
  | "unsupported"
  | "crashed"
  | "timeout";

function conflictingExistingField(
  fixture: PsbtFixture,
  keyType: number,
): readonly [string, string] {
  const location = { kind: "input", index: 0 } as const;
  const value = requireUniquePsbtEntryValue(fixture.initialPsbt, location, keyType);
  value[value.byteLength - 1] = (value[value.byteLength - 1] as number) ^ 0x01;
  return [
    fixture.initialPsbt,
    applyPsbtMutations(fixture.initialPsbt, [
      {
        kind: "replace-value",
        location,
        keyType,
        valueHex: value.toString("hex"),
      },
    ]),
  ];
}

function conflictingInsertedField(
  fixture: PsbtFixture,
  left: PsbtMutationRecipe,
  right: PsbtMutationRecipe,
): readonly [string, string] {
  return [
    applyPsbtMutations(fixture.initialPsbt, [left]),
    applyPsbtMutations(fixture.initialPsbt, [right]),
  ];
}

function conflictCase(
  id: string,
  description: string,
  fixture: PsbtFixture,
  pair: readonly [string, string],
): CombinerConflictCase {
  return { id, description, fixture, left: pair[0], right: pair[1] };
}

export function combinerConflictCases(
  fixtures: CombinerConflictFixtureSet,
): readonly CombinerConflictCase[] {
  const location = { kind: "input", index: 0 } as const;
  return [
    conflictCase(
      "conflicting-witness-utxo",
      "witness UTXO",
      fixtures.p2wpkh,
      conflictingExistingField(fixtures.p2wpkh, 0x01),
    ),
    conflictCase(
      "conflicting-redeem-script",
      "redeem script",
      fixtures.nested,
      conflictingExistingField(fixtures.nested, 0x04),
    ),
    conflictCase(
      "conflicting-witness-script",
      "witness script",
      fixtures.p2wsh,
      conflictingExistingField(fixtures.p2wsh, 0x05),
    ),
    conflictCase(
      "conflicting-sighash-type",
      "sighash type",
      fixtures.p2wpkh,
      conflictingInsertedField(
        fixtures.p2wpkh,
        { kind: "set-entry", location, keyType: 0x03, valueHex: "01000000" },
        { kind: "set-entry", location, keyType: 0x03, valueHex: "02000000" },
      ),
    ),
    conflictCase(
      "conflicting-derivation",
      "BIP32 derivation",
      fixtures.p2wpkh,
      conflictingInsertedField(
        fixtures.p2wpkh,
        {
          kind: "set-entry",
          location,
          keyType: 0x06,
          keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
          valueHex: "deadbeef01000080",
        },
        {
          kind: "set-entry",
          location,
          keyType: 0x06,
          keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
          valueHex: "deadbeef02000080",
        },
      ),
    ),
    conflictCase(
      "conflicting-partial-signature",
      "partial signature",
      fixtures.p2wpkh,
      conflictingInsertedField(
        fixtures.p2wpkh,
        {
          kind: "set-entry",
          location,
          keyType: 0x02,
          keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
          valueHex: "300602010102010101",
        },
        {
          kind: "set-entry",
          location,
          keyType: 0x02,
          keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
          valueHex: "300602010202010101",
        },
      ),
    ),
    conflictCase(
      "conflicting-taproot-signature",
      "Taproot key-path signature",
      fixtures.taproot,
      conflictingInsertedField(
        fixtures.taproot,
        { kind: "set-entry", location, keyType: 0x13, valueHex: "11".repeat(64) },
        { kind: "set-entry", location, keyType: 0x13, valueHex: "22".repeat(64) },
      ),
    ),
  ];
}

function semanticallyEqual(left: string, right: string): boolean {
  const leftDocument = parsePsbtDocument(left);
  const rightDocument = parsePsbtDocument(right);
  const diff = diffPsbtDocuments(leftDocument, rightDocument);
  return (
    diff.added.length === 0 &&
    diff.removed.length === 0 &&
    diff.changed.length === 0 &&
    extractTransactionIdentity(leftDocument).sha256 ===
      extractTransactionIdentity(rightDocument).sha256
  );
}

export function classifyCombinerConflict(
  response: AdapterResponse,
  left: string,
  right: string,
): CombinerConflictClassification {
  if (response.status === "rejected") return "rejected-conflict";
  if (response.status === "unsupported") return "unsupported";
  if (response.status === "crashed") return "crashed";
  if (response.status === "timeout") return "timeout";
  if (response.status !== "ok") return "merged-invalid";
  const combined = response.output["psbt"];
  if (typeof combined !== "string") return "merged-invalid";
  try {
    if (semanticallyEqual(combined, left)) return "left-selected";
    if (semanticallyEqual(combined, right)) return "right-selected";
    return "merged-invalid";
  } catch {
    return "merged-invalid";
  }
}

const CONFLICT_SCRIPT_TYPES = [
  "p2wpkh",
  "p2sh-p2wsh",
  "p2wsh",
  "p2tr-keypath",
] as const satisfies readonly FixtureScriptType[];

export function createCombinerConflictScenario(
  fixtures: CombinerConflictFixtureSet,
  adapter: string,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: `combiner-conflicts-${adapter}`,
    title: `Combiner conflict rejection through ${adapter}`,
    category: "combiner-safety",
    summary:
      "Requires explicit conflict rejection for UTXO, script, sighash, derivation, and signature collisions.",
    requirements: [
      {
        adapter,
        operations: ["combine"],
        roles: ["combiner"],
        psbtVersions: [0],
        scriptTypes: CONFLICT_SCRIPT_TYPES,
        features: ["combiner-conflicts-v1"],
      },
    ],
    async run(context) {
      const cases = combinerConflictCases(fixtures);
      const assertions: ScenarioAssertionEvidence[] = [];
      for (const testCase of cases) {
        const response = await context.request(adapter, "combine", {
          psbts: [testCase.left, testCase.right],
        });
        const classification = classifyCombinerConflict(response, testCase.left, testCase.right);
        assertions.push({
          name: testCase.id,
          passed: classification === "rejected-conflict",
          likelyImplementation: adapter,
          summary: `${adapter} classified conflicting ${testCase.description} as ${classification}`,
        });
      }
      return {
        summary: `Checked ${cases.length} deterministic combiner conflicts through ${adapter}.`,
        assertions,
      };
    },
  };
}
