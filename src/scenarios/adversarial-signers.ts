import { FIXTURE_PUBLIC_KEYS, type FixtureScriptType } from "../core/fixture-profiles.js";
import type { PsbtFixture } from "../core/fixtures.js";
import { requireUniquePsbtEntryValue } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";
import type { ScenarioExecutionContext } from "./context.js";
import type { ScenarioAssertionEvidence, ScenarioDefinition } from "./definition.js";

export interface AdversarialFixtureSet {
  readonly p2wpkh: PsbtFixture;
  readonly p2pkh: PsbtFixture;
  readonly nested: PsbtFixture;
  readonly p2wsh: PsbtFixture;
  readonly taproot: PsbtFixture;
}

export interface AdversarialSignerCase {
  readonly id: string;
  readonly description: string;
  readonly fixture: PsbtFixture;
  readonly mutatedPsbt: string;
}

function replaceInputValue(
  fixture: PsbtFixture,
  keyType: number,
  mutate: (value: Buffer) => void,
): string {
  const location = { kind: "input", index: 0 } as const;
  const value = requireUniquePsbtEntryValue(fixture.initialPsbt, location, keyType);
  mutate(value);
  return applyPsbtMutations(fixture.initialPsbt, [
    {
      kind: "replace-value",
      location,
      keyType,
      valueHex: value.toString("hex"),
    },
  ]);
}

function toggleByte(value: Buffer, offset: number): void {
  if (value.byteLength === 0) throw new Error("Cannot mutate an empty PSBT field");
  const normalized = offset < 0 ? value.byteLength + offset : offset;
  if (normalized < 0 || normalized >= value.byteLength) {
    throw new RangeError("PSBT field mutation offset is out of range");
  }
  value[normalized] = (value[normalized] as number) ^ 0x01;
}

export function adversarialSignerCases(
  fixtures: AdversarialFixtureSet,
): readonly AdversarialSignerCase[] {
  const derivation: PsbtMutationRecipe = {
    kind: "set-entry",
    location: { kind: "input", index: 0 },
    keyType: 0x06,
    keyDataHex: FIXTURE_PUBLIC_KEYS.scalar1,
    valueHex: "deadbeef01000080",
  };
  return [
    {
      id: "wrong-witness-amount",
      description: "witness UTXO amount differs from the authorized fixture",
      fixture: fixtures.p2wpkh,
      mutatedPsbt: replaceInputValue(fixtures.p2wpkh, 0x01, (value) => toggleByte(value, 0)),
    },
    {
      id: "wrong-witness-script-pubkey",
      description: "witness UTXO scriptPubKey differs from the authorized fixture",
      fixture: fixtures.p2wpkh,
      mutatedPsbt: replaceInputValue(fixtures.p2wpkh, 0x01, (value) => toggleByte(value, -1)),
    },
    {
      id: "wrong-non-witness-transaction",
      description: "non-witness previous transaction does not match the outpoint",
      fixture: fixtures.p2pkh,
      mutatedPsbt: replaceInputValue(fixtures.p2pkh, 0x00, (value) =>
        toggleByte(value, Math.max(0, value.byteLength - 5)),
      ),
    },
    {
      id: "redeem-script-mismatch",
      description: "nested redeem script does not match the funding script",
      fixture: fixtures.nested,
      mutatedPsbt: replaceInputValue(fixtures.nested, 0x04, (value) => toggleByte(value, -1)),
    },
    {
      id: "witness-script-mismatch",
      description: "witness script does not match the funding script",
      fixture: fixtures.p2wsh,
      mutatedPsbt: replaceInputValue(fixtures.p2wsh, 0x05, (value) => toggleByte(value, -1)),
    },
    {
      id: "derivation-mismatch",
      description: "BIP32 derivation metadata points outside the fixture key origin",
      fixture: fixtures.p2wpkh,
      mutatedPsbt: applyPsbtMutations(fixtures.p2wpkh.initialPsbt, [derivation]),
    },
    {
      id: "taproot-internal-key-mismatch",
      description: "Taproot internal key differs from the authorized fixture",
      fixture: fixtures.taproot,
      mutatedPsbt: applyPsbtMutations(fixtures.taproot.initialPsbt, [
        {
          kind: "replace-value",
          location: { kind: "input", index: 0 },
          keyType: 0x17,
          valueHex: FIXTURE_PUBLIC_KEYS.scalar2.slice(2),
        },
      ]),
    },
    {
      id: "taproot-merkle-root-mismatch",
      description: "Taproot Merkle root is incompatible with a key-path-only fixture",
      fixture: fixtures.taproot,
      mutatedPsbt: applyPsbtMutations(fixtures.taproot.initialPsbt, [
        {
          kind: "set-entry",
          location: { kind: "input", index: 0 },
          keyType: 0x18,
          valueHex: "11".repeat(32),
        },
      ]),
    },
  ];
}

const REQUIRED_SCRIPT_TYPES = [
  "p2pkh",
  "p2wpkh",
  "p2sh-p2wsh",
  "p2wsh",
  "p2tr-keypath",
] as const satisfies readonly FixtureScriptType[];

export function createAdversarialSignerScenario(
  fixtures: AdversarialFixtureSet,
  adapter: string,
): ScenarioDefinition<ScenarioExecutionContext> {
  return {
    id: `adversarial-signer-inputs-${adapter}`,
    title: `Adversarial signer inputs through ${adapter}`,
    category: "signer-safety",
    summary:
      "Requires clean signer refusal for UTXO, script, derivation, and Taproot commitment mismatches.",
    requirements: [
      {
        adapter,
        operations: ["sign"],
        roles: ["signer"],
        psbtVersions: [0],
        scriptTypes: REQUIRED_SCRIPT_TYPES,
        features: ["fixture-commitment-sha256", "adversarial-signer-inputs-v1"],
      },
    ],
    async run(context) {
      const cases = adversarialSignerCases(fixtures);
      const assertions: ScenarioAssertionEvidence[] = [];
      for (const testCase of cases) {
        const response = await context.request(adapter, "sign", {
          psbt: testCase.mutatedPsbt,
          network: "regtest",
          fixtureId: testCase.fixture.id,
        });
        const rejected = response.status === "rejected";
        assertions.push({
          name: testCase.id,
          passed: rejected,
          likelyImplementation: adapter,
          summary: rejected
            ? `${adapter} rejected ${testCase.description} as ${response.error.class}`
            : `${adapter} returned ${response.status} for ${testCase.description}`,
        });
      }
      return {
        summary: `Checked ${cases.length} adversarial signer inputs through ${adapter}.`,
        assertions,
      };
    },
  };
}
