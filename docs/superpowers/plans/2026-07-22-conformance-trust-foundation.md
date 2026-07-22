# Conformance Trust Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every generated compatibility classification auditable through a stable conformance rule while correcting the BIP371 Taproot-finalization and BIP174 empty-final-scriptSig interpretations.

**Architecture:** A typed catalog in `src/conformance/rules.ts` is the only authored source of normative metadata. Scenarios and transition guidance emit stable rule IDs plus observed behavior; the classifier resolves the catalog and all report formats render the resulting structured model. A generator exposes the public subset to the website so the product copy cannot drift from the engine.

**Tech Stack:** TypeScript 7, Node.js 22/24, Vitest 4, Biome 2, React 19, Vite 7.

## Global Constraints

- Keep `psbt-lab.run/0.1`, CLI commands, adapter protocol, and custom-suite interfaces backward compatible.
- Use stable lowercase dotted rule IDs without implementation names or versions.
- Distinguish `must`, `should`, `may`, `interoperability`, and `house-policy` claims.
- Use only fixed HTTPS source URLs authored in the catalog.
- Preserve existing secret redaction and HTML escaping.
- Apply BIP371 cleanup only after every input has final script data; do not relax roundtrip or signer policy.
- Treat omitted empty `PSBT_IN_FINAL_SCRIPTSIG` as canonical under BIP174.
- Follow a failing-test, minimal-fix, passing-test cycle for every behavior change.

---

### Task 1: Typed Conformance Rule Catalog

**Files:**
- Create: `src/conformance/rules.ts`
- Create: `test/conformance/rules.test.ts`

**Interfaces:**
- Produces: `ConformanceRuleId`, `ConformanceRule`, `CONFORMANCE_RULES`, and `getConformanceRule(id)`.
- Consumed by: scenario findings, report classification, and website metadata generation.

- [ ] **Step 1: Write the catalog contract test**

```ts
import { describe, expect, test } from "vitest";
import { CONFORMANCE_RULES, getConformanceRule } from "../../src/conformance/rules.js";

describe("conformance rule catalog", () => {
  test("publishes complete immutable rules with unique stable IDs", () => {
    const entries = Object.entries(CONFORMANCE_RULES);
    expect(entries.length).toBeGreaterThan(10);
    expect(new Set(entries.map(([id]) => id)).size).toBe(entries.length);
    for (const [id, rule] of entries) {
      expect(id).toMatch(/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/);
      expect(rule.id).toBe(id);
      expect(rule.source.url).toMatch(/^https:\/\//);
      expect(rule.source.section.length).toBeGreaterThan(0);
      expect(rule.expected.length).toBeGreaterThan(0);
      expect(Object.isFrozen(rule)).toBe(true);
    }
  });

  test("fails closed for an unknown runtime rule ID", () => {
    expect(() => getConformanceRule("bip999.unknown" as never)).toThrow(
      "Unknown conformance rule: bip999.unknown",
    );
  });
});
```

- [ ] **Step 2: Run the test and verify RED**

Run: `pnpm test test/conformance/rules.test.ts`

Expected: FAIL because `src/conformance/rules.ts` does not exist.

- [ ] **Step 3: Implement the catalog**

Create the rule types and a frozen catalog containing these IDs:

```ts
export type ConformanceNormativeLevel =
  | "must"
  | "should"
  | "may"
  | "interoperability"
  | "house-policy";

export interface ConformanceRule {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly normativeLevel: ConformanceNormativeLevel;
  readonly source: { readonly name: string; readonly url: string; readonly section: string };
  readonly expected: string;
  readonly severity: "stop" | "review" | "info";
  readonly repairability:
    | "code-or-dependency-change"
    | "investigation-required"
    | "not-a-code-defect";
  readonly confidence: "high" | "medium" | "low";
}

export type ConformanceRuleId = keyof typeof CONFORMANCE_RULES;

export function getConformanceRule(id: ConformanceRuleId): ConformanceRule {
  const rule = CONFORMANCE_RULES[id];
  if (!rule) throw new TypeError(`Unknown conformance rule: ${id}`);
  return rule;
}
```

Build `CONFORMANCE_RULES` with a `freezeRule()` helper and the exact authored metadata below. The
short source names are `BIP174`, `BIP370`, `BIP371`, `Bitcoin Core`, and `PSBT Interop Lab`. BIP
source URLs are the corresponding `bitcoin/bips` mediawiki files; Core policy uses the official
31.0.0 `testmempoolaccept` page; lab rules use the public `docs/conformance-policy.md` URL. No
runtime network lookup is allowed.

| ID | Level | Expected | Severity | Repairability | Confidence |
|---|---|---|---|---|---|
| `bip174.map-keys.unique` | must | Every key in each PSBT map is unique. | review | code-or-dependency-change | high |
| `bip174.unknown-keypairs.preserved` | must | Unknown and proprietary keypairs are preserved when a PSBT is reserialized. | stop | code-or-dependency-change | high |
| `bip174.final-scriptsig.empty-omitted` | must | An empty final scriptSig is represented by omitting PSBT_IN_FINAL_SCRIPTSIG. | review | code-or-dependency-change | high |
| `bip370.valid-vectors.accepted` | must | PSBTv2 documents identified as valid by the official BIP370 vectors are accepted. | review | code-or-dependency-change | high |
| `bip371.output-tap-bip32-derivation.finalization-cleanup` | should | Taproot output derivation fields may be removed only as finalization cleanup after every input has final script data. | review | code-or-dependency-change | high |
| `lab.transaction-intent.unchanged` | house-policy | A handoff does not change the committed unsigned transaction intent. | stop | code-or-dependency-change | high |
| `lab.psbtv2.modifiability.valid` | house-policy | PSBTv2 transaction-modifiable flags only change in ways accepted by the lab transition policy. | stop | code-or-dependency-change | high |
| `lab.signatures.preserved` | house-policy | Existing partial and Taproot signatures are not removed by a handoff. | stop | code-or-dependency-change | high |
| `lab.fields.preserved` | house-policy | Fields required by the selected transition policy are not removed. | stop | code-or-dependency-change | high |
| `lab.fields.immutable` | house-policy | Existing fields required by the selected transition policy are not mutated. | stop | code-or-dependency-change | high |
| `lab.fields.no-unexpected-addition` | house-policy | A handoff adds only fields permitted by the selected transition role. | review | investigation-required | high |
| `core.transaction.policy-accepted` | interoperability | The extracted transaction is accepted by Bitcoin Core regtest mempool policy. | stop | investigation-required | high |
| `lab.workflow.completed` | interoperability | The selected interoperability workflow completes all required assertions. | review | investigation-required | low |
| `lab.capability.declared` | interoperability | An adapter declares every capability required by the selected scenario. | info | not-a-code-defect | high |
| `lab.known-regression.recorded` | interoperability | A historical regression specimen remains reproducible and explicitly identified. | info | not-a-code-defect | high |

- [ ] **Step 4: Run catalog tests and typecheck**

Run: `pnpm test test/conformance/rules.test.ts && pnpm typecheck`

Expected: both commands exit 0.

- [ ] **Step 5: Commit the catalog**

```bash
git add src/conformance/rules.ts test/conformance/rules.test.ts
git commit -m "feat: add typed conformance rule catalog"
```

### Task 2: Rule-Aware Findings and Classifications

**Files:**
- Modify: `src/scenarios/definition.ts`
- Modify: `src/scenarios/engine.ts`
- Modify: `src/scenarios/invalid-inputs.ts`
- Modify: `src/scenarios/bip370.ts`
- Modify: `src/runner/classification.ts`
- Modify: `test/runner/classification.test.ts`
- Modify: `test/scenarios/engine.test.ts`
- Modify: `test/scenarios/definitions.test.ts`
- Modify: `test/scenarios/bip370.test.ts`
- Modify: `test/cli-output.test.ts`

**Interfaces:**
- Consumes: `ConformanceRuleId` and `getConformanceRule` from Task 1.
- Produces: required rule-aware `ScenarioFinding` and additive `ReportClassification` metadata.

- [ ] **Step 1: Write failing classifier expectations**

Add assertions showing a duplicate-key finding resolves to:

```ts
expect(classifications[0]).toMatchObject({
  id: "implementation-divergence",
  ruleId: "bip174.map-keys.unique",
  normativeLevel: "must",
  sourceName: "BIP174",
  expected: "Every key in each PSBT map is unique.",
  actual: ["btcsuite PSBT 1.2.0 accepted a duplicate global key."],
  observedAt: "btcsuite-go",
});
```

Add a test that passes an unknown runtime `ruleId` and expects `classifyScenario` to throw the catalog error.

- [ ] **Step 2: Run the classifier test and verify RED**

Run: `pnpm test test/runner/classification.test.ts`

Expected: FAIL because findings and classifications do not expose rule metadata.

- [ ] **Step 3: Extend findings and classification types**

```ts
export interface ScenarioFinding {
  readonly id: string;
  readonly ruleId: ConformanceRuleId;
  readonly implementation: string;
  readonly summary: string;
  readonly actual: string;
  readonly evidence?: readonly string[];
}

export interface ReportClassification {
  readonly id: ReportClassificationId;
  readonly ruleId: ConformanceRuleId;
  readonly normativeLevel: ConformanceNormativeLevel;
  readonly sourceName: string;
  readonly sourceUrl: string;
  readonly sourceSection: string;
  readonly expected: string;
  readonly actual: readonly string[];
  readonly label: string;
  readonly severity: ReportClassificationSeverity;
  readonly observedAt: string;
  readonly repairability: ReportRepairability;
  readonly confidence: ReportClassificationConfidence;
  readonly summary: string;
  readonly evidence: readonly string[];
}
```

Map each `PsbtSafeGuidanceCode` and operational classification path to a catalog rule ID. Resolve
metadata only through `getConformanceRule`, and merge both `evidence` and `actual` values without
duplicates. Preserve the current broad `ReportClassificationId` values for compatibility.

- [ ] **Step 4: Make every existing finding explicit**

Use these mappings:

```ts
// invalid-inputs.ts
ruleId: "bip174.map-keys.unique",
actual: "btcsuite PSBT 1.2.0 accepted a duplicate global unsigned-transaction key.",

// bip370.ts
ruleId: "bip370.valid-vectors.accepted",
actual: `Native strict parsing rejected valid vectors ${ids}.`,
```

Update test fixtures and `copyFindings` so rule IDs, actual values, and evidence survive scenario
execution unchanged.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run: `pnpm test test/runner/classification.test.ts test/scenarios/engine.test.ts test/scenarios/definitions.test.ts test/scenarios/bip370.test.ts test/cli-output.test.ts`

Expected: all selected tests pass.

- [ ] **Step 6: Commit rule-aware classification**

```bash
git add src/scenarios src/runner/classification.ts test/runner/classification.test.ts test/scenarios test/cli-output.test.ts
git commit -m "feat: make compatibility findings auditable"
```

### Task 3: Correct BIP371 Finalization Semantics

**Files:**
- Modify: `src/psbt/invariants.ts`
- Modify: `src/scenarios/taproot-script-path.ts`
- Modify: `test/psbt/invariants.test.ts`
- Modify: `test/scenarios/taproot-script-path.test.ts`

**Interfaces:**
- Produces: generic finalization permission for output Taproot derivation cleanup after all inputs are finalized.
- Removes: BDK-specific compatibility finding and assertion.

- [ ] **Step 1: Replace the old scenario expectation with the normative behavior**

```ts
test("accepts Taproot output-origin cleanup after valid finalization", async () => {
  // use finalizedPsbtWithoutOutputOrigins fixture
  expect(result).toMatchObject({ outcome: "passed" });
  expect(result?.findings).toBeUndefined();
  expect(result?.assertions).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        name: "bdk-wallet-current-finalization-transition",
        passed: true,
      }),
    ]),
  );
});
```

Add invariant tests proving output key type `0x07` removal fails before finalization and passes under
`finalize` only when every input contains `PSBT_IN_FINAL_SCRIPTSIG` or
`PSBT_IN_FINAL_SCRIPTWITNESS`.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `pnpm test test/psbt/invariants.test.ts test/scenarios/taproot-script-path.test.ts`

Expected: the new cleanup tests fail under the current metadata-loss behavior.

- [ ] **Step 3: Implement protocol-driven cleanup**

Add focused helpers:

```ts
const TAPROOT_OUTPUT_BIP32_DERIVATION = 0x07;

function allInputsFinalized(document: PsbtDocument): boolean {
  return document.maps
    .filter(({ location }) => location.kind === "input")
    .every(({ entries }) => entries.some(({ keyType }) => FINAL_INPUT_TYPES.has(keyType)));
}

function isPermittedFinalizationCleanup(entry: PsbtEntrySummary, after: PsbtDocument): boolean {
  return (
    entry.location.kind === "output" &&
    entry.keyType === TAPROOT_OUTPUT_BIP32_DERIVATION &&
    allInputsFinalized(after)
  );
}
```

Filter only this removal in `finalizeFailures`. Remove the implementation-specific branch and
`ScenarioFinding` import from `taproot-script-path.ts`; always record the normal finalization
transition evidence.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `pnpm test test/psbt/invariants.test.ts test/scenarios/taproot-script-path.test.ts`

Expected: all focused tests pass, including signer/roundtrip rejection coverage.

- [ ] **Step 5: Commit the BIP371 correction**

```bash
git add src/psbt/invariants.ts src/scenarios/taproot-script-path.ts test/psbt/invariants.test.ts test/scenarios/taproot-script-path.test.ts
git commit -m "fix: align Taproot finalization with BIP371"
```

### Task 4: Correct BIP174 Empty Final scriptSig Attribution

**Files:**
- Modify: `src/scenarios/psbtv2-interop.ts`
- Modify: `test/scenarios/psbtv2-interop.test.ts`
- Modify: `test/scenarios/definitions.test.ts`

**Interfaces:**
- Consumes: `bip174.final-scriptsig.empty-omitted`.
- Produces: a rust-psbt-only normative finding; libwally strict rejection becomes expected evidence.

- [ ] **Step 1: Add exported extraction-classification tests**

Exercise the extraction decision through a small exported pure helper:

```ts
expect(classifyFinalScriptSigInterop({
  rustStatus: "rejected",
  wallyStatus: "ok",
  hasWitnessWithoutScriptSig: true,
  hasWitnessWithEmptyScriptSig: false,
})).toEqual({
  kind: "rust-requires-empty-final-scriptsig",
  ruleId: "bip174.final-scriptsig.empty-omitted",
});

expect(classifyFinalScriptSigInterop({
  rustStatus: "ok",
  wallyStatus: "rejected",
  hasWitnessWithoutScriptSig: false,
  hasWitnessWithEmptyScriptSig: true,
})).toEqual({ kind: "wally-rejected-noncanonical-empty-final-scriptsig" });
```

- [ ] **Step 2: Run the test and verify RED**

Run: `pnpm test test/scenarios/psbtv2-interop.test.ts`

Expected: FAIL because the pure classifier and normative attribution do not exist.

- [ ] **Step 3: Implement the split classification**

Return this finding only for rust-psbt's rejection of the canonical omitted form:

```ts
{
  id: "rust-psbt-v2-final-scriptsig-required",
  ruleId: "bip174.final-scriptsig.empty-omitted",
  implementation: RUST,
  summary: "rust-psbt-v2 rejected a finalized SegWit PSBT whose empty final scriptSig was correctly omitted.",
  actual: "The extractor required PSBT_IN_FINAL_SCRIPTSIG to be present with a zero-length value.",
}
```

For libwally rejection of the explicit empty field, retain a passing assertion explaining that it
rejected the noncanonical encoding, return no finding, and continue Core policy validation with the
transaction extracted by rust-psbt.

- [ ] **Step 4: Run PSBTv2 and scenario tests and verify GREEN**

Run: `pnpm test test/scenarios/psbtv2-interop.test.ts test/scenarios/definitions.test.ts`

Expected: all selected tests pass.

- [ ] **Step 5: Commit the BIP174 correction**

```bash
git add src/scenarios/psbtv2-interop.ts test/scenarios/psbtv2-interop.test.ts test/scenarios/definitions.test.ts
git commit -m "fix: attribute empty final scriptSig divergence"
```

### Task 5: Render and Synchronize Auditable Reports

**Files:**
- Modify: `src/runner/report.ts`
- Modify: `test/runner/report.test.ts`
- Create: `scripts/generate-conformance-data.ts`
- Create: `website/src/generated/conformance-rules.ts`
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `website/src/content.ts`
- Modify: `website/src/components/CompatibilityReport.tsx`
- Modify: `website/src/App.test.tsx`

**Interfaces:**
- Consumes: structured `ReportClassification` and `CONFORMANCE_RULES`.
- Produces: matching JSON, Markdown, HTML, and generated website rule metadata.

- [ ] **Step 1: Add failing cross-format report assertions**

Require all formats to contain:

```ts
for (const report of [json, markdown, html]) {
  expect(report).toContain("bip174.unknown-keypairs.preserved");
  expect(report).toContain("BIP174");
  expect(report).toContain("must");
  expect(report).toContain("Unknown and proprietary keypairs are preserved");
  expect(report).toContain("The adapter removed PSBT_IN_PROPRIETARY");
}
expect(html).toContain('href="https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki"');
```

- [ ] **Step 2: Run report tests and verify RED**

Run: `pnpm test test/runner/report.test.ts`

Expected: FAIL because the renderers omit rule metadata.

- [ ] **Step 3: Render the complete structured classification**

Markdown and HTML must label `Rule`, `Normative level`, `Source`, `Expected`, `Observed`, and
`Evidence`. Render the fixed catalog URL as an escaped anchor with `rel="noreferrer"`. Keep the
existing category ID and summary visible for current users.

- [ ] **Step 4: Add generated website conformance data**

The generator writes a deterministic TypeScript module:

```ts
// Generated by scripts/generate-conformance-data.ts. Do not edit.
export const publicConformanceRules = ${JSON.stringify(publicRules, null, 2)} as const;
```

In the generator, define `publicRules` by mapping `Object.values(CONFORMANCE_RULES)` to `id`,
`title`, `normativeLevel`, `source`, and `expected`, then interpolate the deterministic
`JSON.stringify` result shown above. Support `--check` with the same stale-file error pattern as
`generate-validators.ts`. Add root scripts
`generate:conformance-data` and `check:conformance-data`, run generation during `build`, and run check
mode in the TypeScript CI job before lint.

- [ ] **Step 5: Correct and source the website walkthrough**

Import the generated empty-final-scriptSig rule. Replace “equivalent absent or empty encoding” with
the catalog expectation, attribute the finding only to `rust-psbt-v2`, show the stable rule ID and
BIP link, and describe libwally rejection as expected strict parsing.

- [ ] **Step 6: Run report and website tests and verify GREEN**

Run: `pnpm generate:conformance-data && pnpm test test/runner/report.test.ts && npm --prefix website test && npm --prefix website run typecheck`

Expected: all commands exit 0 and check-in data is current.

- [ ] **Step 7: Commit report synchronization**

```bash
git add src/runner/report.ts test/runner/report.test.ts scripts/generate-conformance-data.ts website package.json .github/workflows/ci.yml
git commit -m "feat: render sourced conformance diagnostics"
```

### Task 6: Conformance Policy Documentation and Full Verification

**Files:**
- Create: `docs/conformance-policy.md`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/sources.md`
- Modify: `docs/future-work.md`
- Modify: `website/src/pages/documents.ts`
- Modify: `website/src/components/MarkdownPage.tsx`
- Modify: `website/src/routes.test.tsx`

**Interfaces:**
- Produces: public policy for interpreting and challenging diagnostic rules.

- [ ] **Step 1: Add documentation link tests**

Extend existing website/document tests to require `/docs/conformance-policy` and verify the source
document appears in the documentation registry.

- [ ] **Step 2: Run the focused documentation test and verify RED**

Run: `npm --prefix website test -- --run`

Expected: FAIL because the conformance policy document and route are not registered.

- [ ] **Step 3: Write and link the conformance policy**

Document exact definitions for protocol requirements, interoperability observations, house policy,
normative levels, stable ID compatibility, expected/actual evidence, confidence, and the process for
challenging a rule with an authoritative citation. Link it from README, architecture, sources, and
the website. Remove only the completed stable diagnostic-code line from `docs/future-work.md`.

- [ ] **Step 4: Run fresh complete verification**

Run:

```bash
pnpm check:validators
pnpm check:conformance-data
pnpm lint
pnpm typecheck
pnpm test
pnpm build
npm --prefix website ci --ignore-scripts
npm --prefix website test
npm --prefix website run typecheck
npm --prefix website run build
git diff --check
```

Expected: every command exits 0; root reports zero failing tests; website reports zero failing tests;
both builds complete without errors; `git diff --check` prints nothing.

- [ ] **Step 5: Review acceptance criteria against the diff**

Confirm with `rg` that the obsolete BDK metadata-loss copy and “equivalent absent or empty encoding”
copy are gone, inspect the generated report snapshots, and confirm every `ScenarioFinding` literal
contains `ruleId` and `actual`.

- [ ] **Step 6: Commit documentation and verification updates**

```bash
git add README.md docs website
git commit -m "docs: publish conformance classification policy"
```
