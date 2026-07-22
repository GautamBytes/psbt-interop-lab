# Conformance Trust Foundation Design

**Date:** 2026-07-22
**Branch:** `conformance-trust-foundation`
**Status:** Approved for implementation planning

## Objective

Make every standards-related compatibility claim in PSBT Interop Lab traceable to a stable rule,
an authoritative source, a normative level, and concrete expected-versus-observed evidence. Correct
the BIP371 Taproot finalization and BIP174 empty final-scriptSig classifications without weakening
the transaction-safety invariants.

This branch is deliberately limited to the conformance trust foundation. Version baselines,
scenario minimization, additional adapters, release provenance, external wallet adoption, and
discovery work remain separate follow-up branches because each has its own interfaces and release
risk.

## Architecture

### Typed rule catalog

Add `src/conformance/rules.ts` as the single authored source of protocol and lab-policy metadata.
Each `ConformanceRule` contains:

- a stable lowercase dotted ID that will not include an implementation or version;
- a concise title and category;
- a normative level: `must`, `should`, `may`, `interoperability`, or `house-policy`;
- an authoritative source name, URL, and human-readable section anchor;
- the expected behavior stated in the lab's own words;
- the default report severity, repairability, and confidence.

Initial normative rules cover duplicate PSBT keys, preservation of unknown/proprietary keypairs,
empty final scriptSig omission, and Taproot finalization cleanup. Existing safety classifications
that express lab transition policy use explicit `house-policy` rules rather than being presented as
BIP requirements. Capability gaps, unstructured workflow failures, and Core policy rejection remain
operational classifications and link to documented lab or Core behavior instead of inventing BIP
authority.

`getConformanceRule(id)` is the only lookup entry point. It throws a `TypeError` for an unknown rule
so an internal scenario cannot silently produce an unauditable finding. Compile-time unions prevent
misspelled IDs in TypeScript callers.

### Scenario evidence

Extend `ScenarioFinding` with:

- `ruleId: ConformanceRuleId`;
- `actual: string`, describing the observed behavior without interpretation;
- optional `evidence`, containing bounded, secret-safe evidence tokens.

Expected behavior is never repeated in scenarios; it comes from the catalog. The implementation
and scenario-specific summary remain attached to the finding.

Transition failures continue to originate in the invariant engine. The guidance-to-classification
mapping moves from ad hoc report labels to catalog rule IDs. This preserves current severity
behavior while making clear when the source is a lab safety policy rather than a protocol mandate.

### Report model and rendering

Add the following fields to each `ReportClassification`:

- `ruleId`;
- `normativeLevel`;
- `sourceName`, `sourceUrl`, and `sourceSection`;
- `expected`;
- `actual`, deduplicated when multiple findings produce the same classification.

The existing `id` remains the broad category used by current consumers. New fields are additive, so
the `psbt-lab.run/0.1` artifact envelope and existing report readers remain compatible.

JSON exposes these fields as structured values. Markdown and HTML display the rule ID, normative
level, linked source, expected behavior, observed behavior, and evidence. All dynamic strings remain
redacted and HTML-escaped. Source URLs come only from the fixed catalog.

### Website synchronization

The public walkthrough must not maintain a second interpretation of protocol rules. Add a small
generator that writes the website's serializable conformance metadata from the catalog and a check
mode that fails CI when generated content is stale. Website scenario prose may remain hand-authored,
but normative level, source URL, expected behavior, and classification labels come from generated
data.

The PSBTv2 walkthrough will describe one standards finding: rust-psbt requires or emits an explicit
empty `PSBT_IN_FINAL_SCRIPTSIG` where BIP174 requires the empty field to be omitted. libwally's
rejection of that explicit empty field is expected strict-parser behavior, not a symmetric protocol
divergence.

## Protocol Corrections

### BIP371 Taproot output derivations

Finalization policy will permit removal of `PSBT_OUT_TAP_BIP32_DERIVATION` after a valid
`PSBT_IN_FINAL_SCRIPTWITNESS` has been constructed. This is a general BIP371 rule, not a BDK-specific
allowlist. The BDK Taproot script-path scenario will therefore require a valid exact witness and
successful Core extraction/policy acceptance without emitting the former metadata-loss finding.

Removal before final witness construction, removal during a roundtrip/signing transition, or removal
alongside transaction-intent mutation remains a failure.

### BIP174 empty final scriptSig

The PSBTv2 interop scenario will treat omission of an empty `PSBT_IN_FINAL_SCRIPTSIG` as canonical.
An implementation that requires or emits the explicit empty field receives a high-confidence
standards finding tied to the BIP174 finalizer rule. A strict parser rejecting the explicit empty
encoding passes the malformed/noncanonical probe and is not classified as divergent for doing so.

The valid final witness and extracted transaction still must pass the existing semantic and Bitcoin
Core checks; the classification change does not convert a failed workflow into a pass.

## Data Flow

1. A scenario or invariant records a stable rule ID and observed evidence.
2. `classifyScenario` resolves the ID through the catalog.
3. The classifier combines catalog metadata with implementation, actual behavior, and evidence.
4. Redaction runs over the complete generated report model.
5. JSON, Markdown, and HTML render the same structured classification.
6. The website generator copies the public subset of catalog metadata into its checked-in generated
   module, and CI verifies that it is current.

## Error Handling and Compatibility

- Unknown rule IDs fail immediately with the ID in the error message.
- A normative finding without `actual` evidence is rejected by TypeScript and covered by runtime
  classifier tests.
- Multiple observations of one rule for one implementation merge evidence and actual values without
  duplicating classifications.
- Generic workflow failures retain a low-confidence operational classification when no rule can be
  established; the report must explicitly say it is unclassified rather than guessing.
- Existing category IDs, top-level artifact schemas, CLI commands, and adapter protocols do not
  change in this branch.

## Testing

Implementation follows red-green-refactor cycles.

- Catalog unit tests verify unique IDs, valid HTTPS sources, complete metadata, and immutable lookup.
- Classifier tests verify rule resolution, expected/actual aggregation, normative levels, and unknown
  rule failure.
- Taproot scenario tests first demonstrate that the current BDK-specific finding is wrong, then prove
  removal is allowed only after valid finalization.
- PSBTv2 scenario tests prove rust-psbt receives the BIP174 finding while libwally strict rejection
  does not.
- Report tests assert identical rule metadata in JSON, Markdown, and HTML and retain redaction/XSS
  coverage.
- Website tests assert generated standards data and corrected public copy.
- Full verification runs validator generation checks, formatting/lint, typecheck, all tests, root
  build, website tests, and website build.

## Documentation

Add `docs/conformance-policy.md` explaining:

- the difference between protocol requirements, interoperability guidance, and lab house policy;
- how normative levels are assigned;
- how stable diagnostic rule IDs are versioned;
- how expected and actual evidence should be interpreted;
- how to challenge a classification with an upstream specification citation.

Update architecture, sources, future-work, README, and website documentation to point to this policy.
Remove the completed stable-diagnostic-code item from future work while retaining version comparison
and minimization as future targets.

## Acceptance Criteria

- No current report calls permitted BIP371 Taproot finalization cleanup metadata loss.
- The empty final-scriptSig report attributes the standards divergence to rust-psbt and does not
  classify libwally's strict rejection as an equivalent defect.
- Every generated classification contains a stable rule ID, source, normative level, expected
  behavior, actual behavior, and evidence.
- Website, JSON, Markdown, and HTML present the same normative interpretation.
- Existing adapter and artifact interfaces remain backward compatible.
- All root and website verification commands pass from a clean worktree.
