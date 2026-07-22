# Conformance Classification Policy

Stable rule IDs make every standards claim auditable. This policy defines how PSBT Interop Lab
turns protocol requirements, implementation observations, and lab safety expectations into
diagnostics that remain consistent across CLI, JSON, Markdown, HTML, and website output.

## Rule Classes

Every diagnostic references one entry in the central conformance rule catalog. A rule records its
stable ID, normative level, authoritative source and section, and expected behavior.

- `must`, `should`, and `may` represent the corresponding normative language in an authoritative
  protocol source. The linked source controls if a summary in the catalog is incomplete.
- `interoperability` identifies behavior that is permitted by a protocol but still creates a
  practical handoff boundary between implementations.
- `house-policy` identifies an operational, safety, or reproducibility requirement imposed by the
  lab. It is not presented as a Bitcoin protocol requirement.

Protocol conformance and interoperability are deliberately separate. A strict parser can be
standards-compliant while exposing an interoperability boundary, and a handoff can complete while
still revealing a standards divergence.

## Diagnostic Contract

Rule IDs are public compatibility identifiers. Existing IDs keep their meaning; wording and source
links may be clarified without changing that meaning. A materially different requirement receives
a new ID. Removing or reinterpreting an ID requires a documented compatibility change.

Each finding records:

- the stable rule ID and normative level;
- the authoritative source, section, and expected behavior;
- the observed implementation boundary and actual behavior;
- bounded evidence that can be reproduced without exposing PSBT secrets;
- severity, repairability, and confidence.

Severity describes impact, not blame. Repairability distinguishes code or dependency changes from
configuration, capability, or upstream protocol decisions. Confidence indicates how directly the
evidence identifies the implementation boundary. A finding must not be called a confirmed library
bug when capability gaps or multiple plausible causes remain.

Findings created by an external adapter or future extension must reference a known catalog rule.
Unexpected operational failures that cannot yet be classified remain ordinary failed assertions;
they are not assigned a fabricated protocol claim.

## Current Clarifications

### Taproot output derivations after finalization

BIP371 permits finalizers to remove `PSBT_OUT_TAP_BIP32_DERIVATION`. The lab therefore accepts that
cleanup after every input is finalized. Removing the field during parsing, roundtripping, signing,
or before all inputs are final remains a preservation failure. BDK Wallet's cleanup at the valid
finalization boundary is not classified as metadata loss.

### Empty final scriptSig

BIP174 requires an empty `PSBT_IN_FINAL_SCRIPTSIG` to be omitted. A PSBT containing an explicit
zero-length value is not treated as equivalent to the canonical absent form. The current PSBTv2
scenario attributes the divergence to rust-psbt requiring the explicit empty field; libwally's
strict rejection of that explicit field is recorded as expected parser behavior.

## Challenging a Classification

A classification may be challenged with an authoritative specification section, official test
vector, implementation documentation, or a minimal reproducible adapter transcript. The challenge
should name the rule ID, quote or precisely identify the relevant source language, and show the
expected and observed PSBT states. If the source changes the meaning of a rule, the catalog,
scenario assertions, generated website data, and report tests must change together.

The catalog is implemented in `src/conformance/rules.ts`; website data is generated from that file
and checked for drift in CI. This policy explains the lab's classification contract but never
overrides the linked protocol sources.
