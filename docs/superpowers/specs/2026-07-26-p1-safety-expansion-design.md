# P1 Safety Expansion Design

## Decision

Build P1 around one deterministic PSBT mutation framework shared by safety
scenarios, combiner-conflict proofs, parser differential fuzzing, replay
artifacts, and promoted custom regression suites.

This fits the existing architecture better than hard-coded byte edits in each
scenario. The lab already centralizes PSBT parsing, scenario assertions,
adapter capability negotiation, checkpoints, and custom-suite compilation.
A shared mutation model extends those boundaries without introducing a second
runner or report format.

## Safety Boundaries

- Only lab-generated regtest fixtures may be sent to signing adapters.
- Mutations are allowlisted data operations, never executable commands.
- Every mutation carries a deterministic seed and a human-readable recipe.
- Parser fuzzing is bounded to 1-512 cases and defaults to 64.
- The CI corpus uses fixed seeds and parser operations only.
- Promoted suites contain fixture templates and mutation recipes, not private
  keys, arbitrary files, or arbitrary adapter commands.

## Shared Mutation Model

`src/psbt/mutation.ts` owns:

- canonical serialization of an already parsed PSBT document;
- immutable map-entry operations (`set`, `delete`, `replace`, and
  `duplicate`);
- deterministic byte mutations selected by a seeded PRNG;
- stable mutation identifiers and mutation execution records.

`src/psbt/minimize.ts` owns delta debugging over a mutation recipe sequence.
It first removes operations while the differential predicate remains true,
then shrinks replacement values. This makes every reported parser divergence
small enough to inspect and replay.

## Sighash Matrix

The matrix covers ECDSA `ALL`, `NONE`, and `SINGLE`, each with and without
`ANYONECANPAY`. Taproot adds `DEFAULT`; `DEFAULT|ANYONECANPAY` is invalid and
is tested as a signer refusal.

The proof uses two-input, two-output fixtures. For every mode it records which
transaction components are committed, demonstrates that permitted
post-signing changes preserve signature validity, and demonstrates that
committed changes invalidate finalization or policy acceptance. Signing
adapters advertise `sighash-matrix-v1` before receiving a non-default mode.

## Adversarial Signer Inputs

The signer-safety matrix mutates one semantic field at a time:

- witness UTXO amount;
- witness UTXO scriptPubKey;
- non-witness transaction;
- redeem script;
- witness script;
- BIP32 derivation;
- Taproot internal key;
- Taproot Merkle root.

An adapter passes only when it returns a stable `rejected` response and does
not emit a modified PSBT. `crashed`, `timeout`, and silent signing are
failures. An adapter may be skipped only when its negotiated capabilities do
not claim the affected script profile.

## Combiner Conflicts

Paired PSBTs conflict at the same logical key for UTXOs, scripts, sighash
types, derivations, or signatures. Native adapter outcomes are normalized to:

- `rejected-conflict`;
- `left-selected`;
- `right-selected`;
- `merged-invalid`;
- `crashed`;
- `timeout`.

Explicit rejection is the expected safety behavior. Silent left/right
selection and invalid merged output are reported as deterministic failures,
not accepted implementation differences.

## Legacy And Nested Coverage

Add two real fixture profiles:

- P2PKH with the complete `non_witness_utxo` and no requirement for
  `witness_utxo`;
- P2SH-P2WSH 2-of-3 multisig with exact redeem and witness scripts.

The P2PKH flow signs and finalizes a real legacy transaction. The nested
multisig flow signs independent copies, combines signatures, finalizes with
Bitcoin Core, and requires regtest policy acceptance.

## Differential Fuzzing And Promotion

`psbt-lab fuzz` accepts `--seed`, `--cases`, `--adapter`, `--fixture`, and
`--promote`. It compares the native parser result of selected adapters with
the lab parser and with each other. An interesting case is any disagreement
in acceptance or normalized PSBT facts.

The command minimizes interesting recipes and writes the seed, original
recipe, minimized recipe, classifications, and adapter identities to the run
artifacts. `--promote <path>` emits `psbt-lab.suite/0.2`, whose new `mutate`
and `compare-parsers` steps replay the minimized case through the standard
custom-suite runner.

## Verification

Each component is developed test-first. Completion requires:

- all TypeScript unit and scenario tests;
- Rust, JavaScript, Go, and Python adapter tests where touched;
- typecheck, lint, generated-data checks, and package build;
- fixed-seed fuzz determinism and promotion replay;
- focused Docker P1 scenarios followed by the complete proof matrix;
- website tests and build after P1 documentation is reflected there.
