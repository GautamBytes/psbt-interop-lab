# P1 Safety Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic P1 sighash, adversarial signer, combiner conflict,
legacy/nested signing, and differential fuzzing proofs.

**Architecture:** Extend the existing parser with a canonical mutation layer,
then consume that layer from focused scenario families and the custom-suite
runner. Keep signing commitment-gated and keep fuzzing parser-only, bounded,
seeded, replayable, and promotable.

**Tech Stack:** TypeScript 7, Vitest, Commander, Bitcoin Core regtest,
rust-bitcoin, bitcoinjs-lib, btcsuite, BDK, libwally, Docker Compose.

## Global Constraints

- Branch from current `origin/main`.
- Keep package version at `0.7.0`; versioning remains a separate release task.
- Do not send arbitrary user PSBTs to bundled signing adapters.
- Bound fuzz runs to 512 cases and use 64 cases by default.
- Preserve existing report, replay, and adapter protocol compatibility.

---

### Task 1: Canonical PSBT Mutations

**Files:**
- Create: `src/psbt/mutation.ts`
- Create: `src/psbt/minimize.ts`
- Test: `test/psbt/mutation.test.ts`
- Test: `test/psbt/minimize.test.ts`

**Interfaces:**
- Produces: `applyPsbtMutations(psbt, recipes)`,
  `generateBoundedMutations(psbt, seed, cases)`, and
  `minimizeMutationRecipes(recipes, predicate)`.

- [ ] Write serializer roundtrip and immutable field-operation tests.
- [ ] Run `vitest run test/psbt/mutation.test.ts` and verify the missing-module failure.
- [ ] Implement canonical CompactSize serialization and allowlisted recipes.
- [ ] Run the mutation tests and verify deterministic passing output.
- [ ] Write a failing delta-debugging test with two irrelevant recipes.
- [ ] Implement sequence removal and byte shrinking.
- [ ] Run both focused test files.

### Task 2: Real Legacy And Nested Fixtures

**Files:**
- Modify: `src/core/fixture-profiles.ts`
- Modify: `src/core/fixtures.ts`
- Modify: `src/protocol/types.ts`
- Test: `test/core/fixture-profiles.test.ts`
- Test: `test/core/fixtures.test.ts`

**Interfaces:**
- Produces fixture profiles `p2pkh` and `p2sh-p2wsh-2-of-3`.
- Preserves `PsbtFixture` while allowing either witness or non-witness UTXO
  evidence according to script type.

- [ ] Add failing profile and descriptor assertions.
- [ ] Implement `pkh(...)` and `sh(wsh(multi(...)))` descriptors and script types.
- [ ] Add failing fixture validation tests for legacy previous transactions.
- [ ] Update fixture validation to verify non-witness transaction outpoints and
  nested redeem/witness scripts.
- [ ] Run all core fixture tests.

### Task 3: Sighash Signer Support And Proofs

**Files:**
- Create: `src/scenarios/sighash-matrix.ts`
- Modify: `src/scenarios/proof.ts`
- Modify: `adapters/rust-bitcoin/src/lib.rs`
- Modify: `adapters/bitcoinjs-lib/adapter.mjs`
- Modify: `adapters/bdk-wallet-current/src/lib.rs`
- Test: `test/scenarios/sighash-matrix.test.ts`
- Test: `adapters/rust-bitcoin/tests/protocol.rs`
- Test: `adapters/bitcoinjs-lib/test/adapter.test.mjs`
- Test: `adapters/bdk-wallet-current/tests/protocol.rs`

**Interfaces:**
- Sign requests may include `sighashType` only for commitment-gated fixtures.
- Adapters advertise `sighash-matrix-v1` when supported.
- Produces deterministic ECDSA and Taproot scenario definitions.

- [ ] Add failing adapter tests for every valid sighash byte and invalid
  `DEFAULT|ANYONECANPAY`.
- [ ] Implement explicit sighash parsing and native signing in each touched adapter.
- [ ] Add failing scenario-definition tests for matrix membership and capability requirements.
- [ ] Implement committed/permitted mutation assertions and Core verification.
- [ ] Run focused adapter and scenario tests.

### Task 4: Adversarial Signer Safety

**Files:**
- Create: `src/scenarios/adversarial-signers.ts`
- Modify: `src/scenarios/proof.ts`
- Test: `test/scenarios/adversarial-signers.test.ts`

**Interfaces:**
- Consumes `applyPsbtMutations`.
- Produces one deterministic scenario per semantic mismatch and adapter profile.

- [ ] Write failing tests for all eight mutation classes.
- [ ] Implement exact field mutations and stable refusal assertions.
- [ ] Assert no crash, timeout, or signature-bearing success response can pass.
- [ ] Run focused scenario tests.

### Task 5: Combiner Conflict Classification

**Files:**
- Create: `src/scenarios/combiner-conflicts.ts`
- Modify: `src/runner/classification.ts`
- Modify: `src/scenarios/proof.ts`
- Test: `test/scenarios/combiner-conflicts.test.ts`
- Test: `test/runner/classification.test.ts`

**Interfaces:**
- Produces `CombinerConflictClassification` and paired conflict cases.
- Consumes existing adapter `combine` requests and PSBT field diffing.

- [ ] Write failing classification tests for reject, left/right winner,
  merged-invalid, crash, and timeout.
- [ ] Implement normalized classification.
- [ ] Write failing scenario tests for UTXO, script, sighash, derivation, and
  signature conflicts.
- [ ] Implement paired mutations and require explicit conflict rejection.
- [ ] Run focused classification and scenario tests.

### Task 6: Differential Fuzzer And Suite Promotion

**Files:**
- Create: `src/fuzz/differential.ts`
- Create: `src/fuzz/promotion.ts`
- Modify: `src/cli.ts`
- Modify: `src/custom/manifest.ts`
- Modify: `src/custom/scenarios.ts`
- Modify: `src/custom/suite-manifest.schema.json`
- Modify: `src/protocol/schema-definitions.ts`
- Test: `test/fuzz/differential.test.ts`
- Test: `test/fuzz/promotion.test.ts`
- Modify: `test/custom/manifest.test.ts`
- Modify: `test/custom/scenarios.test.ts`
- Modify: `test/cli-program.test.ts`

**Interfaces:**
- Produces `runDifferentialFuzz(options)` and
  `promoteDifferentialCase(result)`.
- Adds custom steps `mutate` and `compare-parsers` under schema
  `psbt-lab.suite/0.2`.

- [ ] Write failing seeded determinism, bound, and divergence tests.
- [ ] Implement parser comparison and minimization.
- [ ] Write failing promotion-schema and replay tests.
- [ ] Implement safe recipe serialization and custom-step execution.
- [ ] Add the Commander `fuzz` command and validate `1 <= cases <= 512`.
- [ ] Regenerate validators and run focused fuzz/custom/CLI tests.

### Task 7: End-To-End Proofs And Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/adapters.md`
- Modify: `docs/conformance-policy.md`
- Modify: `docs/future-work.md`
- Modify: `website/src/content.ts`
- Modify: `website/src/components/Sections.tsx`
- Modify: `website/src/App.test.tsx`
- Modify: `examples/custom-suite.json`

**Interfaces:**
- Documents only scenarios and commands present in the executable catalog.

- [ ] Run all focused TypeScript and native adapter tests.
- [ ] Run typecheck, lint, generated checks, build, and package smoke tests.
- [ ] Run fixed-seed fuzzing twice and compare promoted suite bytes.
- [ ] Run focused Docker P1 scenarios and the complete proof matrix.
- [ ] Update repository and website content from verified behavior.
- [ ] Run website tests/build and the full TypeScript suite.
- [ ] Review the complete branch diff and commit the implementation.
