# v0.7 P0 Interoperability Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a consumable wallet CI integration and executable PSBTv2 constructor, locktime, BIP371, and Taproot-v2 proofs to PSBT Interop Lab v0.7.

**Architecture:** Extend the capability-negotiated adapter protocol additively, implement constructor behavior in the native rust-psbt-v2 adapter, and register focused no-Core scenarios around that operation. Add pure JUnit/SARIF serializers at the report boundary, expose them through CLI options, and wrap the public CLI in a composite action tested by an independent consumer package.

**Tech Stack:** TypeScript 7, Node.js 22/24, Commander, Vitest, Rust 1.97, psbt-v2 0.3.0, GitHub composite actions, JUnit XML, SARIF 2.1.0.

## Global Constraints

- Keep package version `0.7.0` and adapter protocol `psbt-lab.adapter/0.2`.
- Preserve backward compatibility through capability negotiation.
- Never include private keys, raw secrets, or unredacted process output in reports.
- Use the official deployed BIP371 vectors from `bitcoin/bips`.
- Write a failing behavioral test before each production-code slice.
- Keep the original dirty checkout untouched; work only on `codex/p0-interop-expansion`.

---

### Task 1: Machine-Readable CI Reports

**Files:**
- Create: `src/runner/ci-reports.ts`
- Create: `test/runner/ci-reports.test.ts`
- Modify: `src/cli.ts`
- Modify: `test/cli-program.test.ts`
- Modify: `test/baseline.test.ts`

**Interfaces:**
- Consumes: `RunManifest` and `redactSensitiveText`.
- Produces: `generateJunitReport(manifest): string`, `generateSarifReport(manifest): string`, and `writeCiReports(manifest, options): Promise<void>`.

- [ ] **Step 1: Add failing serializer tests**

Create representative passed, failed, unsupported, and finding-bearing manifests.
Assert valid XML escaping, one JUnit test case per scenario, skipped entries,
failure text, SARIF `2.1.0`, stable rule IDs, redaction, and result counts.

- [ ] **Step 2: Verify the tests fail**

Run: `pnpm --ignore-workspace vitest run test/runner/ci-reports.test.ts`

Expected: failure because `src/runner/ci-reports.ts` does not exist.

- [ ] **Step 3: Implement pure serializers and atomic report writes**

Use explicit XML escaping and `JSON.stringify` for SARIF. Resolve output paths,
create parent directories with mode `0700`, and write files with mode `0600`.

- [ ] **Step 4: Add failing CLI option tests**

Assert `run`, `matrix`, and `baseline` expose `--junit` and `--sarif`, and that
baseline forwards both paths to `executeProof`.

- [ ] **Step 5: Verify the CLI tests fail**

Run: `pnpm --ignore-workspace vitest run test/cli-program.test.ts test/baseline.test.ts`

Expected: failures for missing options and forwarded values.

- [ ] **Step 6: Wire report options into `executeProof`**

After `runProof`, call `writeCiReports` before setting the process exit code.
The report writer must run for both passed and failed manifests.

- [ ] **Step 7: Verify Task 1**

Run: `pnpm --ignore-workspace vitest run test/runner/ci-reports.test.ts test/cli-program.test.ts test/baseline.test.ts`

Expected: all selected tests pass.

### Task 2: Reusable GitHub Action and Wallet Consumer

**Files:**
- Create: `action.yml`
- Create: `scripts/run-action.mjs`
- Create: `test/action.test.ts`
- Create: `examples/wallet-ci-adapter/package.json`
- Create: `examples/wallet-ci-adapter/package-lock.json`
- Create: `examples/wallet-ci-adapter/adapter.mjs`
- Create: `examples/wallet-ci-adapter/adapter-manifest.json`
- Create: `examples/wallet-ci-adapter/test/adapter.test.mjs`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/adapters.md`
- Modify: `package.json`

**Interfaces:**
- Consumes: released or packed `psbt-interop-lab` package and a trusted adapter manifest.
- Produces: `node scripts/run-action.mjs` entry point and root composite action.

- [ ] **Step 1: Add failing action contract tests**

Parse `action.yml` as text and assert all documented inputs, Node 24 setup,
the script invocation, and artifact upload behavior. Spawn `run-action.mjs`
with a fake CLI and assert argument boundaries and report paths.

- [ ] **Step 2: Verify action tests fail**

Run: `pnpm --ignore-workspace vitest run test/action.test.ts`

Expected: failure because the action files do not exist.

- [ ] **Step 3: Implement the action runner and composite metadata**

The Node runner creates a temporary install directory, installs
`package-spec` with `npm`, invokes `adapter check`, then invokes `matrix` with
the manifest, artifact, JUnit, SARIF, and build arguments. Use `spawn` with an
argument array and inherited stdio.

- [ ] **Step 4: Add the independent wallet adapter tests**

Test `hello`, a valid native parse, valid roundtrip, malformed JSON, invalid
PSBT rejection, and unknown operation behavior by spawning the adapter.

- [ ] **Step 5: Verify the wallet tests fail**

Run: `npm test --prefix examples/wallet-ci-adapter`

Expected: failure until the adapter is implemented.

- [ ] **Step 6: Implement and lock the consumer package**

Use only package-public APIs. Emit one strict JSON response per input line and
enforce the 4 MiB line boundary used by the main protocol.

- [ ] **Step 7: Add CI and documentation**

Install the example with `npm ci`, run its tests, pack the root project, and
drive `scripts/run-action.mjs` with the tarball and example manifest.
Document the five-line action usage and report upload behavior.

- [ ] **Step 8: Verify Task 2**

Run:

```bash
pnpm --ignore-workspace vitest run test/action.test.ts
npm ci --prefix examples/wallet-ci-adapter --ignore-scripts
npm test --prefix examples/wallet-ci-adapter
pnpm --ignore-workspace build
node dist/cli.js adapter check examples/wallet-ci-adapter/adapter-manifest.json
```

Expected: all commands exit zero.

### Task 3: Additive Constructor Capability Contract

**Files:**
- Modify: `src/protocol/types.ts`
- Modify: `src/protocol/schema-definitions.ts`
- Modify: `src/generated/validators.ts`
- Modify: `test/protocol/schema.test.ts`
- Modify: `test/fixtures/fake-adapter.mjs`
- Modify: `docs/adapters.md`

**Interfaces:**
- Produces: adapter operation `construct` and adapter role `constructor`.

- [ ] **Step 1: Add failing schema tests**

Assert `construct` requests validate, `constructor` hello capabilities
validate, malformed operation/role values fail, and operation script type maps
may include `construct`.

- [ ] **Step 2: Verify schema tests fail**

Run: `pnpm --ignore-workspace vitest run test/protocol/schema.test.ts`

Expected: enum validation rejects the new values.

- [ ] **Step 3: Extend protocol constants and schema definitions**

Add `construct` and `constructor` without changing the protocol version.
Regenerate validators with `pnpm --ignore-workspace generate:validators`.

- [ ] **Step 4: Verify Task 3**

Run:

```bash
pnpm --ignore-workspace vitest run test/protocol/schema.test.ts
pnpm --ignore-workspace check:validators
```

Expected: both commands exit zero.

### Task 4: Native PSBTv2 Constructor and Locktime API

**Files:**
- Modify: `adapters/rust-psbt-v2/src/lib.rs`
- Modify: `adapters/rust-psbt-v2/tests/protocol.rs`
- Modify: `adapters/rust-psbt-v2/tests/workflow.rs`

**Interfaces:**
- Consumes: the `construct` payload contract in the design spec.
- Produces: strict constructor responses and stable rejection classes.

- [ ] **Step 1: Add failing Rust protocol tests**

Cover hello advertisement, create defaults, payload unknown fields, numeric
bounds, malformed txid/script, non-v2 PSBTs, and every rejection class.

- [ ] **Step 2: Verify the protocol tests fail**

Run: `cargo test --locked --test protocol construct -- --nocapture`

Expected: failures because `construct` is unsupported.

- [ ] **Step 3: Implement strict payload parsing and response facts**

Use `serde` deny-unknown-fields action structs, `Creator`, `Constructor`,
`Input`, `Output`, and `Updater`. Use checked count mutation for removals and
call `determine_lock_time` before serializing every response.

- [ ] **Step 4: Add failing workflow tests**

Exercise create/add/remove/sequence/seal, fallback locktime, compatible
height/time maxima, height tie preference, and incompatible domains.

- [ ] **Step 5: Verify workflow tests fail for missing behavior**

Run: `cargo test --locked --test workflow construct -- --nocapture`

Expected: focused assertion failures for the missing action transitions.

- [ ] **Step 6: Complete action behavior**

Enforce modifiable flags before mutation, preserve input/output ordering,
reject out-of-range indexes, and map locktime conflicts to
`psbt.locktime_conflict`.

- [ ] **Step 7: Verify Task 4**

Run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Expected: all rust-psbt-v2 checks pass.

### Task 5: Executable Constructor and Locktime Scenarios

**Files:**
- Create: `src/scenarios/psbtv2-constructor.ts`
- Create: `test/scenarios/psbtv2-constructor.test.ts`
- Modify: `src/scenarios/proof.ts`
- Modify: `test/scenarios/definitions.test.ts`
- Modify: `test/scenarios/proof.test.ts`

**Interfaces:**
- Consumes: rust-psbt-v2 `construct`.
- Produces: `createPsbtv2ConstructorScenario()` and `createPsbtv2LocktimeScenario()`.

- [ ] **Step 1: Add failing scenario tests**

Use a deterministic fake execution context to assert request order, payloads,
checkpoint stages, count/map assertions, seal rejection, locktime selection,
and conflict rejection.

- [ ] **Step 2: Verify scenario tests fail**

Run: `pnpm --ignore-workspace vitest run test/scenarios/psbtv2-constructor.test.ts`

Expected: failure because the scenario module does not exist.

- [ ] **Step 3: Implement scenario factories**

Use fixed zero/one txids and standard witness scripts. Parse each returned
PSBT with `parsePsbtDocument` and assert global count fields plus map-level
required fields, not only adapter-reported facts.

- [ ] **Step 4: Add failing registration tests**

Assert both scenarios are listed, require no Core or fixtures, and select only
rust-psbt-v2.

- [ ] **Step 5: Register scenarios and verify Task 5**

Run:

```bash
pnpm --ignore-workspace vitest run test/scenarios/psbtv2-constructor.test.ts test/scenarios/definitions.test.ts test/scenarios/proof.test.ts
```

Expected: all selected tests pass.

### Task 6: Official BIP371 Corpus

**Files:**
- Create: `src/psbt/bip371-vectors.ts`
- Create: `src/scenarios/bip371.ts`
- Create: `test/psbt/bip371-vectors.test.ts`
- Create: `test/scenarios/bip371.test.ts`
- Modify: `src/scenarios/proof.ts`
- Modify: `test/scenarios/definitions.test.ts`
- Modify: `test/scenarios/proof.test.ts`

**Interfaces:**
- Produces: `BIP371_VALID_VECTORS`, `BIP371_INVALID_VECTORS`, and `createBip371VectorScenario`.

- [ ] **Step 1: Add failing vector integrity tests**

Assert 6 valid and 8 invalid unique IDs, canonical base64, PSBT magic,
expected Taproot key types, valid parser acceptance, and invalid parser
rejection.

- [ ] **Step 2: Verify vector tests fail**

Run: `pnpm --ignore-workspace vitest run test/psbt/bip371-vectors.test.ts`

Expected: failure because the vector module does not exist.

- [ ] **Step 3: Vendor the official vectors**

Copy immutable base64 strings and titles from canonical BIP371 and include the
source URL in the generated-file header.

- [ ] **Step 4: Add failing scenario tests**

Verify all valid vectors call native parse and roundtrip, all invalid vectors
call native parse, and the two aggregate assertions report exact failing IDs.

- [ ] **Step 5: Implement and register BIP371 scenarios**

Register supported bundled native parsers in the `taproot-conformance`
category with no Core or fixture dependency.

- [ ] **Step 6: Verify Task 6**

Run:

```bash
pnpm --ignore-workspace vitest run test/psbt/bip371-vectors.test.ts test/scenarios/bip371.test.ts test/scenarios/definitions.test.ts test/scenarios/proof.test.ts
```

Expected: all selected tests pass.

### Task 7: PSBTv2 Taproot Handoff

**Files:**
- Modify: `src/scenarios/psbtv2-interop.ts`
- Modify: `test/scenarios/psbtv2-interop.test.ts`
- Modify: `src/scenarios/proof.ts`
- Modify: `test/scenarios/definitions.test.ts`
- Modify: `test/scenarios/proof.test.ts`

**Interfaces:**
- Produces: two directional PSBTv2 Taproot roundtrip scenarios.

- [ ] **Step 1: Add failing directional scenario tests**

Start from a valid BIP371 vector, assert v0-to-v2 conversion, both native
roundtrips, v2-to-v0 conversion, Taproot field preservation, and unchanged
transaction identity.

- [ ] **Step 2: Verify the tests fail**

Run: `pnpm --ignore-workspace vitest run test/scenarios/psbtv2-interop.test.ts`

Expected: failures for missing Taproot scenario factories.

- [ ] **Step 3: Implement the handoff scenarios**

Use libwally only for version conversion. Use native `roundtrip` for each
direction and the existing transition policy to verify all Taproot maps.

- [ ] **Step 4: Register and verify Task 7**

Run:

```bash
pnpm --ignore-workspace vitest run test/scenarios/psbtv2-interop.test.ts test/scenarios/definitions.test.ts test/scenarios/proof.test.ts
```

Expected: all selected tests pass.

### Task 8: Full Verification and E2E

**Files:**
- Modify as required by verification findings only.

**Interfaces:**
- Produces: release-grade evidence for the complete P0 branch.

- [ ] **Step 1: Run static and unit checks**

```bash
pnpm --ignore-workspace check:validators
pnpm --ignore-workspace check:conformance-data
pnpm --ignore-workspace typecheck
pnpm --ignore-workspace lint
pnpm --ignore-workspace test
pnpm --ignore-workspace build
```

Expected: all commands exit zero.

- [ ] **Step 2: Run adapter checks**

Run Rust fmt, clippy, and tests for rust-psbt-v2, plus the independent wallet
adapter's clean install and tests.

- [ ] **Step 3: Run focused Docker E2E**

```bash
node dist/cli.js run --category psbtv2-constructor --junit artifacts/p0-constructor.xml --sarif artifacts/p0-constructor.sarif
node dist/cli.js run --category taproot-conformance
node dist/cli.js run --category psbtv2-taproot
```

Expected: every selected scenario passes and report files parse.

- [ ] **Step 4: Run the complete Docker proof**

Run: `pnpm --ignore-workspace proof`

Expected: complete active matrix passes, replayable artifacts are written, and
Core is stopped afterward.

- [ ] **Step 5: Review the diff**

Run `git diff --check`, inspect `git diff --stat`, confirm no generated,
temporary, secret, or unrelated files are included, and compare the final
implementation against every design requirement.
