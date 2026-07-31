# PSBT Interop Lab

PSBT Interop Lab is a local developer tool for finding interoperability failures between Bitcoin
PSBT implementations. It runs deterministic PSBT workflows through real libraries, checks every
handoff semantically, asks Bitcoin Core to finalize and policy-check completed transactions, and
writes replayable compatibility reports.

The current suite integrates Bitcoin Core 31.1, rust-bitcoin 0.32.102, btcsuite PSBT 1.2.0,
bitcoinjs-lib 7.0.1, BDK Wallet 3.1.0, rust-psbt's PSBTv2 0.3.0 implementation, and libwally
1.5.4. Version 0.8.0 adds two isolated MuSig2 0.4.1 signer processes and an HWI-compatible JSON
process simulator backed by bitcoinjs-lib. A frozen bdkpython
2.3.1 adapter remains as a real regression specimen. Everything runs on regtest; the tool never
broadcasts and has no mainnet mode.

## Quick Start

Requirements:

- Docker Desktop or Docker Engine with Compose
- Node.js 22 or 24

```bash
npx --yes psbt-interop-lab@0.8.0 quickstart
```

`quickstart` is the bounded first-run proof. It checks Node.js, Docker, and Compose, runs five
semantic detector canaries, then completes one real Bitcoin Core -> rust-bitcoin -> Bitcoin Core
signing and finalization handoff. It writes the same replayable reports as the full suite and stops
the local regtest node automatically.

For exhaustive compatibility testing, install the CLI once and run the complete 47-scenario matrix:

```bash
npm install --global psbt-interop-lab@0.8.0
psbt-lab matrix
```

The complete matrix includes the frozen BDK 2.3.1 regression specimen. On ARM hosts, that one
legacy adapter requires Docker support for `linux/amd64` emulation; `quickstart` does not.

The first matrix run builds checksum- and digest-pinned images. Later runs can reuse them:

```bash
psbt-lab matrix --no-build
```

List the executable scenarios, capture a baseline, compare completed runs, or replay evidence:

```bash
psbt-lab list
psbt-lab run --scenario psbtv2-2-of-3-cross-library
psbt-lab run --category taproot-scriptpath
psbt-lab parse-matrix --runtime local
psbt-lab fuzz --runtime local --seed 42 --cases 64
psbt-lab baseline
psbt-lab compare artifacts/<baseline-run-id> artifacts/<candidate-run-id>
psbt-lab replay artifacts/<run-id>
```

`--scenario` and `--category` validate the requested selection before starting Docker, so a typo
cannot create resources or silently run a different test. `parse-matrix --runtime local` is the
Dockerless parser-only path: the published package currently runs its checksum-pinned bundled
JavaScript parser and reports native adapters without a published local binary as `unsupported`.
Use `matrix` for the complete Core-backed, cross-library signing and finalization proof.
`baseline` records the standard comparison snapshot, and `compare` replay-verifies both artifact
directories before reporting scenario status, finding, adapter-cell, and checkpoint changes.
Deterministic checkpoints compare exact wire facts. Entropy-bearing MuSig2 checkpoints explicitly
compare field structure so fresh nonces and signatures do not create false regressions; replay still
verifies the exact SHA256 of every stored PSBT.

Stop the local regtest node when finished:

```bash
psbt-lab stop
```

To work from a source checkout instead, install pnpm 10.30.2, run
`pnpm install --frozen-lockfile`, and replace `psbt-lab` above with `node dist/cli.js` after
`pnpm build`.

## Walkthrough: Verify the Complete Matrix

This real v0.8.0 run executes every bundled workflow against the pinned integration stacks and an
isolated Bitcoin Core regtest node:

```bash
psbt-lab matrix
```

![Complete matrix terminal output](https://raw.githubusercontent.com/GautamBytes/psbt-interop-lab/41732b2e6fd789f8385281e810f13118fb6c83a7/docs/assets/walkthrough/cli-finding-and-replay.png)

The verified run completed all 47 bundled scenarios. The terminal proof keeps every scenario ID
visible and records the real run ID, Core height, outcome, artifact path, and 91 replay-verified
checkpoints. One known btcsuite duplicate-key compatibility finding remains visible while the
scenario passes because the lab correctly detected and classified that behavior.

Open `artifacts/<run-id>/report.html` for the complete result, or verify later that the recorded
evidence still matches its manifest:

```bash
psbt-lab replay artifacts/<run-id>
```

![Complete matrix generated report](https://raw.githubusercontent.com/GautamBytes/psbt-interop-lab/41732b2e6fd789f8385281e810f13118fb6c83a7/docs/assets/walkthrough/compatibility-report.png)

The report screenshot comes directly from that run's generated, self-contained HTML artifact. The
CLI screenshot is a compact rendering of the same report and replay result, with all 47 bundled
scenarios visible. The report includes per-request adapter cells, stable conformance rule IDs,
normative levels, authoritative sources, expected-versus-observed behavior, severity,
repairability, confidence, exact evidence, adapter failure cells, and replay-verified artifact
comparison.

## External Adapters

Wallet and library maintainers can point the CLI at their own local JSONL adapter without editing
the built-in matrix:

```bash
psbt-lab adapter check ./adapters.json
psbt-lab adapter check ./adapters.json --json
psbt-lab matrix --adapter-manifest ./adapters.json
psbt-lab matrix --external-only --adapter-manifest ./adapters.json
```

The command validates the strict manifest, process transport, self-reported implementation
identity, capabilities, valid and malformed native-parser behavior, and semantic roundtrip
preservation. It executes the configured command directly with `shell: false`; the
manifest must therefore be treated as trusted local code. See [the adapter guide](docs/adapters.md)
and the bundled [manifest schema](src/conformance/adapter-manifest.schema.json).

The matrix keeps all 47 bundled scenarios and appends native-parse and semantic-roundtrip cells for
each external adapter across P2WPKH, nested P2SH-P2WPKH, P2WSH, Taproot key-path, and Taproot
script-path fixtures. It also appends signing handoffs when the adapter declares the matching
signer capabilities and the `fixture-commitment-sha256` safety feature.

`--external-only` prepares the same deterministic Core-backed fixtures but skips every bundled
adapter and scenario. This is the focused path for wallet CI. The repository includes an
independently installed [bitcoinjs-lib consumer example](examples/wallet-ci-adapter) and a reusable
GitHub Action:

```yaml
- uses: GautamBytes/psbt-interop-lab@v0.8.0
  with:
    adapter-manifest: ./adapters.json
```

The action checks the adapter, runs its generated matrix, and uploads replayable artifacts plus
JUnit and SARIF reports. The same outputs are available directly:

```bash
psbt-lab matrix --external-only --adapter-manifest ./adapters.json \
  --junit psbt-interop.xml --sarif psbt-interop.sarif
```

## Differential Fuzzing

Run a deterministic, bounded mutation campaign through the lab parser and the available native
parsers without starting Bitcoin Core:

```bash
psbt-lab fuzz --runtime local --fixture minimal --seed 42 --cases 64 --json
```

The seed reproduces the exact recipe sequence. Each case applies an allowlisted structured-map or
raw-byte mutation, normalizes every parser result as accepted, rejected, unsupported, crashed, or
timed out, and reports structural divergences among accepted parses. Campaigns are capped at 512
cases.

When a divergence is found, write a minimized, SHA256-committed custom-suite regression:

```bash
psbt-lab fuzz --runtime local --seed 42 --cases 64 --promote regression-suite.json
psbt-lab parse-matrix --runtime local --suite-manifest regression-suite.json
```

Promotion removes redundant mutations, shrinks the remaining payload where possible, and emits a
`psbt-lab.suite/0.2` parser fixture with each parser's exact minimized classification and, for
accepted parses, normalized version/input/output facts.
`parse-matrix` replays that parser-only suite with the same Dockerless runtime. Core-backed or
signing steps are refused on this path. A checked-in
[parser regression example](examples/parser-regression-suite.json) shows the complete v0.2 shape.

## Custom Suites

Maintainers can describe deterministic regtest fixtures and checked handoff steps without changing
the lab's source:

```bash
psbt-lab matrix --suite-manifest examples/custom-suite.json
```

The manifest can select fixed public script templates, transaction outputs, fee, locktime,
sequences, and adapter order. Suite schema 0.2 can also include SHA256-committed parser fixtures,
allowlisted mutation recipes, and cross-parser classification checks. Parser fixtures never enter a
signing step. The manifest cannot supply shell commands, descriptors, private keys, arbitrary
signing PSBTs, or arbitrary adapter payloads. The bundled adapters can roundtrip custom transaction
fixtures. Custom signing is capability-gated and runs only when an adapter explicitly advertises
`user-fixture-template-v1` in addition to the normal fixture-commitment protection. See the
[example](examples/custom-suite.json) and
[schema](src/custom/suite-manifest.schema.json).

## Current Coverage

The suite currently runs 47 scenarios:

- Core-created P2PKH, P2WPKH, P2WSH, nested P2SH-P2WSH, and Taproot key-path signing handoffs
  through rust-bitcoin, btcsuite, bitcoinjs-lib, and current BDK Wallet
- Nested P2SH-P2WPKH roundtrips plus bidirectional Taproot script-path signing/finalization and
  wrong-leaf/control-block rejection canaries
- ECDSA and Taproot key-path sighash matrices covering ALL, NONE, SINGLE, ANYONECANPAY
  combinations, Taproot DEFAULT, cryptographically measured outpoint/sequence/output mutations,
  and malformed signer requests
- Eight adversarial rust-bitcoin signer probes for wrong UTXOs, scripts, derivations, Taproot
  internal keys, and Merkle roots
- Seven deterministic bitcoinjs-lib combiner-conflict probes across UTXOs, scripts, sighash types,
  derivations, ECDSA signatures, and Taproot signatures
- A BIP373 MuSig2 key-path workflow that preserves ordered participant fields through rust-bitcoin
  and bitcoinjs-lib, exchanges CSPRNG-generated session-bound public nonces between two isolated
  signer processes, refuses nonce reuse, verifies both partial signatures, aggregates the BIP340
  signature, and requires Bitcoin Core policy acceptance
- An HWI-compatible simulator workflow that enumerates a separate JSON-speaking device process,
  checks a fixed regtest BIP84 key origin, proves simulated user cancellation, permits only the
  expected signature mutation, and requires Bitcoin Core finalization and policy acceptance
- All 14 valid and 21 invalid official BIP370 vectors through rust-psbt-v2 and libwally
- Native PSBTv2 construction, input/output removal, sequence updates, scope sealing, and BIP370
  fallback/height/time locktime selection and conflict rejection
- All 6 valid and 11 invalid official BIP371 vectors through rust-bitcoin, btcsuite,
  bitcoinjs-lib, and current BDK Wallet
- Bidirectional PSBTv2 Taproot handoffs across all six valid BIP371 key-path and script-path
  vectors through rust-psbt-v2 and libwally
- Bidirectional PSBTv2 P2WPKH handoffs and cross-library 2-of-3 signing, combining, finalization,
  extraction, conversion, and Bitcoin Core policy acceptance
- Same-input 2-of-3 multisig where Rust and JavaScript sign independent copies, JavaScript
  combines them, and Core finalizes the result
- A four-library BDK to Rust to Go to JavaScript roundtrip and signing chain
- Parallel signing where Rust and Go contribute different inputs before bitcoinjs combines them
- Transaction-intent preservation across multiple outputs, RBF sequence, non-zero locktime,
  explicit sighash type, and BIP32 derivation metadata
- Twenty native-parser cells across four libraries and five malformed or undeclared PSBT cases,
  including a reported btcsuite 1.2.0 duplicate-global-key compatibility finding
- Unknown and BIP174 proprietary fields preserved through four parsers, three signers, exact-union
  combining, Core PSBT finalization, and Core policy acceptance
- BDK issue #488 reproduction after Rust, Go, and JavaScript finalization workflows

Exact-byte equality is recorded, but it is not the main success rule. Libraries may legally reorder
PSBT map entries. The lab instead verifies transaction identity and field-level transition rules for
roundtripping, signing, combining, and finalization. Unsupported capabilities are reported as
unsupported rather than counted as passes.

Known native-library divergences remain explicit compatibility findings in CLI, JSON, Markdown,
and HTML output. Failures identify familiar BIP174, BIP370, and BIP371 field names where known,
attribute the failing handoff, and provide evidence-based next steps without rewriting the PSBT.
The current baseline allows only btcsuite 1.2.0 to either accept or reject the duplicate global key
probe; another parser accepting malformed input, or any parser crashing or timing out, still fails
the scenario.

Each adapter request is also captured as a report cell with adapter ID, operation, request ID,
status, duration, and error detail. Adapter transport failures and malformed responses are recorded
as failed cells, and restartable adapter processes are restarted before later cells continue.

The PSBTv2 baseline now enforces the canonical omission of empty final scriptSig fields and accepts
the official BIP370 vectors with undefined `PSBT_GLOBAL_TX_MODIFIABLE` bits, while transition checks
still require unknown bits to remain unchanged. Completed transactions still have to pass Bitcoin
Core policy on isolated regtest.
The Taproot script-path baseline permits `PSBT_OUT_TAP_BIP32_DERIVATION` cleanup only at the
BIP371 finalization boundary, after every input is final. Earlier removal remains a metadata
preservation failure. The exact committed leaf witness and the extracted transaction must still
pass Bitcoin Core policy.

Run `psbt-lab self-test` to prove the detectors catch deliberate proprietary and unknown-field
loss, output-amount mutation, sequence mutation, and signature removal.

## Reports

Each run creates a private directory under `artifacts/<run-id>/` containing:

- `manifest.json`: machine-readable identities, outcomes, assertions, and checkpoint hashes
- `report.json`: redacted machine-readable compatibility results
- `report.md`: readable scenario and assertion summary
- `report.html`: self-contained static compatibility report with no scripts or network requests
- Optional JUnit XML and SARIF 2.1.0 files selected with `--junit` and `--sarif`
- Compatibility findings: implementation-specific behavior that completed safely but diverged from
  the expected PSBT rules
- `checkpoints/**/*.psbt`: canonical PSBT states at important handoffs
- `checkpoints/**/*.facts.json`: bounded field facts and hashes

Required scenarios that are unsupported remain command failures in both CI formats: JUnit records
them as failed capability checks and SARIF emits `psbt-lab.scenario.unsupported`.

The reports classify non-passing behavior by stable rule ID, normative level, category, severity,
observed implementation boundary, repairability, and confidence. Every classification includes an
authoritative source and section, expected behavior, actual observations, and bounded evidence;
capability gaps and ambiguous implementation divergences are not labeled as confirmed code bugs.
The [conformance classification policy](docs/conformance-policy.md) defines this public diagnostic
contract and how to challenge a classification.

Raw PSBTs are stored only in checkpoint files with local mode `0600`; artifact directories use
`0700`. Reports redact PSBTs, WIFs, common BIP32/SLIP-132 extended private keys, mnemonics, seed
phrases, and labeled password or secret values. Replay verifies every checkpoint's canonical base64
and SHA256 against the manifest and stored facts. It does not authenticate a mutable artifact
directory controlled by the same host.

## Safety Boundary

This is test infrastructure, not a wallet or signer:

- Signing and finalization accept only bounded, suite-generated regtest fixtures; committed custom
  bytes are confined to parser-only regression steps.
- Signers require a run-scoped SHA256 commitment to the exact unsigned transaction.
- The only private keys are deterministic Bitcoin scalars one and two, public test values with no
  economic value.
- Core requires version 31.1, zero peers, and disabled networking; RPC binds to host loopback.
- Adapter containers have no network, read-only roots, dropped capabilities, memory/process limits,
  and `no-new-privileges`.
- Adapter identity fields are compatibility self-reports, not cryptographic image attestation.

Read [SECURITY.md](SECURITY.md) and the
[threat model](psbt-interop-lab-threat-model.md) before extending the signing surface.

## Website

The public project website is a standalone Vite application under [`website/`](website/). Its
dependencies and build output are isolated from the published CLI package.

```bash
cd website
npm install
npm test
npm run build
npm run dev
```

## Development

```bash
pnpm check:validators
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Native adapter checks run in CI and during Docker builds. See
[the architecture](docs/architecture.md), [future work](docs/future-work.md), and
[official source ledger](docs/sources.md). The project is MIT licensed.
