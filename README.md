# PSBT Interop Lab

PSBT Interop Lab is a local developer tool for finding interoperability failures between Bitcoin
PSBT implementations. It runs deterministic PSBT workflows through real libraries, checks every
handoff semantically, asks Bitcoin Core to finalize and policy-check completed transactions, and
writes replayable compatibility reports.

The current suite integrates Bitcoin Core 31.1, rust-bitcoin 0.32.102, btcsuite PSBT 1.2.0,
bitcoinjs-lib 7.0.1, BDK Wallet 3.1.0, rust-psbt's PSBTv2 0.3.0 implementation, and libwally
1.5.4. Version 0.10.1 corrects Core policy-availability reporting and transaction-ID labels for the
Silent Payment workflows introduced in 0.10.0. It retains complete BIP375 field and official-vector
conformance, bounded basic and advanced Silent Payment sender workflows, a BIP376 receiver-spend
workflow, the generated TypeScript adapter project, reproducible upstream issue bundles,
replay-verified compatibility history, a MuSig2 proof crossing independent Rust `musig2` 0.4.1 and
TypeScript Scure 2.2.0 signer processes, and an HWI-compatible JSON process simulator backed by
bitcoinjs-lib. A
frozen bdkpython 2.3.1 adapter remains as a real regression specimen. Everything runs on regtest;
the tool never broadcasts and has no mainnet mode.

Choose the shortest path for your role:

- **Wallet maintainers:** generate an adapter and run the focused [wallet CI path](#external-adapters).
- **Library maintainers:** exercise native parsing and deterministic [differential fuzzing](#differential-fuzzing).
- **Protocol reviewers:** inspect the [complete replayable walkthrough](#walkthrough-verify-the-complete-matrix).

## Quick Start

Requirements:

- Docker Desktop or Docker Engine with Compose
- Node.js 22 or 24

```bash
npx --yes psbt-interop-lab@0.10.1 quickstart
```

`quickstart` is the bounded first-run proof. It checks Node.js, Docker, and Compose, runs five
semantic detector canaries, then completes one real Bitcoin Core -> rust-bitcoin -> Bitcoin Core
signing and finalization handoff. It writes the same replayable reports as the full suite and stops
the local regtest node automatically.

For exhaustive compatibility testing, install the CLI once and run the complete 52-scenario matrix:

```bash
npm install --global psbt-interop-lab@0.10.1
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
psbt-lab history artifacts/<oldest-run-id> artifacts/<middle-run-id> artifacts/<newest-run-id> \
  --output compatibility-history --fail-on-regression
psbt-lab replay artifacts/<run-id>
```

`--scenario` and `--category` validate the requested selection before starting Docker, so a typo
cannot create resources or silently run a different test. `parse-matrix --runtime local` is the
Dockerless parser-only path: the published package currently runs its checksum-pinned bundled
JavaScript parser and reports native adapters without a published local binary as `unsupported`.
Use `matrix` for the complete Core-backed, cross-library signing and finalization proof.
`baseline` records the standard comparison snapshot, and `compare` replay-verifies both artifact
directories before reporting scenario status, finding, adapter-cell, and checkpoint changes.
`history` accepts two or more artifact directories in oldest-to-newest order, replay-verifies every
run, and classifies each adjacent transition as `unchanged`, `regression`, `improvement`, `mixed`,
or `changed`. It can write deterministic `history.json` and `history.md` files into a new output
directory. `--fail-on-regression` exits unsuccessfully only when the newest transition is a
`regression` or `mixed`, so a resolved historical regression does not keep a current CI run red.
Coverage, adapter, capability, checkpoint, skipped-status, and modified-finding differences remain
neutral `changed` signals because they do not establish a safe direction by themselves.
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

## Independent SPDK wallet interoperability (unreleased)

Run the same two-output lifecycle through SPDK's receiver and wallet signer:

```sh
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js run --scenario bip352-spdk-wallet-interop
```

The adapter pins [SPDK's wallet implementation](https://github.com/cygnet3/spdk/tree/a00f9807609b3be16892b7dd671a56db52db88a7)
and disables its network backends. SPDK discovers both recipient outputs from public parent
inputs and receiver keys, then `SpClient` signs their combined spend. The lab bridges those
signatures into the BIP376 child PSBT and retains its funding, destination, fee and signature checks.
The report requires the exact SPDK revision, independent libwally extraction, and Core acceptance
of both ordered and shuffled parent/child packages: 46 assertions and 12 replayable checkpoints.

This proves offline interoperability with SPDK's wallet library for this fixed regtest fixture.
External maintainer adoption, wallet-app integration, chain synchronization, labels and multiple
receiver identities remain future work. The scenario is source-only; published v0.10.1 is unchanged.

## Two-output Silent Payment lifecycle (unreleased)

The source scenario `bip352-multi-output-lifecycle-rust-psbt-v2` pays the same scan-2/spend-1
receiver twice (`k=0` and `k=1`) from two funded P2WPKH inputs, with ordinary change. It runs
both `[recipient, recipient, change]` and `[change, recipient, recipient]` layouts. The sender
permutes the unsigned template before derivation and signing, respecting BIP375 counter order.

```sh
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js run --scenario bip352-multi-output-lifecycle-rust-psbt-v2
```

TypeScript and Rust independently discover both scripts from public sender inputs, without
fixed output positions or sender shares. A single BIP376 child spends both exact outpoints
and values, preserving their total minus the fixed 10,000-sat fee. Swapped tweaks, duplicate
inputs, incorrect outpoints and altered values are rejected. libwally independently extracts
both transactions; Core must reject the child alone and accept the parent/child package in
each layout. Nothing is broadcast. Twelve replayable checkpoints retain both lifecycles.

This is a bounded two-output, one-receiver regtest proof, not multi-recipient wallet or chain
scanning support. It is not included in published v0.10.1 or the historical screenshots.

## Sender → receiver discovery → spend (unreleased)

Run `bip352-sender-receiver-lifecycle-rust-psbt-v2` from source to follow the actual funded
multi-input sender output into a receiver spend:

```sh
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js run --scenario bip352-sender-receiver-lifecycle-rust-psbt-v2
```

The receiver independently derives the BIP352 output from public input witnesses/outpoints
and its scan/spend keys, without using sender shares or recipient metadata. Rust independently
checks that derivation, binds the BIP376 child to the exact parent txid/output/value, and signs.
libwally extracts both transactions. Core must reject the child alone with `missing-inputs`
and accept both together through `testmempoolaccept`, confirming both transaction IDs.
Six checkpoints preserve funding, sender signing/finalization, discovery, and receiver
signing/finalization. Neither transaction is broadcast.

This is a bounded regtest lifecycle with two P2WPKH inputs, one scan-2/spend-1 recipient,
ordinary change, and a fixed 10,000-sat receiver fee. Wrong receiver keys discover nothing;
altered outpoints, tweaks and destinations must be rejected before signing. It is not a
chain scanner, reorg/recovery engine, or general wallet implementation. The published
v0.10.1 package and historical screenshots do not include this scenario.

## Funded multi-input Silent Payment sender (unreleased)

The source checkout includes `bip375-core-funded-multi-input-rust-psbt-v2`: two mature
P2WPKH inputs controlled by different public fixture keys, one fixed Silent Payment recipient,
and ordinary change. It runs global and per-input ECDH shares in both input orders. All four
variants must derive the same recipient script, preserve amounts and change, verify both
signatures against their finalized witnesses, match independent libwally extraction, and pass
Bitcoin Core `testmempoolaccept`. Missing parents fail; nothing is broadcast.

```sh
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js run --scenario bip375-core-funded-multi-input-rust-psbt-v2
node dist/cli.js replay artifacts/<run-id>
node dist/cli.js stop
```

The run retains nine checkpoints (one template and four signed/finalized pairs). It also rejects
changed inputs, recipient amounts, change scripts, supplied recipient/share/proof data, and
mainnet requests. This scenario is not included in the published v0.10.1 package or historical
walkthrough screenshots. It is bounded test infrastructure, not a general wallet or collaborative
multi-party signer.

## Core-funded Silent Payment sender (unreleased)

The source checkout additionally includes a Core-funded BIP375 sender proof. This unreleased
scenario derives a fixed Silent Payment recipient, signs and finalizes a mature regtest input,
compares independent extraction, and requires Bitcoin Core policy acceptance without broadcasting.
Run it from source:

```bash
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js run --scenario bip375-core-funded-sender-rust-psbt-v2
node dist/cli.js replay artifacts/<run-id>
node dist/cli.js stop
```

This requires Docker and the same Node.js versions as the published CLI. The fixed test recipient
uses public scalars 2 (scan) and 1 (spend). This is one P2WPKH input and one Silent Payment output;
it does not establish multi-input sender policy acceptance or receiver discovery.


## Walkthrough: Verify the Complete Matrix

This real v0.10.0 run executes every bundled workflow against the pinned integration stacks and an
isolated Bitcoin Core regtest node:

```bash
psbt-lab matrix
```

The verified run completed all 52 bundled scenarios and replay-verified 101 checkpoints. The
terminal proof keeps every scenario ID visible and records the real run ID, Core height, outcome,
artifact path, and findings. Three known native-library compatibility findings remain visible while
their containing scenarios pass only when the lab detects and classifies the expected behavior.

Open `artifacts/<run-id>/report.html` for the complete result, or verify later that the recorded
evidence still matches its manifest:

```bash
psbt-lab replay artifacts/<run-id>
```

![Complete matrix generated report](https://raw.githubusercontent.com/GautamBytes/psbt-interop-lab/be10bae35542aa1adae605dbe1d19c662f8f540d/docs/assets/walkthrough/compatibility-report.png)

The report screenshot comes directly from that run's generated, self-contained HTML artifact. The
capture shows the same 52-scenario outcome from the fresh v0.10.0 run. The report includes
per-request adapter cells, stable conformance rule IDs,
normative levels, authoritative sources, expected-versus-observed behavior, severity,
repairability, confidence, exact evidence, adapter failure cells, and replay-verified artifact
comparison.

![Silent Payment workflow report evidence](https://raw.githubusercontent.com/GautamBytes/psbt-interop-lab/be10bae35542aa1adae605dbe1d19c662f8f540d/docs/assets/walkthrough/silent-payments-report.png)

The Silent Payment capture shows all 41 official BIP375 vectors and the two explicit native-library
compatibility findings. The same run also finalizes the bounded BIP375 sender and confirms its
transaction identity with Core, but its external parent is not present in the isolated regtest
chain, so the lab makes no policy-acceptance claim for that fixture. The Core-funded BIP376 receiver
spend does pass regtest policy.

## External Adapters

Wallet and library maintainers can point the CLI at their own local JSONL adapter without editing
the built-in matrix:

```bash
psbt-lab adapter init ./wallet-adapter --name example-wallet
cd ./wallet-adapter
npm ci
npm test
npm run conformance
```

The initializer generates a pinned TypeScript and bitcoinjs-lib parser adapter, process-level
tests, a conformance manifest, and a GitHub Actions workflow. It only writes a new directory: it
does not install dependencies, initialize Git, execute generated code, or overwrite an existing
path. Use the generated project as a protocol-correct starting point, then replace its parser and
identity with the wallet or library under test.

Existing adapters can be checked directly:

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

The source checkout matrix keeps all 57 bundled scenarios and appends native-parse and semantic-roundtrip cells for
each external adapter across P2WPKH, nested P2SH-P2WPKH, P2WSH, Taproot key-path, and Taproot
script-path fixtures. It also appends signing handoffs when the adapter declares the matching
signer capabilities and the `fixture-commitment-sha256` safety feature.

`--external-only` prepares the same deterministic Core-backed fixtures but skips every bundled
adapter and scenario. This is the focused path for wallet CI. The repository includes an
independently installed [bitcoinjs-lib consumer example](examples/wallet-ci-adapter) and a reusable
GitHub Action:

```yaml
- uses: GautamBytes/psbt-interop-lab@v0.10.1
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
psbt-lab fuzz --runtime local --fixture bip174-minimal-v0 --seed 42 --cases 64 --json
```

The seed reproduces the exact recipe sequence. Each case applies an allowlisted structured-map or
raw-byte mutation, normalizes every parser result as accepted, rejected, unsupported, crashed, or
timed out, and reports structural divergences among accepted parses. Campaigns are capped at 512
cases.

For every candidate accepted by the lab parser, the lab separately assesses the current
transaction projection's signed output amounts against Bitcoin's consensus money range. JSON cases
carry that bounded assessment, while the text summary reports `semantic-invalid=<count>`. This does
not change native parser classifications or make semantic-only cases parser differentials.

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

To investigate a wallet or library parser, enroll its trusted adapter manifest and export the first
minimized divergence as an upstream-ready bundle:

```bash
psbt-lab fuzz --runtime local --adapter-manifest ./wallet-adapter/adapter-manifest.json \
  --fixture bip174-minimal-v0 --seed 42 --cases 64 --issue-bundle parser-issue
psbt-lab parse-matrix --runtime local \
  --adapter-manifest ./wallet-adapter/adapter-manifest.json \
  --suite-manifest parser-issue/regression-suite.json
```

The new destination contains `manifest.json`, `regression-suite.json`, and `issue.md`. The
`psbt-lab.issue-bundle/0.2` manifest records exact negotiated implementation identities, normalized
outcomes, the minimized candidate's separate lab semantic assessment, and SHA256 commitments to the
other two files. The issue draft uses neutral investigation language: the lab does not assign fault
from a differential result. Commands, environment variables, raw diagnostics, and local paths are
excluded. Fuzzing remains limited to the frozen public test fixtures; it does not accept wallet
PSBTs or production transaction data. The destination must not already exist.

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

The source checkout currently runs 57 scenarios (the published v0.10.1 package has 52):

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
  and bitcoinjs-lib, exchanges CSPRNG-generated session-bound public nonces between independent
  Rust `musig2` and TypeScript Scure signers, refuses nonce reuse, verifies both partial signatures,
  aggregates the BIP340 signature, and requires Bitcoin Core policy acceptance
- An HWI-compatible simulator workflow that enumerates a separate JSON-speaking device process,
  checks a fixed regtest BIP84 key origin, proves simulated user cancellation, permits only the
  expected signature mutation, and requires Bitcoin Core finalization and policy acceptance
- All 14 valid and 21 invalid official BIP370 vectors through rust-psbt-v2 and libwally
- All 19 valid and 22 invalid official BIP375 vectors through the lab's independent reference
  validator and the native rust-psbt Silent Payment implementation
- A bounded BIP375 sender workflow that derives and verifies the Silent Payment share, DLEQ proof,
  and output script from an official fixture before signing, finalizing, extracting, and asking
  Core to parse the transaction and confirm its txid. The official fixture's external parent is not
  in the isolated regtest chain, so this workflow does not claim Core policy acceptance
- A funded two-key BIP375 sender comparing global/per-input shares and both input orders, with
  preserved ordinary change, independent extraction, and Core acceptance for every variant.
- A Core-funded BIP375 sender using the committed P2WPKH fixture, independent DLEQ/output
  verification and libwally extraction, mandatory Core policy acceptance, and changed-input,
  supplied-recipient, supplied-proof, and mainnet rejection canaries
- An advanced BIP375 sender workflow over five additional official fixtures covering global
  multi-input aggregation, per-input shares, multiple scan keys, labels with ordinary change, and
  repeated-recipient output ordering. It independently checks returned output scripts and
  partial-signature fields, reports the fixtures' explicit non-finalization boundary, and verifies
  stable classifications for invalid proof, coverage, sighash, script, and order cases
- A bounded BIP376 receiver-spend workflow that preserves the spend key and output tweak through a
  PSBTv2 handoff, derives and verifies the Taproot output key, signs and finalizes natively, removes
  spent signing material, rejects mainnet and wrong-tweak canaries, and requires Core policy acceptance
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
and HTML output. Failures identify familiar BIP174, BIP370, BIP371, and BIP375 field names where
known, attribute the failing handoff, and provide evidence-based next steps without rewriting the
PSBT.
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

Native adapter checks run in CI and during Docker builds. Read the
[contribution guide](CONTRIBUTING.md), [release process](docs/releasing.md),
[the architecture](docs/architecture.md), [future work](docs/future-work.md), and
[official source ledger](docs/sources.md). The project is MIT licensed.
