# PSBT Interop Lab

PSBT Interop Lab is a local developer tool for finding interoperability failures between Bitcoin
PSBT implementations. It runs deterministic PSBT workflows through real libraries, checks every
handoff semantically, asks Bitcoin Core to finalize and policy-check completed transactions, and
writes replayable compatibility reports.

The current suite integrates Bitcoin Core 31.1, rust-bitcoin 0.32.102, btcsuite PSBT 1.2.0,
bitcoinjs-lib 7.0.1, BDK Wallet 3.1.0, and rust-psbt's PSBTv2 0.3.0 parser. A frozen bdkpython
2.3.1 adapter remains as a real regression specimen. Everything runs on regtest; the tool never
broadcasts and has no mainnet mode.

## Quick Start

Requirements:

- Docker Desktop or Docker Engine with Compose
- Node.js 22 or 24
- On ARM hosts, Docker must support `linux/amd64` emulation for the frozen BDK 2.3.1 specimen

```bash
npm install --global psbt-interop-lab@0.4.0
psbt-lab doctor
psbt-lab self-test
psbt-lab matrix
```

The first matrix run builds checksum- and digest-pinned images. Later runs can reuse them:

```bash
psbt-lab matrix --no-build
```

List the executable scenarios or replay a completed run:

```bash
psbt-lab list
psbt-lab replay artifacts/<run-id>
```

Stop the local regtest node when finished:

```bash
psbt-lab stop
```

To work from a source checkout instead, install pnpm 10.30.2, run
`pnpm install --frozen-lockfile`, and replace `psbt-lab` above with `node dist/cli.js` after
`pnpm build`.

## External Adapters

Wallet and library maintainers can point the CLI at their own local JSONL adapter without editing
the built-in matrix:

```bash
psbt-lab adapter check ./adapters.json
psbt-lab adapter check ./adapters.json --json
psbt-lab matrix --adapter-manifest ./adapters.json
```

The command validates the strict manifest, process transport, self-reported implementation
identity, capabilities, valid and malformed native-parser behavior, and semantic roundtrip
preservation. It executes the configured command directly with `shell: false`; the
manifest must therefore be treated as trusted local code. See [the adapter guide](docs/adapters.md)
and the bundled [manifest schema](src/conformance/adapter-manifest.schema.json).

The matrix keeps all 24 bundled scenarios and appends native-parse and semantic-roundtrip cells for
each external adapter across P2WPKH, nested P2SH-P2WPKH, P2WSH, Taproot key-path, and Taproot
script-path fixtures. It also appends signing handoffs when the adapter declares the matching
signer capabilities and the `fixture-commitment-sha256` safety feature.

## Custom Suites

Maintainers can describe deterministic regtest fixtures and checked handoff steps without changing
the lab's source:

```bash
psbt-lab matrix --suite-manifest examples/custom-suite.json
```

The manifest can select fixed public script templates, transaction outputs, fee, locktime,
sequences, and adapter order. It cannot supply shell commands, descriptors, private keys, raw PSBTs,
or arbitrary adapter payloads. The bundled adapters can roundtrip custom fixtures. Custom signing
is capability-gated and runs only when an adapter explicitly advertises
`user-fixture-template-v1` in addition to the normal fixture-commitment protection. See the
[example](examples/custom-suite.json) and
[schema](src/custom/suite-manifest.schema.json).

## Current Coverage

The suite currently runs 24 scenarios:

- Core-created P2WPKH, P2WSH, and Taproot key-path signing handoffs through rust-bitcoin,
  btcsuite, bitcoinjs-lib, and current BDK Wallet
- Nested P2SH-P2WPKH and Taproot script-path roundtrip matrices through four current libraries
- All 14 valid and 21 invalid official BIP370 vectors through a pinned native PSBTv2 parser
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

Run `psbt-lab self-test` to prove the detectors catch deliberate proprietary and unknown-field
loss, output-amount mutation, sequence mutation, and signature removal.

## Reports

Each run creates a private directory under `artifacts/<run-id>/` containing:

- `manifest.json`: machine-readable identities, outcomes, assertions, and checkpoint hashes
- `report.json`: redacted machine-readable compatibility results
- `report.md`: readable scenario and assertion summary
- `report.html`: self-contained static compatibility report with no scripts or network requests
- Compatibility findings: implementation-specific behavior that completed safely but diverged from
  the expected PSBT rules
- `checkpoints/**/*.psbt`: canonical PSBT states at important handoffs
- `checkpoints/**/*.facts.json`: bounded field facts and hashes

Raw PSBTs are stored only in checkpoint files with local mode `0600`; artifact directories use
`0700`. Reports redact PSBTs, WIFs, common BIP32/SLIP-132 extended private keys, mnemonics, seed
phrases, and labeled password or secret values. Replay verifies every checkpoint's canonical base64
and SHA256 against the manifest and stored facts. It does not authenticate a mutable artifact
directory controlled by the same host.

## Safety Boundary

This is test infrastructure, not a wallet or signer:

- Only bounded, suite-generated regtest fixtures are accepted; arbitrary PSBT input is not exposed.
- Signers require a run-scoped SHA256 commitment to the exact unsigned transaction.
- The only private keys are deterministic Bitcoin scalars one and two, public test values with no
  economic value.
- Core requires version 31.1, zero peers, and disabled networking; RPC binds to host loopback.
- Adapter containers have no network, read-only roots, dropped capabilities, memory/process limits,
  and `no-new-privileges`.
- Adapter identity fields are compatibility self-reports, not cryptographic image attestation.

Read [SECURITY.md](SECURITY.md) and the
[threat model](psbt-interop-lab-threat-model.md) before extending the signing surface.

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
