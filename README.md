# PSBT Interop Lab

PSBT Interop Lab is a local developer tool for finding interoperability failures between Bitcoin
PSBT implementations. It runs deterministic PSBT workflows through real libraries, checks every
handoff semantically, asks Bitcoin Core to finalize and policy-check completed transactions, and
writes replayable compatibility reports.

The current suite integrates Bitcoin Core 31.1, rust-bitcoin 0.32.102, btcsuite PSBT 1.2.0,
bitcoinjs-lib 7.0.1, and a frozen bdkpython 2.3.1 regression specimen. Everything runs on regtest;
the tool never broadcasts and has no mainnet mode.

## Quick Start

Requirements:

- Docker Desktop or Docker Engine with Compose
- Node.js 22 or 24
- pnpm 10.30.2

```bash
pnpm install --frozen-lockfile
pnpm build
node dist/cli.js doctor
node dist/cli.js self-test
node dist/cli.js matrix
```

The first matrix run builds checksum- and digest-pinned images. Later runs can reuse them:

```bash
node dist/cli.js matrix --no-build
```

List the executable scenarios or replay a completed run:

```bash
node dist/cli.js list
node dist/cli.js replay artifacts/<run-id>
```

Stop the local regtest node when finished:

```bash
docker compose stop core
```

## Current Coverage

The suite currently runs ten scenarios:

- Core-created P2WSH signing handoffs through rust-bitcoin, btcsuite, and bitcoinjs-lib
- A four-library BDK to Rust to Go to JavaScript roundtrip and signing chain
- Parallel signing where Rust and Go contribute different inputs before bitcoinjs combines them
- Twenty invalid-input cells across four parsers and five malformed or undeclared PSBT cases
- BIP174 proprietary-field preservation in every global, input, and output map
- BDK issue #488 reproduction after Rust, Go, and JavaScript finalization workflows

Exact-byte equality is recorded, but it is not the main success rule. Libraries may legally reorder
PSBT map entries. The lab instead verifies transaction identity and field-level transition rules for
roundtripping, signing, combining, and finalization. Unsupported capabilities are reported as
unsupported rather than counted as passes.

Run `node dist/cli.js self-test` to prove the detectors catch deliberate metadata loss, output-amount
mutation, sequence mutation, and signature removal.

## Reports

Each run creates a private directory under `artifacts/<run-id>/` containing:

- `manifest.json`: machine-readable identities, outcomes, assertions, and checkpoint hashes
- `report.json`: redacted machine-readable compatibility results
- `report.md`: readable scenario and assertion summary
- `report.html`: self-contained static compatibility report with no scripts or network requests
- `checkpoints/**/*.psbt`: canonical PSBT states at important handoffs
- `checkpoints/**/*.facts.json`: bounded field facts and hashes

Raw PSBTs are stored only in checkpoint files with local mode `0600`; artifact directories use
`0700`. Reports redact PSBTs, WIFs, common BIP32/SLIP-132 extended private keys, mnemonics, seed
phrases, and labeled password or secret values. Replay verifies every checkpoint's canonical base64
and SHA256 against the manifest and stored facts. It does not authenticate a mutable artifact
directory controlled by the same host.

## Safety Boundary

This is test infrastructure, not a wallet or signer:

- Only suite-generated regtest fixtures are accepted for signing.
- Signers require a run-scoped SHA256 commitment to the exact unsigned transaction.
- The only private key is Bitcoin scalar one, a public test key with no economic value.
- Core requires version 31.1, zero peers, and disabled networking; RPC binds to host loopback.
- Adapter containers have no network, read-only roots, dropped capabilities, memory/process limits,
  and `no-new-privileges`.
- Adapter identity fields are compatibility self-reports, not cryptographic image attestation.

Read [SECURITY.md](SECURITY.md) and the
[threat model](psbt-interop-lab-threat-model.md) before extending the signing surface.

## Development

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Native adapter checks run in CI and during Docker builds. See
[the architecture](docs/architecture.md) and [official source ledger](docs/sources.md). The project
is MIT licensed.
