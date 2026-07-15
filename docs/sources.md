# Official Source Ledger

Research and dependency snapshot: 2026-07-15.

This file records the primary sources used to choose protocol behavior, APIs, versions, and pinned
artifacts. Runtime dependencies are also locked in `pnpm-lock.yaml`, `Cargo.lock`, and the hashed
Python requirement.

## PSBT Specifications

- [BIP174: Partially Signed Bitcoin Transaction Format](https://bips.dev/174/) defines PSBT magic,
  key-value maps, minimally encoded CompactSize values, unique complete keys, creator/updater/signer
  roles, and PSBTv0 fields.
- [BIP370: PSBT Version 2](https://bips.dev/370/) defines PSBTv2's global input/output counts and
  per-input/per-output transaction fields. The wire parser recognizes its map framing, but the MVP
  proof scenarios intentionally use Core-created PSBTv0.

## Bitcoin Core

- [Bitcoin Core 31.1 downloads](https://bitcoincore.org/bin/bitcoin-core-31.1/) and
  [official SHA256SUMS](https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS) are the binary
  source. The Dockerfile verifies:
  - Linux aarch64: `dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004`
  - Linux x86_64: `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`
- The official 31.0 RPC reference documents
  [`createpsbt`](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/createpsbt/),
  [`utxoupdatepsbt`](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/utxoupdatepsbt/),
  [`finalizepsbt`](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/finalizepsbt/), and
  [`testmempoolaccept`](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/testmempoolaccept/).
  Core publishes RPC documentation by major release; the runtime patch binary is 31.1.
- `createpsbt`'s `version` parameter is documented as the transaction version, not the PSBT version.
  The suite confirms the resulting wire format is PSBTv0 before continuing.

## Rust Adapter

- [`bitcoin` 0.32.101 documentation](https://docs.rs/bitcoin/0.32.101/bitcoin/) and its
  [PSBT module](https://docs.rs/bitcoin/0.32.101/bitcoin/psbt/) define the native parsing, sighash,
  signature, and PSBT APIs used by the adapter.
- The adapter builds with the official `rust:1.97.0-bookworm` image and a committed `Cargo.lock`.
  `cargo test --locked` runs during the image build.

## BDK Regression Adapter

- [BDK FFI release v2.3.1](https://github.com/bitcoindevkit/bdk-ffi/releases/tag/v2.3.1) and
  [bdkpython 2.3.1 on PyPI](https://pypi.org/project/bdkpython/2.3.1/) identify the frozen affected
  implementation.
- The exact CPython 3.13 manylinux x86_64 wheel is installed directly with
  `--require-hashes --no-deps`. Its PyPI SHA256 is
  `ba6553eae92f2328cff268ed654d39da04516ebbf8ef9a84d46f99e70ecd2c85`.
- [BDK wallet issue #488](https://github.com/bitcoindevkit/bdk_wallet/issues/488) documents the
  `PSBT is missing witness script` failure when finalization encounters an already-finalized input,
  and confirms that Core can finalize the same PSBT. The upstream discussion records the fix in
  rust-miniscript 12.3.7 and bdkpython 3.0.0. This MVP keeps 2.3.1 only as a regression specimen.

## Tooling

- [Node.js documentation](https://nodejs.org/docs/latest-v22.x/api/) is the host runtime reference.
- [TypeScript documentation](https://www.typescriptlang.org/docs/) is the compiler and language
  reference. The exact compiler and npm dependency graph are locked by `pnpm-lock.yaml`.
- [Ajv documentation](https://ajv.js.org/) and
  [Commander documentation](https://github.com/tj/commander.js#readme) are the primary references
  for strict JSON Schema validation and CLI parsing respectively.
- [Vitest documentation](https://vitest.dev/guide/) defines the test-runner behavior used by the
  TypeScript suite.
- [Docker Compose documentation](https://docs.docker.com/compose/) is the container orchestration
  reference.
- Docker base images are pinned to the official manifest digests resolved on 2026-07-15: Debian
  bookworm-slim `7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818`,
  Rust 1.97.0 bookworm
  `8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073`, and Python 3.13
  slim-bookworm `9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64`.
- [GitHub Actions checkout v6](https://github.com/actions/checkout),
  [setup-node v6](https://github.com/actions/setup-node), and
  [setup-python v6](https://github.com/actions/setup-python), plus
  [pnpm/action-setup v6](https://github.com/pnpm/action-setup), are used by CI. The workflow pins
  each action to the exact commit behind its reviewed v6 release rather than a mutable tag.
- [OSV](https://osv.dev/) and the official
  [RustSec `cargo-audit`](https://github.com/RustSec/rustsec/tree/main/cargo-audit) scanner are used
  for advisory checks. The npm production graph, frozen Python package, and committed Rust lockfile
  were queried separately.

Version updates should change this ledger, the relevant lock/pin, and the expected adapter identity
in the same pull request.
