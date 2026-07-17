# Official Source Ledger

Research and dependency snapshot: 2026-07-17.

This file records the primary sources used to choose protocol behavior, APIs, versions, and pinned
artifacts. Runtime dependencies are also locked in `pnpm-lock.yaml`, `Cargo.lock`, and the hashed
Python requirement.

## PSBT Specifications

- [BIP174: Partially Signed Bitcoin Transaction Format](https://bips.dev/174/) defines PSBT magic,
  key-value maps, minimally encoded CompactSize values, unique complete keys, creator/updater/signer
  roles, and PSBTv0 fields.
- [BIP370: PSBT Version 2](https://bips.dev/370/) defines PSBTv2's global input/output counts and
  per-input/per-output transaction fields. The wire parser validates PSBTv2 and the rejection matrix
  uses the official required-fields vector, while signing scenarios use Core-created PSBTv0. Its
  Constructor rules permit `PSBT_GLOBAL_TX_MODIFIABLE` to be omitted or removed when no further
  inputs or outputs may be added; the semantic roundtrip rule therefore treats omission and an
  explicit zero byte as equivalent, and no other field-presence normalization.
- [BIP371: Taproot Fields for PSBT](https://bips.dev/371/) defines Taproot key, signature, leaf,
  derivation, internal-key, and tree fields. The semantic parser validates their field layouts, and
  active scenarios create, key-path sign, finalize, and policy-check Core-generated P2TR PSBTs;
  script-path fixtures exercise leaf-script, control-block, and internal-key preservation.
- [BIP382](https://bips.dev/382/) defines `wpkh()` output descriptors, including their use inside
  `sh()`, and [BIP386](https://bips.dev/386/) defines `tr()` descriptors. The fixture factory uses
  these forms for nested SegWit and Taproot script-path regtest outputs.

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
  [`getnetworkinfo`](https://bitcoincore.org/en/doc/31.0.0/rpc/network/getnetworkinfo/) documents the
  numeric server `version` used by the runtime contract. Core publishes RPC documentation by major
  release; the runtime patch binary is 31.1.
- `createpsbt`'s `version` parameter is documented as the transaction version, not the PSBT version.
  The suite confirms the resulting wire format is PSBTv0 before continuing.

## Rust Adapter

- [`bitcoin` 0.32.102 documentation](https://docs.rs/bitcoin/0.32.102/bitcoin/) and its
  [PSBT module](https://docs.rs/bitcoin/0.32.102/bitcoin/psbt/) define the native parsing, sighash,
  signature, and PSBT APIs used by the adapter.
- The adapter builds with the official `rust:1.97.0-bookworm` image and a committed `Cargo.lock`.
  `cargo test --locked` runs during the image build.

## Go Adapter

- [`btcsuite/btcutil/psbt` v1.2.0](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil/psbt@v1.2.0)
  provides the parser, updater, signer, finalizer, and extractor APIs used by the Go adapter.
  The native-parser matrix records that this release accepts a second global unsigned-transaction
  key as an unknown global field; BIP174 requires each key to be unique within its map.
- [`btcsuite/btcd/txscript`](https://pkg.go.dev/github.com/btcsuite/btcd/txscript) provides sighash
  calculation and script execution used to independently verify fixture signatures.
- The adapter builds with the official Go 1.26.5 image. The committed `go.mod` and `go.sum` lock its
  dependency graph, and `go test ./...` runs during the image build.

## JavaScript Adapter

- [`bitcoinjs-lib` 7.0.1](https://github.com/bitcoinjs/bitcoinjs-lib/tree/v7.0.1) provides PSBT
  parsing, signing, combining, finalization, and extraction. Its own documentation warns callers to
  verify and test cryptographic behavior; the lab therefore validates signatures independently.
- [`tiny-secp256k1` 2.2.4](https://www.npmjs.com/package/tiny-secp256k1/v/2.2.4) provides the
  secp256k1 operations used by the adapter. `package-lock.json` pins the complete npm graph.

## BDK Regression Adapter

- [`bdk_wallet` 3.1.0](https://docs.rs/bdk_wallet/3.1.0/bdk_wallet/) is the current BDK PSBT
  implementation exercised for P2WPKH, P2WSH, and Taproot key-path signing plus all PSBTv0
  roundtrip profiles. Its committed lockfile pins bitcoin 0.32.102, miniscript 12.3.7, and
  bdk_chain 0.23.3.

- [BDK FFI release v2.3.1](https://github.com/bitcoindevkit/bdk-ffi/releases/tag/v2.3.1) and
  [bdkpython 2.3.1 on PyPI](https://pypi.org/project/bdkpython/2.3.1/) identify the frozen affected
  implementation.
- The exact CPython 3.13 manylinux x86_64 wheel is installed directly with
  `--require-hashes --no-deps`. Its PyPI SHA256 is
  `ba6553eae92f2328cff268ed654d39da04516ebbf8ef9a84d46f99e70ecd2c85`.
  ARM hosts therefore require Docker support for `linux/amd64` emulation when this historical
  specimen is included in the complete matrix.
- [BDK wallet issue #488](https://github.com/bitcoindevkit/bdk_wallet/issues/488) documents the
  `PSBT is missing witness script` failure when finalization encounters an already-finalized input,
  and confirms that Core can finalize the same PSBT. The upstream discussion records the fix in
  rust-miniscript 12.3.7 and bdkpython 3.0.0. The suite keeps 2.3.1 only as a regression specimen.

## PSBTv2 Adapter

- [`psbt-v2` 0.3.0](https://docs.rs/psbt-v2/0.3.0/psbt_v2/) provides the native PSBTv2 parser used
  for the official BIP370 valid and invalid vectors. The adapter pins source revision
  `8ca657c333b6b391f2501e8b31627ccbb6a67f66` and intentionally claims parser/roundtrip support only;
  it does not imply cross-library PSBTv2 signing support.

## Tooling

- [Node.js documentation](https://nodejs.org/docs/latest-v22.x/api/) is the host runtime reference.
  The [`fsPromises.open`](https://nodejs.org/docs/latest-v22.x/api/fs.html#fspromisesopenpath-flags-mode)
  and [`FileHandle`](https://nodejs.org/docs/latest-v22.x/api/fs.html#class-filehandle) references
  define the descriptor-based open, stat, read, and close operations used by bounded replay reads.
  The [file-open constants](https://nodejs.org/docs/latest-v22.x/api/fs.html#file-open-constants)
  reference documents platform-dependent flag exposure, including `O_NOFOLLOW` where available.
- [TypeScript documentation](https://www.typescriptlang.org/docs/) is the compiler and language
  reference. The exact compiler and npm dependency graph are locked by `pnpm-lock.yaml`.
- [Ajv documentation](https://ajv.js.org/) and its
  [standalone validation code](https://ajv.js.org/standalone.html) guide define the build-time JSON
  Schema compiler used to generate runtime validators with no Ajv production dependency.
- [Commander documentation](https://github.com/tj/commander.js#readme) is the primary reference for
  CLI parsing.
- [Vitest documentation](https://vitest.dev/guide/) defines the test-runner behavior used by the
  TypeScript suite.
- [Mermaid 11.16.0](https://www.npmjs.com/package/mermaid/v/11.16.0) and its
  [render API documentation](https://mermaid.js.org/config/usage.html#api-usage) define the
  strict, lazy-loaded architecture diagram renderer used by the project website.
- [Docker Compose documentation](https://docs.docker.com/compose/) is the container orchestration
  reference. Its service reference defines [`read_only`](https://docs.docker.com/reference/compose-file/services/#read_only),
  [`tmpfs`](https://docs.docker.com/reference/compose-file/services/#tmpfs),
  [`cap_drop`](https://docs.docker.com/reference/compose-file/services/#cap_drop),
  [`pids_limit`](https://docs.docker.com/reference/compose-file/services/#pids_limit),
  [`mem_limit`](https://docs.docker.com/reference/compose-file/services/#mem_limit), and
  [`security_opt`](https://docs.docker.com/reference/compose-file/services/#security_opt).
- Docker base images are pinned to the official manifest digests resolved on 2026-07-15: Debian
  bookworm-slim `7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818`,
  Rust 1.97.0 bookworm
  `8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073`, and Python 3.13
  slim-bookworm `9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64`.
- [GitHub Actions checkout v6](https://github.com/actions/checkout),
  [setup-go v6.4.0](https://github.com/actions/setup-go/releases/tag/v6.4.0),
  [setup-node v6](https://github.com/actions/setup-node), and
  [setup-python v6](https://github.com/actions/setup-python), plus
  [pnpm/action-setup v6](https://github.com/pnpm/action-setup), are used by CI. The complete proof
  publishes only redacted reports with
  [upload-artifact v7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1). The
  workflow pins every action to the exact commit behind its reviewed release rather than a mutable
  tag.
- GitHub's workflow references define
  [concurrency cancellation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
  and per-job
  [`timeout-minutes`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes),
  which bound superseded and long-running CI work.
- [OSV](https://osv.dev/) and the official
  [RustSec `cargo-audit`](https://github.com/RustSec/rustsec/tree/main/cargo-audit) scanner are used
  for advisory checks. The npm production graph, frozen Python package, and committed Rust lockfile
  were queried separately.
- The official Go
  [`govulncheck`](https://go.dev/doc/tutorial/govulncheck) tool is pinned at v1.6.0 in CI and checks
  whether known vulnerabilities are reachable from the btcsuite adapter.

Version updates should change this ledger, the relevant lock/pin, and the expected self-reported
adapter compatibility strings in the same pull request.
