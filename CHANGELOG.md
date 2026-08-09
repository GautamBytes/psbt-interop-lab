# Changelog

All notable changes to PSBT Interop Lab are recorded here.

## [Unreleased]

### Added

- A bounded BIP375 Silent Payment sender workflow that derives and independently validates the
  BIP374 DLEQ proof and BIP352 output script, signs and finalizes the pinned official fixture on
  regtest, and rejects mainnet or transaction-intent mutations before signing.
- An advanced BIP375 sender workflow covering global multi-input aggregation, per-input shares,
  multiple recipients, labels with ordinary change, and deterministic repeated-recipient ordering
  across five SHA256-pinned official fixtures. The report also proves five stable invalid-vector
  classifications, independently checks output scripts and partial-signature fields, and states
  when an upstream fixture cannot be finalized by its supplied keys.

## [0.9.0] - 2026-08-05

### Added

- A TypeScript adapter project initializer that generates a pinned parser adapter, process tests,
  a conformance manifest, and a GitHub Actions workflow without executing generated code.
- Deterministic, SHA256-committed upstream issue bundles for minimized parser divergences, with
  neutral investigation language and replay commands.
- Replay-verified compatibility history reports that classify ordered run transitions and can fail
  CI only when the newest transition is a regression or mixed result.
- A cross-library BIP373 proof using independent Rust and TypeScript MuSig2 signer processes, with
  session-bound nonces, nonce-reuse refusal, partial-signature verification, aggregation, and
  Bitcoin Core policy acceptance.

### Changed

- Generated adapter projects now target the 0.9.0 CLI and pin the reviewed v0.9 release baseline
  for the reusable GitHub Action. Their documentation explains the self-referential lockfile
  integrity exception and how to hydrate the registry SRI value after publication.
- The reusable GitHub Action, CLI version output, SARIF metadata, documentation, and website now
  identify version 0.9.0.

### Safety

- The lab remains regtest-only test infrastructure. It does not broadcast, accept production wallet
  secrets, repair transaction intent, or claim physical-device or production signer security.
