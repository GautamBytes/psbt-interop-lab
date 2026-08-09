# Changelog

All notable changes to PSBT Interop Lab are recorded here.

## [Unreleased]

## [0.10.0] - 2026-08-09

### Added

- Complete BIP375 field validation plus all 19 valid and 22 invalid official vectors through an
  independent reference validator and the native rust-psbt Silent Payment implementation.
- A bounded BIP375 Silent Payment sender workflow that derives and independently validates the
  BIP374 DLEQ proof and BIP352 output script, signs and finalizes the pinned official fixture on
  regtest, confirms the extracted transaction identity with Bitcoin Core, and rejects mainnet or
  transaction-intent mutations before signing.
- An advanced BIP375 sender workflow covering global multi-input aggregation, per-input shares,
  multiple recipients, labels with ordinary change, and deterministic repeated-recipient ordering
  across five SHA256-pinned official fixtures. The report also proves five stable invalid-vector
  classifications, independently checks output scripts and partial-signature fields, and states
  when an upstream fixture cannot be finalized by its supplied keys.
- A bounded BIP376 receiver-spend workflow that preserves spend fields through a PSBTv2 handoff,
  derives and verifies the Taproot output key, signs and finalizes natively, removes spent signing
  material, rejects wrong-network and wrong-tweak inputs, and passes Bitcoin Core regtest policy.

### Changed

- The npm package, reusable Action, generated adapter defaults, website, and documentation now
  identify version 0.10.0 and the complete 52-scenario matrix.
- The release walkthrough now uses a fresh complete-matrix artifact and calls out the exact
  difference between Core transaction validation and Core policy acceptance for upstream fixtures.

### Fixed

- Silent Payment workflow reports now retain signed and finalized PSBT checkpoints and require
  explicit finalization evidence instead of allowing a missing artifact to appear successful.
- The basic BIP375 workflow now reports Core policy as unavailable when its official external
  parent transaction is absent from isolated regtest, while still proving finalization, parsing,
  and transaction identity.

### Security

- Updated the website dependency graph, tightened its content-security policy, moved the initial
  theme bootstrap out of inline markup, and added browser-level security smoke coverage.

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
