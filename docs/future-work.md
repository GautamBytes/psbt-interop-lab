# Future Work

PSBT Interop Lab already provides a working interoperability matrix, external adapter enrollment,
deterministic custom suites, official BIP370 vectors, and field-level diagnoses. Future work should
be driven by real wallet and library maintainers using those foundations.

## Broader Compatibility

- Add adapters for more wallet projects, hardware-signing bridges, and implementation languages.
- Add PSBTv2 cross-implementation handoffs and signing only after at least two mature native
  implementations expose compatible APIs; 0.4.0 validates the official vectors with one parser.
- Add Taproot script-path signing/finalization and carefully selected legacy profiles. Current
  Taproot script-path coverage proves parse and roundtrip preservation.
- Let bundled signers authorize specific custom public fixture templates through the existing
  `user-fixture-template-v1` capability boundary.

## Better Diagnostics

- Compare compatibility results across implementation versions to expose new regressions.
- Add stable machine-readable diagnostic codes for downstream CI annotations and dashboards.
- Improve minimization of failing custom scenarios into smaller reproducible test cases.

## Developer Integration

- Provide straightforward CI integration for wallet and library repositories.
- Publish versioned compatibility reports and reusable test vectors.
- Publish optional prebuilt adapter images after demand justifies the release and attestation work.
- Produce reproducible upstream bug reports and contribute practical fixes where maintainers want
  them.

## Safety Boundary

The lab may recommend where an implementation should preserve or regenerate metadata, but it will
not silently rewrite a recipient, amount, signature, or other transaction intent. Missing signing
material cannot be reconstructed safely, and automatic PSBT mutation could hide a wallet bug or an
attack. The project remains regtest-only test infrastructure, not a wallet, signer, or transaction
repair service.
