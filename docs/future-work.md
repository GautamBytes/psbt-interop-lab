# Future Work

PSBT Interop Lab already provides a working interoperability matrix, external adapter enrollment,
deterministic custom suites, official BIP370 vectors, and field-level diagnoses. Future work should
be driven by real wallet and library maintainers using those foundations.

## Broader Compatibility

- Add adapters for more wallet projects, hardware-signing bridges, and implementation languages.
- Expand PSBTv2 coverage beyond the current rust-psbt/libwally P2WPKH and 2-of-3 workflows.
- Add Taproot script-path threshold leaves and carefully selected legacy profiles beyond the
  deterministic single-leaf signing and finalization paths.
- Let bundled signers authorize specific custom public fixture templates through the existing
  `user-fixture-template-v1` capability boundary.

## Better Diagnostics

- Compare compatibility results across implementation versions to expose new regressions.
- Add stable machine-readable diagnostic codes for downstream CI annotations and dashboards.
- Improve minimization of failing custom scenarios into smaller reproducible test cases.

## Developer Integration

- Validate the adapter kit in an independent wallet repository and publish a reusable CI example.
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
