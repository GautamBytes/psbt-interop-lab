# Future Work

PSBT Interop Lab already provides a working interoperability matrix, external adapter enrollment,
deterministic custom suites, bounded differential fuzzing with regression promotion, official
BIP370 vectors, and field-level diagnoses. Future work should be driven by real wallet and library
maintainers using those foundations.

## Broader Compatibility

- Add adapters for more wallet projects, physical-device HWI drivers, and implementation languages.
- Expand PSBTv2 coverage beyond the current constructor, P2WPKH, Taproot roundtrip, and 2-of-3
  workflows.
- Add Taproot script-path threshold leaves and carefully selected legacy profiles beyond the
  deterministic single-leaf signing and finalization paths.
- Add a second independent MuSig2 implementation so the current two-process state-machine proof
  becomes a cross-library cryptographic interoperability proof.
- Add executable workflows for Silent Payments, proof-of-reserves, generic signed message, and
  DNSSEC proof PSBT fields. The diagnostic registry names these fields, but compatibility scenarios
  still need fixtures and adapter support.
- Let bundled signers authorize specific custom public fixture templates through the existing
  `user-fixture-template-v1` capability boundary.

## Better Diagnostics

- Publish recurring baseline comparisons as versioned regression reports.
- Add corpus scheduling and coverage feedback while preserving deterministic, bounded campaigns.
- Attach promoted parser regressions to upstream-ready issue templates with implementation metadata.

## Developer Integration

- Extend the shipped TypeScript adapter initializer with a Rust template after independent wallet
  maintainers validate the generated-project workflow.
- Validate the reusable action against additional independent wallet repositories and native
  adapter implementations.
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
