# Future Work

PSBT Interop Lab already provides a working interoperability matrix and field-level transition
checks. Future work will broaden the implementations and workflows it can test, make failures
easier to understand, and help maintainers prevent regressions in CI. Priorities should follow
feedback from wallet and library developers using the released tool.

## Broader Compatibility

- Add adapters for more wallet projects, signing libraries, and implementation languages.
- Let external adapters participate in the complete scenario matrix without repository changes.
- Add executable PSBTv2 workflows and official BIP370 interoperability vectors.
- Expand script coverage to Taproot script-path, nested SegWit, and legacy profiles where useful.
- Support deterministic user-defined fixtures and handoff scenarios for real regtest regressions.

## Better Diagnostics

- Display familiar BIP field names alongside numeric PSBT key types.
- Explain the likely failing implementation and provide safe, evidence-based next steps.
- Add executable scenario replay, while keeping stored artifacts bounded and redacted.
- Compare compatibility results across implementation versions to expose new regressions.

## Developer Integration

- Provide straightforward CI integration for wallet and library repositories.
- Publish versioned compatibility reports and reusable test vectors.
- Continue the matrix when one adapter crashes or times out, while recording that failure clearly.
- Produce reproducible upstream bug reports and contribute practical fixes where maintainers want
  them.

## Safety Boundary

The lab may recommend where an implementation should preserve or regenerate metadata, but it will
not silently rewrite a recipient, amount, signature, or other transaction intent. Missing signing
material cannot be reconstructed safely, and automatic PSBT mutation could hide a wallet bug or an
attack. The project remains regtest-only test infrastructure, not a wallet, signer, or transaction
repair service.
