# Future Work

PSBT Interop Lab already provides a working compatibility matrix, external adapter enrollment,
deterministic custom suites, bounded differential fuzzing, upstream issue bundles, compatibility
history, and an independent MuSig2 proof. Future work will be driven by real wallet and library
maintainers using those foundations, with adoption evidence prioritized over scenario count alone.

## Target 1: Independent wallet adoption

Validate the generated adapter and reusable GitHub Action in wallet repositories outside this
project.

Acceptance criteria:

- Two maintainers run `adapter check` and an external-only matrix in their own CI.
- Each integration uploads replayable artifacts plus JUnit or SARIF output.
- Maintainers document setup friction and the project resolves or records each blocking issue.
- One public case study links the exact workflow, implementation identity, and retained evidence.

## Target 2: Broader native adapter coverage

Add adapters only when an implementation maintainer can review its identity and capability claims.
Candidate areas include wallet projects, physical-device HWI drivers, and another implementation
language.

Acceptance criteria for each adapter:

- The process passes protocol negotiation, valid and malformed native-parse checks, and semantic
  roundtrip preservation.
- CI pins source versions and image inputs by checksum or digest.
- Signing capabilities enforce the fixture commitment and run without network access.
- Unsupported operations remain visible and do not count as passes.

## Target 3: PSBTv2 and field coverage

Expand PSBTv2 beyond the current constructor, P2WPKH, Taproot roundtrip, and 2-of-3 workflows. Add
new field families after fixtures and at least one native implementation are available.

Candidate work:

- Taproot script-path threshold leaves and selected legacy profiles.
- Additional BIP375 sender fixtures plus multi-input and multi-output BIP376 receiver-spend cases.
- Proof-of-reserves, generic signed-message, and DNSSEC proof PSBT fields.
- Capability-gated custom signing for reviewed public fixture templates.

Every new workflow must include a deterministic fixture, a sourced transition rule, a negative
canary, and replay verification.

## Target 4: Diagnostic feedback

Add corpus scheduling and coverage feedback without making campaigns unbounded or
non-reproducible.

Acceptance criteria:

- A seed and fixture reproduce every scheduled mutation.
- Coverage data cannot include PSBT contents, keys, local paths, or environment secrets.
- The scheduler has explicit case and time limits.
- Promoted regressions remain valid custom-suite fixtures.

## Target 5: Release and artifact operations

Automate publication after maintainers validate the manual process in
[the release guide](releasing.md).

Acceptance criteria:

- A release job verifies the tag, package version, clean source tree, tests, and packed file list.
- npm publication uses provenance and short-lived credentials.
- GitHub release assets include checksums tied to the tagged commit.
- Scheduled compatibility-history publication remains opt-in with a documented retention policy.

Prebuilt adapter images remain deferred until users need them and maintainers define an
attestation policy.

## Safety boundary

The lab may explain where an implementation should preserve or regenerate metadata. It will not
rewrite recipients, amounts, signatures, or transaction intent. Missing signing material cannot be
reconstructed safely. The project remains regtest-only test infrastructure, not a wallet, signer,
or transaction repair service.
