# v0.7 P0 Interoperability Expansion Design

## Goal

Make PSBT Interop Lab v0.7 useful in a wallet project's CI while expanding the
proof surface for the two largest protocol gaps: PSBTv2 construction and
locktime semantics, and complete official BIP371 parser conformance.

## Scope

This branch delivers four P0 outcomes:

1. A repository-local composite GitHub Action that checks an external adapter,
   runs its generated compatibility matrix, writes JUnit and SARIF reports, and
   uploads the normal replayable artifacts.
2. A separately packaged wallet-style adapter example that uses the public
   adapter protocol from a consumer package, not private project imports.
3. A PSBTv2 constructor operation implemented by the native rust-psbt-v2
   adapter, with executable scenarios for add/remove/seal behavior,
   modifiability enforcement, sequence updates, and BIP370 locktime selection.
4. The complete official BIP371 valid and invalid parser corpus, plus a
   PSBTv2 Taproot roundtrip handoff between rust-psbt-v2 and libwally.

The adapter wire protocol remains `psbt-lab.adapter/0.2`. The change is
backward compatible because operations and roles are capability-negotiated;
existing adapters can continue to advertise their current subsets.

## Non-Goals

- No hosted service, browser UI, or remote adapter execution.
- No private-key handling in the GitHub Action.
- No Taproot signing implementation in rust-psbt-v2 0.3.0, whose signer API
  explicitly does not support Taproot.
- No fork or unreviewed pull request to an unrelated wallet repository. The
  consumer example proves the integration contract locally; a real external
  repository can adopt the same action after the contract is released.
- No general transaction builder DSL. The constructor payload exposes only
  the fields required by BIP370 construction and locktime rules.

## CI Adoption Surface

### Report options

`run`, `matrix`, and `baseline` gain:

```text
--junit <path>  Write a JUnit XML report
--sarif <path>  Write a SARIF 2.1.0 report
```

Paths are resolved from the caller's current directory. Parent directories are
created as needed. The normal artifact bundle remains authoritative and is
always produced.

JUnit contains one test case per scenario. Failed scenarios become failures;
unsupported and skipped scenarios become skipped test cases. SARIF contains
one result for each scenario finding and each failed assertion, with stable
rule identifiers and scenario/adapter metadata. Sensitive text is passed
through the existing report redaction boundary before serialization.

### Composite action

The root `action.yml` accepts:

```yaml
adapter-manifest: required
artifacts: psbt-interop-artifacts
package-spec: psbt-interop-lab@0.7
junit: psbt-interop-junit.xml
sarif: psbt-interop.sarif
build: "true"
upload-artifacts: "true"
```

The action installs Node 24, installs the selected package into an
action-owned temporary directory, runs `adapter check`, then runs `matrix`
with the manifest and report paths. It never executes shell text supplied by
the adapter manifest; command arguments are passed as individual array
elements. The manifest remains a trusted-local-input boundary as documented
by the project.

`package-spec` defaults to the v0.7 release line but is overrideable so this
repository can self-test a packed tarball before publication.

### Wallet consumer example

`examples/wallet-ci-adapter` is an independent npm package with its own lock
file. It uses a maintained Bitcoin PSBT package and implements only
`hello`, `native-parse`, and `roundtrip`. Its manifest invokes the adapter as
an external process. CI installs the example independently, checks the
manifest, and runs the generated external compatibility matrix through the
same public CLI surface consumers use.

## Constructor Contract

The new operation is `construct`; the new role is `constructor`. The
rust-psbt-v2 adapter advertises both `constructor` and the existing `updater`
role.

All successful `construct` responses contain:

```json
{
  "psbt": "<base64>",
  "psbtVersion": 2,
  "inputs": 1,
  "outputs": 1,
  "transactionModifiableFlags": 3,
  "locktime": 0,
  "locktimeType": "none"
}
```

`locktimeType` is `height` for values from 1 through 499999999, `time` for
values at or above 500000000, and `none` only when the selected locktime is
zero.

### Create

```json
{
  "action": "create",
  "inputsModifiable": true,
  "outputsModifiable": true,
  "sighashSingle": false,
  "transactionVersion": 2,
  "fallbackLocktime": 0
}
```

All fields after `action` are optional and use the shown defaults.
`transactionVersion` must be an integer at least 2. `fallbackLocktime` is an
unsigned 32-bit integer.

### Add input

```json
{
  "action": "add-input",
  "psbt": "<base64>",
  "previousTxid": "<64 lowercase hex characters in display order>",
  "outputIndex": 0,
  "sequence": 4294967294,
  "requiredHeightLocktime": 200,
  "requiredTimeLocktime": 500000200
}
```

`sequence` and both locktime fields are optional. Height locktime must be in
`1..499999999`; time locktime must be in `500000000..4294967295`. Both may be
present on one input. The adapter rejects an addition that conflicts with the
existing locktime domain.

### Add output

```json
{
  "action": "add-output",
  "psbt": "<base64>",
  "amountSats": 50000,
  "scriptHex": "00140000000000000000000000000000000000000000"
}
```

`amountSats` must be a positive safe integer no greater than 2100000000000000.
`scriptHex` must be canonical lowercase even-length hex and no more than
10000 bytes.

### Remove and update

```json
{ "action": "remove-input", "psbt": "<base64>", "index": 0 }
{ "action": "remove-output", "psbt": "<base64>", "index": 0 }
{ "action": "set-sequence", "psbt": "<base64>", "index": 0, "sequence": 1 }
```

Add/remove actions require their corresponding modifiable flag. Removing a
map decrements the matching global count. Indexes must exist.

### Seal

```json
{ "action": "seal", "psbt": "<base64>", "scope": "inputs" }
{ "action": "seal", "psbt": "<base64>", "scope": "outputs" }
{ "action": "seal", "psbt": "<base64>", "scope": "all" }
```

Sealing clears the requested modifiable bits. Subsequent add/remove requests
for a sealed scope are rejected with `psbt.not_modifiable`.

Malformed payloads are rejected as `protocol.invalid_payload`. Invalid PSBTs
are rejected as `psbt.parse_failed`; incompatible locktimes as
`psbt.locktime_conflict`; invalid indexes as `psbt.index_out_of_bounds`.

## Protocol Proofs

`psbtv2-constructor-workflow` creates a PSBT, adds two inputs and two outputs,
removes one of each, updates sequence, verifies global counts and required
maps after every transition, seals both scopes, and proves later mutations are
rejected.

`psbtv2-locktime-workflow` proves:

- fallback locktime when inputs have no requirements;
- maximum compatible height locktime;
- maximum compatible time locktime;
- height preference when every constrained input permits both domains;
- rejection when one input is height-only and another is time-only.

These scenarios require no Bitcoin Core fixture and run only against the
rust-psbt-v2 adapter.

## BIP371 Proofs

The source is the deployed canonical BIP371 document in the bitcoin/bips
repository. The vendored corpus contains all 8 invalid and all 6 valid PSBTs,
with source titles and immutable base64 values.

`bip371-official-vectors-<adapter>` sends valid vectors through
`native-parse` and `roundtrip`, and requires invalid vectors to return
`psbt.native_parse_failed`. It is registered for every bundled adapter that
advertises native Taproot parsing without needing signing keys.

`psbtv2-taproot-roundtrip-rust-to-libwally` and the reverse direction convert
official valid Taproot PSBTv0 vectors to v2 through libwally, roundtrip them
through both native parsers, convert back to v0, and require the semantic
transition policy to preserve every Taproot field and transaction intent.

## Verification

The branch is complete only after:

- TypeScript unit tests, typecheck, lint, validator freshness, and build pass.
- rust-psbt-v2 unit, protocol, and workflow tests pass with fmt and clippy.
- The wallet consumer installs from its own lock file and passes adapter
  conformance plus its generated matrix.
- A packed npm tarball can drive the composite action's shell entry point.
- Docker E2E passes for constructor, locktime, BIP371, PSBTv2 Taproot, and the
  full proof matrix.

