# Security Model

PSBT Interop Lab processes transaction metadata and invokes signing code, so its boundary is kept
intentionally smaller than a general-purpose wallet tool.

## Supported Use

Use this tool only with its generated regtest fixtures on a development machine. Do not pass it a
mainnet PSBT, import a real seed, reuse the fixture key for funds, expose Core RPC to another host,
or treat a passing result as a security audit of an implementation.

The local runtime assumes one trusted developer, host account, and Docker daemon. GitHub-hosted CI
is a separate boundary for build/test evidence: it has no workflow secrets, read-only repository
permission, ephemeral runners, and runs the complete Docker proof only for main-branch or trusted
manual executions. See [the threat model](psbt-interop-lab-threat-model.md) for the repository-grounded
abuse paths and residual-risk calibration.

## Protected Assets

- Host files outside the chosen artifact directory
- Any real wallet keys or production PSBTs on the host
- Integrity of checkpoint and report data
- Availability of the runner when adapters misbehave

## Controls

### Signing restrictions

The Rust adapter has no generic private-key input. It recognizes only `network=regtest`, one of two
fixture identifiers, the expected scalar-one public key, the expected witness script, matching
funding scripts, and internally consistent full/witness UTXO data. A request outside that policy is
rejected. The scalar-one WIF in the adapter is a widely known test value and must never hold funds.

The fixture identifier is not an authentication credential, and the image does not prove that an
accepted PSBT came from this particular CLI run. Its safety comes from using a public valueless test
key on regtest, not from protecting that key. Do not place real funds on the fixture script.

Bitcoin Core receives only the public descriptor. It does not receive the fixture private key.

### Process isolation

Adapters are started with argument arrays and `shell: false`. Their containers use `--network
none`, a read-only root filesystem, all Linux capabilities dropped, a 64-process limit, a 256 MiB
memory limit, and `no-new-privileges`. Requests have timeouts, 4 MiB line limits, bounded stderr,
strict JSON schemas, and matching request IDs.

The runner compares canonical returned PSBT bytes independently of an adapter's `byteIdentical`
claim. It also pins the adapter's self-reported name, implementation version, source revision,
operations, and PSBTv0 support. A malicious adapter can spoof those expected identity strings and
supply any schema-valid self-reported digest; the runner does not compare a pinned content digest.
These are compatibility assertions and do not attest which image or binary is running. Dockerfile
base digests, downloaded checksums, lockfiles, and dependency hashes improve build reproducibility,
not runtime attestation.

### Bitcoin Core isolation

Core runs only on regtest with `networkactive=0`, `listen=0`, seed discovery disabled, and zero
peers. Compose publishes RPC to `127.0.0.1` only. The bundled credentials are intentionally local
regtest credentials, not secrets. Other containers deliberately attached to the project bridge
could reach Core RPC, so do not attach untrusted containers while the suite is running.

Every Core RPC response ID must exactly match its request, and fixture setup requires Bitcoin Core
numeric version `310100`, regtest, zero peers, and expected suite-generated PSBTv0 structure. Core's
container also has a read-only root, dropped capabilities, a 128-process limit, a 1 GiB memory limit,
and `no-new-privileges`; only its named regtest data volume remains writable, with a bounded temporary
`/tmp` mount.

Core validates returned PSBTs through finalization and policy checks. That does not prove BDK
executed or that later adapter operations preserved the intended unsigned transaction. The residual
false-PASS risk is low only under the trusted-image scope.

### Parsing and artifacts

The TypeScript wire parser enforces canonical base64, PSBT magic, minimal CompactSize values,
unique complete keys, bounded map and entry counts, exact framing, and no trailing bytes. It reports
structure and hashes rather than interpreting signing intent.

Artifact writes use contained paths, private permissions, temporary files, `fsync`, and atomic
rename. Replay rejects absolute and lexically escaping checkpoint paths, non-regular files,
oversized files, malformed PSBTs, SHA256 mismatches, and manifests above 1,000 checkpoints.
Intermediate symlinks remain trusted. Final-component `O_NOFOLLOW` protection applies only where
Node exposes the flag; the descriptor is then used for the regular-file check and read.

Replay reparses each PSBT and verifies its SHA256 against the manifest and stored facts JSON
`sha256`. It does not recompute other stored facts or recorded outcomes and does not rerun adapters.
An actor able to replace the artifact directory can rewrite all values consistently, so replay is
not artifact authentication.

Raw PSBT, script, and UTXO material is excluded from reports. Implementation name, version, source
revision, and self-reported digest metadata are intentionally recorded and protected only by local
file permissions. Those permissions do not protect artifacts from the trusted host account, and
local checkpoints may still contain sensitive transaction metadata.

### GitHub CI

The workflow grants `contents: read`, disables persisted checkout credentials, supplies no secrets,
pins action revisions, uses ephemeral GitHub-hosted runners, sets per-job timeouts, and cancels
superseded work for the same workflow/ref. Pull-request code runs language build/test jobs, but the
complete Docker proof condition allows only main-branch or manual runs. Untrusted build code still has
runner network and compute access until its timeout; GitHub-host isolation and dependency services
remain external trust. These controls mitigate credential, compute, and network abuse. Pull-request
code can alter its own tests and build scripts, so a green run means revision self-consistency, not
independent check integrity.

## Out Of Scope

- Protection from a compromised Docker daemon, kernel, base image, or dependency registry
- Safe handling of arbitrary or adversarial production PSBTs by the native libraries themselves
- Hardware-wallet firmware or USB/HID isolation
- Mainnet signing, transaction broadcast, wallet policy approval, or fee validation for users
- Public APIs, web UIs, uploads, authentication, rate limiting, multi-tenancy, or shared storage
- Cryptographic adapter/image attestation or authentication of a mutable artifact directory
- Consensus proof beyond what the pinned Core binary and `testmempoolaccept` report

Before adding arbitrary input signing, replace the fixture-only adapter with a separately reviewed
policy and key-isolation design. That change should be treated as a new security boundary, not a
small feature.
