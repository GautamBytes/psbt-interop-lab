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

External adapter manifests are also trusted local code-execution configuration. `adapter check`
starts the declared command and arguments with `shell: false`, a bounded timeout, bounded JSONL, and
a minimal inherited environment, but it does not sandbox an arbitrary host executable. Do not run a
manifest received from an untrusted person. Prefer a separately reviewed container command with the
same restrictions as the built-in adapters.

Custom suite manifests are data, not executable configuration. They are limited to 1 MiB, fixed
public script templates, bounded transaction fields, typed handoff operations, and safe IDs. They
cannot provide commands, paths, private keys, arbitrary descriptors, raw PSBTs, or arbitrary
adapter payloads. Custom signing remains disabled unless an adapter explicitly supports the
`user-fixture-template-v1` authorization contract.

## Dependency And Scanner Status

The installed CLI has one production dependency, Commander. Ajv is development-only: it compiles
the protocol and manifest JSON Schemas into checked-in standalone validators, and CI verifies that
the generated runtime code is current and contains no Ajv import or `require` call. The release
tarball smoke test installs without lifecycle scripts and confirms that Ajv is absent.

The btcsuite adapter pins `golang.org/x/crypto` v0.52.0 and its required
`golang.org/x/sys` v0.45.0. CI runs the official `govulncheck` v1.6.0 against the adapter. On
2026-07-16, `npm audit --omit=dev` reported zero vulnerabilities and `govulncheck` reported zero
reachable or imported-package vulnerabilities.

Some package scanners inspect every bundled Dockerfile and adapter lockfile as if it were part of
the Node.js runtime. They may therefore report native code, install scripts, network or shell
access, changing transitive ownership, or module-level advisories. Those capabilities are expected
in a source-distributed interoperability lab that builds Rust, Go, Python, JavaScript, and Bitcoin
Core containers. A capability alert is not evidence that the CLI executes that dependency during
installation. Review reachable vulnerabilities and the controls in this document rather than
treating aggregate capability counts as runtime findings.

## Protected Assets

- Host files outside the chosen artifact directory
- Any real wallet keys or production PSBTs on the host
- Integrity of checkpoint and report data
- Availability of the runner when adapters misbehave

## Controls

### Signing restrictions

The Rust, Go, JavaScript, and current BDK adapters have no generic private-key input. They recognize only
`network=regtest`, declared suite fixture identifiers, run-scoped unsigned-transaction commitments,
expected public keys and scripts, and internally consistent full/witness UTXO data. Each operation
also enforces the exact fixture profile and supported script type. A request outside that policy is
rejected.

The adapters contain only deterministic private scalars one and two. These are widely known public
test values used for single-key fixtures and the first two keys of the 2-of-3 fixture; they must
never hold funds. Taproot key-path signing is restricted to the fixture internal key. Taproot
script-path signing is restricted to the committed `p2tr-scriptpath` regtest fixture, its fixed
public test key, exact leaf script, leaf version, Merkle root, and control block. The adapters reject
arbitrary keys, leaves, and control blocks. The Go adapter retains the full-previous-transaction
requirement for SegWit v0 signing to avoid the incomplete-UTXO safety issue described by
CVE-2020-14199.

The fixture identifier is not an authentication credential, and the image does not prove that an
accepted PSBT came from this particular CLI run. Its safety comes from using a public valueless test
key on regtest, not from protecting that key. Do not place real funds on the fixture script.

Bitcoin Core receives only public descriptors. It does not receive fixture private keys.

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

The external conformance command never prints manifest command arguments or environment values in
its report. Its identity checks remain self-reported compatibility checks, not binary attestation.
Unlike the bundled Docker adapters, a manifest command runs with the privileges and filesystem
access of the invoking user unless the manifest itself starts a constrained container.

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
- Sandboxing or safely executing untrusted external adapter manifests
- Consensus proof beyond what the pinned Core binary and `testmempoolaccept` report

Before adding arbitrary input signing, replace the fixture-only adapter with a separately reviewed
policy and key-isolation design. That change should be treated as a new security boundary, not a
small feature.
