# PSBT Interop Lab MVP Hardening Design

**Date:** 2026-07-15  
**Status:** Approved for implementation

## Goal

Harden the existing local proof without expanding its product scope. The lab must reject misleading
adapter or Core results, bound resource use earlier, isolate containers and CI jobs more tightly,
and state its remaining trust assumptions precisely.

The CLI, two proof scenarios, artifact format, and generated-regtest-only workflow remain intact.

## Confirmed Scope

- One trusted developer runs the CLI locally.
- The suite creates every PSBT on isolated Bitcoin Core regtest.
- No arbitrary user PSBTs, mainnet signing, public API, web UI, uploads, or multi-tenancy.
- The local Docker daemon and host account are trusted.
- Artifacts remain local and may contain sensitive transaction metadata.
- GitHub-hosted CI is a separate build-time boundary: no secrets, read-only repository permission,
  ephemeral runners, and the complete Docker proof only on trusted main-branch or manual runs.

## Chosen Approach

Use targeted integrity and isolation hardening. Keep existing module boundaries unless a small pure
validator makes a security rule independently testable. Avoid a broad refactor because it would add
regression risk without improving the MVP's grant proof.

## Runtime Integrity

### Independent PSBT verification

The runner must not trust an adapter's `byteIdentical` claim. After every roundtrip operation, the
runner will decode both canonical PSBT strings and compare their bytes independently. A changed,
missing, or malformed returned PSBT fails the scenario even when the adapter reports success.

### Adapter contract pinning

Startup negotiation will verify the expected adapter name, implementation version, source revision,
supported operations, and PSBTv0 capability. This protects against accidental use of a stale or
wrong image. These self-reported values are compatibility assertions, not cryptographic image
attestation.

### Core contract pinning

The fixture builder will require regtest, zero peers, and Bitcoin Core 31.1's numeric version before
creating fixtures. The RPC client will require each JSON-RPC response ID to exactly match its
request ID. Wrong-version Core instances and stale or mismatched responses fail closed.

### Strict protocol values

Adapter executable digests must use canonical lowercase `sha256:` followed by exactly 64 hexadecimal
characters. PSBT parsing will reject obviously oversized encoded input before allocating a decoded
buffer, then retain the existing decoded-size and structural limits.

### Replay handling

Replay will cap checkpoint count and read each checkpoint through one non-following file descriptor,
then validate the opened file type, size, digest, and PSBT structure. This narrows path-swap and
resource-exhaustion behavior. Replay hashes detect accidental or partial corruption only; because
the mutable manifest stores the hashes beside the files, they do not authenticate artifacts against
a malicious local editor.

## Isolation And Availability

The Bitcoin Core container will match the adapters' baseline isolation where compatible: read-only
root filesystem, writable named data volume, temporary `/tmp`, dropped capabilities, process and
memory limits, and `no-new-privileges`. RPC remains bound to host loopback. Core remains offline with
zero peers.

CI will keep read-only permissions and gain per-job timeouts plus concurrency cancellation. Docker
proof stays unavailable to untrusted pull-request code. Adapter build contexts will ignore Rust,
Python, and Git build artifacts so local state cannot inflate or contaminate image contexts.

## Data Flow And Failure Behavior

1. The CLI validates Docker and Core prerequisites.
2. Core identity and regtest isolation are checked.
3. Each adapter negotiates and is checked against its pinned contract.
4. Core creates deterministic fixtures.
5. Adapters process bounded JSONL requests in networkless containers.
6. The runner independently validates returned PSBT bytes and Core policy results.
7. Private local artifacts are written atomically.
8. Replay reopens bounded checkpoint files and verifies internal consistency.

Every new check fails closed with a concise error naming the violated contract. Errors must not echo
raw PSBTs, credentials, private-key-like values, or unbounded adapter output.

## Testing Strategy

Use red-green-refactor for each behavior:

- RPC response-ID mismatch tests.
- Canonical digest schema tests.
- Lying-adapter roundtrip tests where `byteIdentical=true` but bytes differ.
- Wrong adapter identity, missing capability, and wrong Core version tests.
- Oversized encoded PSBT rejection before decode.
- Replay checkpoint-count and symlink/non-regular-file tests.
- Compose configuration assertions where practical.

Then run formatting, lint, type checking, all TypeScript tests, production build, Rust formatting,
Clippy and tests, Python tests, dependency audits, clean Docker builds, the full Core/Rust/BDK proof,
and artifact replay.

## Security Documentation

Add a repository-grounded threat model covering runtime and CI separately. Update the security model
to distinguish compatibility checks from provenance and internal replay consistency from artifact
authenticity. Record residual risks instead of claiming production-wallet safety.

## Repository Hygiene

After the hardened commit is integrated into the primary working tree, remove its stale temporary
`origin` remote and upstream tracking. Do not invent a replacement remote without the user's real
repository URL.

## Non-Goals

- General-purpose PSBT inspection or signing.
- Mainnet/testnet/signet support.
- Real keys, hardware wallets, transaction broadcast, or policy approval.
- Public service hardening, authentication, rate limiting, or multi-user storage.
- Cryptographic adapter/image attestation.
- A broad runner, parser, or adapter architecture rewrite.

## Acceptance Criteria

- Existing legitimate proof and replay still pass.
- A changed PSBT cannot pass through a truthful or lying `byteIdentical` field.
- Wrong RPC IDs, noncanonical digests, unexpected adapters, and wrong Core versions are rejected.
- Runtime and CI resource limits are explicit.
- Threat boundaries and replay limitations are documented without overclaiming.
- Full local verification passes from clean container builds.
