# Architecture

## Design Goal

The MVP answers one concrete question: can several real Bitcoin implementations hand the same PSBT
to one another and still produce a transaction that Bitcoin Core can finalize and accept under
policy? It does not reimplement wallet logic in TypeScript. The orchestrator controls the run while
each native library parses and acts on the PSBT itself.

```mermaid
flowchart LR
  CLI["TypeScript CLI"] -->|"JSON-RPC on loopback"| Core["Bitcoin Core 31.1 regtest"]
  CLI -->|"bounded JSONL"| Rust["rust-bitcoin 0.32.101 adapter"]
  CLI -->|"bounded JSONL"| BDK["bdkpython 2.3.1 adapter"]
  CLI --> Facts["Lossless wire-facts parser"]
  CLI --> Artifacts["Private checkpoints and reports"]
  Artifacts --> Replay["Offline PSBT-digest replay"]
```

## Components

### TypeScript orchestrator

The CLI owns scenario order, Core RPC, adapter lifecycle, strict request and response validation,
timeouts, result classification, artifact writing, and replay. TypeScript is used for developer
experience and orchestration; no signature algorithm is implemented there.

For every adapter round trip, `assertByteIdenticalRoundtrip` in `src/scenarios/contracts.ts` parses
the source and returned canonical PSBT and compares decoded bytes independently of the adapter's
`byteIdentical` claim. `CoreRpc.call` in `src/core/rpc.ts` requires matching JSON-RPC request/response
IDs, and fixture preparation requires Bitcoin Core numeric version `310100`.

### Bitcoin Core fixture source and oracle

Core 31.1 mines a local regtest chain, funds the known public P2WSH descriptor, creates PSBTv0 with
`createpsbt`, and fills UTXO/script metadata with `utxoupdatepsbt`. At the end of each path,
`finalizepsbt` extracts the transaction and `testmempoolaccept` checks current consensus and mempool
policy without broadcasting it.

The Core RPC `version` argument to `createpsbt` is the unsigned transaction version. It is not the
PSBT format version. The generated fixture is inspected as PSBTv0 before any adapter receives it.

### Native adapters

Adapters speak `psbt-lab.adapter/0.1`, one JSON object per line. Every response repeats the request
ID and includes implementation name, version, and artifact digest. The status is one of `ok`,
`unsupported`, `rejected`, `crashed`, or `timeout`; failures use stable error classes rather than
language-specific stack traces.

Startup pins each adapter's self-reported name, version, source revision, operations, and PSBTv0
support as a compatibility check. A malicious adapter can spoof the expected identity strings and
supply any schema-valid self-reported digest; the runner does not compare a pinned content digest.
These values are not cryptographic attestation of the running image. Dockerfile base digests,
downloaded checksums, and dependency hashes support reproducible build selection rather than
runtime provenance.

The Rust adapter signs and finalizes only known fixture inputs. The Python adapter freezes the
affected `bdkpython` 2.3.1 wheel and exposes round-trip/finalize behavior. Neither adapter has
network access at runtime.

### Wire facts and artifacts

The wire-facts parser reads BIP174/BIP370 framing directly so serialization changes cannot be
hidden by a library's normalized object model. It records PSBT version, byte length, SHA256, map
counts, and key/value sizes. Raw PSBT, script, and UTXO material is excluded from reports.
Implementation name, version, source revision, and self-reported digest metadata are intentionally
recorded and protected only by local file permissions.

Each handoff writes both the canonical base64 PSBT and its facts. The manifest records these files
alongside the run's self-reported implementation identities. Replay reparses each PSBT and verifies
its SHA256 against the manifest and stored facts JSON `sha256`; it does not recompute other stored
facts or recorded outcomes and does not rerun adapters. This does not authenticate the mutable
artifact directory.

Replay rejects absolute and lexically escaping checkpoint paths and caps a manifest at 1,000
checkpoints. Intermediate symlinks remain trusted. Final-component `O_NOFOLLOW` protection applies
only where Node exposes the flag.

## Runtime And CI Boundaries

Locally, one trusted developer controls the host account and Docker daemon. Core and both adapters
run with read-only roots, dropped capabilities, process/memory limits, and `no-new-privileges`; Core
alone retains its named regtest data volume and a bounded temporary `/tmp` mount. Adapters use no
network, while Core JSON-RPC is published only to host loopback. These settings reduce ordinary
process and resource exposure but do not protect against a compromised trusted host, Docker daemon,
kernel, or base image.

GitHub-hosted CI is separate from that runtime. `.github/workflows/ci.yml` gives jobs read-only
repository permission, no persisted checkout credential or workflow secrets, pinned action commits,
ephemeral runners, timeouts, and concurrency cancellation. Pull requests run the TypeScript, Rust,
and BDK checks; the complete Docker proof runs only on `refs/heads/main` or a trusted manual dispatch.
These controls mitigate credential, compute, and network abuse. Pull-request code can alter its own
tests and build scripts, so green means revision self-consistency rather than independent check
integrity. The workflow does not publish or attest a release image.

The detailed assumptions, abuse paths, and residual risks are recorded in the
[threat model](../psbt-interop-lab-threat-model.md).

## Proof Scenarios

### Happy path

1. Core builds one funded P2WSH input and one output.
2. Rust deserializes and serializes it byte-identically.
3. Rust signs the known input.
4. Core finalizes, extracts, and policy-checks the transaction.

### BDK finalization regression

1. Core builds a two-input P2WSH PSBT.
2. BDK round-trips it byte-identically.
3. Rust signs both inputs.
4. Rust finalizes input zero and removes metadata as a conforming finalizer may do; input one stays
   partially signed.
5. Frozen BDK 2.3.1 tries to finalize the already-finalized first input and returns the historical
   missing-witness-script failure.
6. Core finalizes the same mixed-state PSBT and policy-accepts the extracted transaction.

This is a synthetic minimal fixture based on the state transition described in BDK issue #488. It
does not copy the reporter's wallet data or seed.

Core validates the returned PSBT but does not prove BDK executed or that later adapter operations
preserved the intended unsigned transaction. The interpretation above retains low false-PASS risk
only under the trusted-image scope.

## Extension Points

A grant-funded implementation can add adapters without changing scenario semantics. The next
interfaces should be a public adapter conformance kit, a declarative scenario format, transition
invariants, and a normalized diff model. New implementations can then be compared by capability and
version while raw PSBT bytes remain the source of truth.
