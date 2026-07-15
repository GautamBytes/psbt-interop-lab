# Security Model

PSBT Interop Lab processes transaction metadata and invokes signing code, so its boundary is kept
intentionally smaller than a general-purpose wallet tool.

## Supported Use

Use this MVP only with its generated regtest fixtures on a development machine. Do not pass it a
mainnet PSBT, import a real seed, reuse the fixture key for funds, expose Core RPC to another host,
or treat a passing result as a security audit of an implementation.

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

### Bitcoin Core isolation

Core runs only on regtest with `networkactive=0`, `listen=0`, seed discovery disabled, and zero
peers. Compose publishes RPC to `127.0.0.1` only. The bundled credentials are intentionally local
regtest credentials, not secrets. Other containers deliberately attached to the project bridge
could reach Core RPC, so do not attach untrusted containers while the suite is running.

### Parsing and artifacts

The TypeScript wire parser enforces canonical base64, PSBT magic, minimal CompactSize values,
unique complete keys, bounded map and entry counts, exact framing, and no trailing bytes. It reports
structure and hashes rather than interpreting signing intent.

Artifact writes use contained paths, private permissions, temporary files, `fsync`, and atomic
rename. Replay rejects absolute paths, directory escapes, symlinks, non-regular files, oversized
files, malformed PSBTs, and hash mismatches. Reports redact raw PSBT-shaped strings and secret-like
fields.

## Out Of Scope

- Protection from a compromised Docker daemon, kernel, base image, or dependency registry
- Safe handling of arbitrary or adversarial production PSBTs by the native libraries themselves
- Hardware-wallet firmware or USB/HID isolation
- Mainnet signing, transaction broadcast, wallet policy approval, or fee validation for users
- Consensus proof beyond what the pinned Core binary and `testmempoolaccept` report

Before adding arbitrary input signing, replace the fixture-only adapter with a separately reviewed
policy and key-isolation design. That change should be treated as a new security boundary, not a
small feature.
