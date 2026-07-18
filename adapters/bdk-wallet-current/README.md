# Current BDK Wallet Adapter

This isolated protocol 0.2 adapter exercises the current Rust BDK wallet signing and finalization
path without changing the lab's root CLI, contracts, proof matrix, or Compose configuration.

## Locked implementation

- `bdk_wallet` 3.1.0
- `bitcoin` 0.32.102
- `miniscript` 12.3.7
- `bdk_chain` 0.23.3
- Rust 1.97
- Source revision: `bdk-wallet-v3.1.0+bitcoin-0.32.102+miniscript-12.3.7`

`Cargo.lock` is committed and every build and test command uses `--locked`. The primary upstream
references are the [BDK 3.1.0 release](https://github.com/bitcoindevkit/bdk_wallet/releases/tag/v3.1.0),
[BDK API documentation](https://docs.rs/bdk_wallet/3.1.0/bdk_wallet/), and
[rust-bitcoin 0.32.102 documentation](https://docs.rs/bitcoin/0.32.102/bitcoin/).

## Protocol capabilities

The process reads one JSON request per line from stdin and writes one JSON response per line to
stdout. It declares:

```text
operations: hello, native-parse, inspect, roundtrip, sign, finalize
roles: parser, signer, finalizer
psbtVersions: 0
scriptTypes: p2wpkh, p2sh-p2wpkh, p2wsh, p2tr-keypath, p2tr-scriptpath
```

Inspection and roundtripping cover all five declared script types. Signing and
finalization cover P2WPKH, P2WSH, Taproot key-path, and Taproot script-path;
nested P2SH-P2WPKH is deliberately roundtrip-only.

`native-parse`, `inspect`, and `roundtrip` accept a payload containing only `psbt`. Signing and
finalization accept `psbt`, `network`, and `fixtureId`; signing additionally accepts optional
`inputIndexes`. Request IDs must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.

The adapter supports these deterministic fixture IDs:

```text
happy-path
bdk-finalize-regression
p2wpkh
intent-rich-p2wpkh
p2wsh-single-key
p2wsh-2-of-3
p2tr-keypath
p2tr-scriptpath
```

For `p2wsh-2-of-3`, signing contributes only the scalar-1 fixture signature. Finalization succeeds
only after a second valid signature is present. BDK 3.1.0 skips already-finalized inputs, and the
regression test verifies that behavior against the historical BDK wallet issue 488 shape.

## Security boundary

The binary is network-free at runtime. It creates an ephemeral, non-persistent regtest wallet for
each authorized operation and has no RPC, socket, database, or filesystem input. The built-in WIF
is the lab's public deterministic scalar-1 regtest key and must never control real funds.

Signing and finalization require `PSBT_LAB_FIXTURE_COMMITMENTS`, a startup-only JSON object mapping
an allowlisted fixture ID to `sha256:<lowercase unsigned-transaction digest>`. Caller-provided keys,
commitments, unknown payload fields, non-regtest networks, mismatched scripts, uncommitted Taproot
leaves or control blocks, and non-default fixture sighashes are rejected.

Core-generated SegWit fixtures contain `witness_utxo` without `non_witness_utxo`. Accordingly,
signing sets `trust_witness_utxo=true` only after the startup commitment and exact fixture script
policy pass. Other safety options remain strict:

```text
try_finalize=false
allow_all_sighashes=false
tap_leaves_options=All for p2tr-scriptpath signing; None otherwise
sign_with_tap_internal_key=false for p2tr-scriptpath; true otherwise
allow_grinding=true
```

The script-path profile verifies the exact fixed leaf script, leaf version,
internal key, Merkle root, and control block before signing. Finalization
verifies the existing script-path signature and exact witness shape before
returning the PSBT.

The adapter verifies existing partial and finalized signatures before BDK finalization. Input PSBTs
must be canonical padded base64, PSBTv0, and small enough for the 4 MiB protocol line limit. BDK
re-exports rust-bitcoin's `Psbt`, so this adapter provides independent wallet behavior but not an
independent parser implementation. PSBTv2 is intentionally rejected.

## Run and test

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked
```

Example startup authorization:

```bash
PSBT_LAB_FIXTURE_COMMITMENTS='{"happy-path":"sha256:<64 lowercase hex characters>"}' \
  cargo run --locked
```

The Docker image builds with the same checks and runs as UID 10001 on a minimal Debian runtime.
