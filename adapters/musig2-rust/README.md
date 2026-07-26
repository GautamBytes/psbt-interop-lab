# MuSig2 Rust Adapter

This adapter is launched twice, with `PSBT_LAB_MUSIG2_SIGNER=1` and `=2`, to model two isolated
BIP373 participants. It uses `musig2` 0.4.1 and `bitcoin` 0.32.102 for the real key aggregation,
nonce, partial-signature, verification, aggregation, and Taproot sighash operations.

The supported fixture is the deterministic regtest-only `p2tr-musig2` profile. Each process seeds
its secret nonce from the operating-system CSPRNG, keeps it only in memory, expires it after 15
minutes, and consumes it on the first partial-sign attempt. A bounded replay cache rejects recent
session reuse, and the signer accepts only the run-committed unsigned transaction. Both
participants use the same Rust implementation; this is not a cross-library MuSig2 proof or a
production signing service.

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
