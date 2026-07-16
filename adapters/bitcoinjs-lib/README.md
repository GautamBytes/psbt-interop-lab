# bitcoinjs-lib adapter

PSBT Interop Lab adapter for `bitcoinjs-lib` 7.0.1 and `tiny-secp256k1` 2.2.4.

The adapter speaks JSONL on standard input/output and targets `psbt-lab.adapter/0.2`. It accepts
canonical, bounded PSBTv0 base64 only. A binary PSBT is capped just below 3 MiB so its base64
response, including its JSON envelope, remains within the 4 MiB JSONL line limit. Its signer is deliberately limited to the lab's deterministic
regtest fixtures and never accepts a caller-supplied key or network request.

The exact signing policies are:

- `happy-path` and `bdk-finalize-regression`: scalar 1 signs the legacy
  `wsh(pk(scalar1))` fixture; these remain the only finalizable fixture IDs.
- `p2wpkh`: scalar 1 signs only the exact `wpkh(scalar1)` funding script.
- `p2wsh-2-of-3`: scalar 2 adds its deterministic signature to the exact ordered
  `multi(2,scalar1,scalar2,scalar3)` witness script.
- `p2tr-keypath`: scalar 1 is normalized and BIP341 `TapTweak`-adjusted before the signer exposes
  `signSchnorr`; only the exact internal key, no script-path metadata, and default sighash are
  accepted.

Every input must have the exact funding script for its selected fixture. A non-witness UTXO must
match the unsigned transaction outpoint, and when both UTXO forms are present their script and value
must agree. `hello` advertises `p2wpkh`, `p2wsh`, and `p2tr-keypath`, plus only the proven
`fixture-commitment-sha256` feature.

Signing and finalization also require `PSBT_LAB_FIXTURE_COMMITMENTS` at process startup. The value
must be a non-empty JSON object of at most 4096 UTF-8 bytes mapping allowed fixture IDs
(`happy-path`, `bdk-finalize-regression`, `p2wpkh`, `p2wsh-2-of-3`, and `p2tr-keypath`) to the
lowercase SHA256 commitment of each fixture's PSBTv0 unsigned transaction bytes:

```sh
PSBT_LAB_FIXTURE_COMMITMENTS='{"happy-path":"sha256:<64-lowercase-hex>"}'
```

The adapter hashes `psbt.data.globalMap.unsignedTx.toBuffer()` and compares it with the configured
commitment before signing or finalizing. A commitment supplied inside a request payload is rejected.

Run its isolated checks with:

```sh
npm ci
npm test
npm run typecheck
```

The Docker runtime deliberately remains the digest-pinned Node image: this JavaScript adapter needs
Node and the packaged `tiny-secp256k1` WASM dependency, so a compiled standalone Debian runtime is
not practical. Deploy the container with a read-only root filesystem and no network access.

Official references: [bitcoinjs-lib v7.0.1](https://www.npmjs.com/package/bitcoinjs-lib/v/7.0.1),
[tiny-secp256k1 v2.2.4](https://www.npmjs.com/package/tiny-secp256k1/v/2.2.4), and the
[v7.0.1 PSBT source](https://github.com/bitcoinjs/bitcoinjs-lib/blob/v7.0.1/ts_src/psbt.ts).
