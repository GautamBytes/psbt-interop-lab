# bitcoinjs-lib adapter

PSBT Interop Lab adapter for `bitcoinjs-lib` 7.0.1 and `tiny-secp256k1` 2.2.4.

The adapter speaks JSONL on standard input/output and targets `psbt-lab.adapter/0.2`. It accepts
canonical, bounded PSBTv0 base64 only. A binary PSBT is capped just below 3 MiB so its base64
response, including its JSON envelope, remains within the 4 MiB JSONL line limit. Its signer is deliberately limited to the lab's deterministic
regtest `wsh(pk(test key))` fixtures and never accepts a caller-supplied key or network request.

Signing and finalization also require `PSBT_LAB_FIXTURE_COMMITMENTS` at process startup. The value
must be a JSON object of at most 4096 UTF-8 bytes mapping one or both allowed fixture IDs
(`happy-path` and `bdk-finalize-regression`) to the lowercase SHA256 commitment of that fixture's
PSBTv0 unsigned transaction bytes:

```sh
PSBT_LAB_FIXTURE_COMMITMENTS='{"happy-path":"sha256:<64-lowercase-hex>"}'
```

The adapter hashes `psbt.data.globalMap.unsignedTx.toBuffer()` and compares it with the configured
commitment before signing or finalizing. A commitment supplied inside a request payload is rejected.
`hello` advertises this contract as `fixture-commitment-sha256`.

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
