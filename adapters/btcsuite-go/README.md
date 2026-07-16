# btcsuite Go adapter

This adapter implements `psbt-lab.adapter/0.2` over bounded JSONL stdin/stdout.
It uses `github.com/btcsuite/btcd/btcutil/psbt` v1.2.0 for PSBTv0 parsing,
serialization, and signature insertion. Signing is hard-restricted to committed
lab regtest fixtures; no network or broadcast behavior is present.

Supported operations are `hello`, `native-parse`, `inspect`, `roundtrip`, `sign`, `finalize`,
and `finalize-inputs`. `native-parse` performs only bounded canonical base64 decoding before calling
btcsuite's parser, so invalid-input results come from the native library rather than the fixture
policy preflight. The signer supports the `p2wpkh`, `p2wsh`, and
`p2tr-keypath` script types. `combine` and unknown operations return
`unsupported` with class `operation.unsupported`.

The profile signer uses only built-in fixture keys: scalar 1 signs the exact
P2WPKH and Taproot key-path profiles, while scalar 2 contributes only its
signature to the exact ordered scalar-1/scalar-2/scalar-3 2-of-3 P2WSH profile.
Taproot key-path signatures use `SIGHASH_DEFAULT` and are inserted directly as
`PSBT_IN_TAP_KEY_SIG`. Caller-provided signing keys are not accepted.

The library's general P2WSH finalizer supports multisig scripts, while the lab
fixture is `wsh(pk(test-key))`; the adapter therefore constructs only that
already-authorized fixture witness during finalization. Every fixture input
in a SegWit-v0 signing or finalization profile must include a full previous
transaction and an exactly matching witness UTXO, preserving the
CVE-2020-14199 defense. Taproot inputs require all witness UTXOs; any supplied
full previous transaction must identify and match the same output. Taproot
internal keys and output scripts must match the key-only fixture exactly, and
script-path metadata is rejected.
Before reporting finalization success, the adapter executes all present partial
and final witnesses with btcd's standard script flags against those verified
previous outputs. Profile signing likewise verifies every existing and newly
produced ECDSA or Schnorr signature cryptographically.

PSBTs are limited to 1024 inputs, 1024 outputs, and 1024 entries in each global,
input, or output map, in addition to the JSONL response-size limit.

Signing and finalization require `PSBT_LAB_FIXTURE_COMMITMENTS` at startup. It
is a JSON object whose keys are fixture IDs and whose values are lowercase
`sha256:<64 hex>` digests of the exact unsigned transaction serialization, for
example `{"happy-path":"sha256:..."}`. The adapter never accepts commitments
from requests.

```sh
go test ./...
go run ./cmd/adapter
docker build -t psbt-lab-btcsuite-go .
```
