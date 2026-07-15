# btcsuite Go adapter

This adapter implements `psbt-lab.adapter/0.2` over bounded JSONL stdin/stdout.
It uses `github.com/btcsuite/btcd/btcutil/psbt` v1.2.0 for PSBTv0 parsing,
serialization, and signature insertion. Signing is hard-restricted to the lab's
two regtest `wsh(pk(test-key))` fixtures; no network or broadcast behavior is
present.

Supported operations are `hello`, `inspect`, `roundtrip`, `sign`, `finalize`,
and `finalize-inputs`. `combine`, Taproot signing, and unknown operations return
`unsupported` with class `operation.unsupported`.

The library's general P2WSH finalizer supports multisig scripts, while the lab
fixture is `wsh(pk(test-key))`; the adapter therefore constructs only that
already-authorized fixture witness during finalization. Every fixture input
must include a full previous transaction and an exactly matching witness UTXO.
Before reporting finalization success, the adapter executes all present partial
and final witnesses with btcd's standard script flags against those verified
previous outputs.

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
