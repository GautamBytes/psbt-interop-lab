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
already-authorized fixture witness during finalization.

```sh
go test ./...
go run ./cmd/adapter
docker build -t psbt-lab-btcsuite-go .
```
