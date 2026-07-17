# rust-psbt PSBTv2 adapter

This is a bounded, parser-only PSBTv2 adapter for the `psbt-lab.adapter/0.2`
JSONL protocol. It uses the Rust Bitcoin `psbt-v2` crate to parse, inspect, and
serialize BIP370 PSBTs. It does not sign, finalize, combine, extract, or modify
transactions.

## Pinned source

- Crate: [`psbt-v2` 0.3.0](https://crates.io/crates/psbt-v2/0.3.0)
- Repository: [`rust-bitcoin/rust-psbt`](https://github.com/rust-bitcoin/rust-psbt)
- Tag: `psbt-v2-0.3.0`
- Peeled tag commit: `8ca657c333b6b391f2501e8b31627ccbb6a67f66`
- Specification: [BIP370](https://bips.dev/370/)

`Cargo.toml` pins the crate exactly and `Cargo.lock` commits the complete
dependency resolution. The tests copy the exact 14 valid and 21 invalid BIP370
vector cases shipped by that pinned CC0 upstream source. The local harness also
sends every vector through this adapter's `native-parse`, `inspect`, and
`roundtrip` operations.

## Capabilities

The `hello` response declares:

```json
{
  "operations": ["hello", "native-parse", "inspect", "roundtrip"],
  "roles": ["parser"],
  "psbtVersions": [2],
  "scriptTypes": ["p2wpkh"]
}
```

The lab's current capability schema requires at least one `scriptTypes` value.
This adapter declares only `p2wpkh`, the script profile present in and exercised
by the pinned BIP370 vectors. Parsing is generic PSBT map parsing, but this
declaration intentionally avoids claiming untested script-specific coverage. It
is not a signing or finalization claim.

`roundtrip` uses the native serializer. PSBT map order is not semantically
significant, and the library may materialize an explicit default field, so the
response includes `byteIdentical` as diagnostic data. Correctness is based on
the roundtripped PSBT parsing to the same native PSBT value, not byte equality.

## Run locally

```bash
cargo test --locked
cargo run --locked
```

Requests and responses are one JSON object per line:

```json
{"protocol":"psbt-lab.adapter/0.2","id":"hello-1","operation":"hello","payload":{}}
```

Build and run the container with a read-only filesystem and no network:

```bash
docker build -t psbt-lab-rust-psbt-v2 .
docker run --rm -i --read-only --network=none --cap-drop=ALL \
  --security-opt=no-new-privileges psbt-lab-rust-psbt-v2
```

## Security boundary

- Request lines are capped at 4 MiB before allocation can grow past that bound.
- Canonical base64 and complete PSBT map framing are required.
- Decoded PSBT size is bounded below the JSONL process limit.
- Declared input and output counts are capped at 4,096 each before calling the
  native parser.
- Each PSBT map is capped at 16,384 entries and preflight scanning uses constant
  space.
- Requests and payloads reject unknown JSON fields.
- The process reads stdin and writes stdout only. It needs no network, wallet,
  key, filesystem write, or Bitcoin node access.
- Parse failures return stable error classes without echoing PSBT contents or
  native parser internals.

The runtime image is digest-pinned, contains only the release binary and Debian
runtime base, and runs as an unprivileged system user. Deployments should retain
the read-only filesystem, no-network, no-new-privileges, and dropped-capability
flags shown above.
