# rust-psbt PSBTv2 adapter

This is a bounded PSBTv2 workflow adapter for the `psbt-lab.adapter/0.2` JSONL
protocol. It uses the Rust Bitcoin `psbt-v2` crate to parse, inspect, serialize,
sign, combine, finalize, extract, and construct BIP370 PSBTs. Signing operations
are restricted to committed deterministic regtest fixtures; constructor actions
operate only on caller-supplied PSBTv2 documents.

## Pinned source

- Crate: [`psbt-v2` 0.3.0](https://crates.io/crates/psbt-v2/0.3.0)
- Repository: [`rust-bitcoin/rust-psbt`](https://github.com/rust-bitcoin/rust-psbt)
- Tag: `psbt-v2-0.3.0`
- Peeled tag commit: `8ca657c333b6b391f2501e8b31627ccbb6a67f66`
- Specification: [BIP370](https://bips.dev/370/)

`Cargo.toml` pins the crate exactly and `Cargo.lock` commits the complete
dependency resolution. The tests copy the exact 14 valid and 21 invalid BIP370
vector cases shipped by that pinned CC0 upstream source. The local harness sends
every vector through the native parser and also exercises bidirectional P2WPKH
signing/finalization and cross-library 2-of-3 P2WSH signing, combining,
finalization, and extraction.

## Capabilities

The `hello` response declares:

```json
{
  "operations": ["hello", "native-parse", "inspect", "roundtrip", "sign", "combine", "finalize", "extract", "construct"],
  "roles": ["parser", "updater", "signer", "combiner", "finalizer", "extractor", "constructor"],
  "psbtVersions": [2],
  "scriptTypes": ["p2wpkh", "p2wsh", "p2tr-keypath", "p2tr-scriptpath"]
}
```

The operation-specific capability map declares P2WPKH and P2WSH signing,
combining, finalization, extraction, and construction. Taproot inspection and
native roundtripping cover key-path and script-path PSBTv2 data, but the adapter
does not claim Taproot signing or PSBT version conversion.

`roundtrip` uses the native serializer. PSBT map order is not semantically
significant, and the library may materialize an explicit default field, so the
response includes `byteIdentical` as diagnostic data. Correctness is based on
the roundtripped PSBT parsing to the same native PSBT value, not byte equality.

`construct` creates modifiable PSBTv2 documents, adds or removes inputs and
outputs, updates sequence values, selects BIP370 locktimes, and seals input or
output scopes. The pinned `psbt-v2` 0.3.0 crate uses a zero amount as its
internal missing-value sentinel, so zero-valued outputs are rejected with
`psbt.zero_amount_unsupported`; this is a documented library boundary rather
than a BIP370 validity claim.

`sign` and `finalize` accept only `p2wpkh`, `intent-rich-p2wpkh`, or
`p2wsh-2-of-3` and require a startup `PSBT_LAB_FIXTURE_COMMITMENTS` entry whose
SHA256 matches the exact unsigned transaction. `combine` and `extract` are
generic bounded PSBTv2 operations; the orchestrated workflows still apply them
only to suite-generated fixtures. Existing signatures are verified,
two-of-three workflows must preserve two distinct pubkey signatures, and
extracted transactions remain subject to Bitcoin Core policy checks in the
orchestrated suite.

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
  filesystem write, or Bitcoin node access.
- The only signing keys are public, valueless deterministic regtest scalars.
  Caller-provided keys, arbitrary fixtures, and non-regtest signing are rejected.
- Parse failures return stable error classes without echoing PSBT contents or
  native parser internals.

The runtime image is digest-pinned, contains only the release binary and Debian
runtime base, and runs as an unprivileged system user. Deployments should retain
the read-only filesystem, no-network, no-new-privileges, and dropped-capability
flags shown above.
