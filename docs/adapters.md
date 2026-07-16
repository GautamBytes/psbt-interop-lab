# External Adapter Guide

`psbt-lab adapter check` lets a wallet or library maintainer validate a local adapter without
changing PSBT Interop Lab source. This is protocol onboarding, not automatic enrollment in every
built-in compatibility scenario.

## Adapter Manifest

Create a JSON file that follows `psbt-lab.adapters/0.1`:

```json
{
  "schema": "psbt-lab.adapters/0.1",
  "adapters": [
    {
      "id": "example-wallet",
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "example/wallet-psbt-adapter:1.0.0"
      ],
      "timeoutMs": 10000,
      "expected": {
        "name": "example-wallet",
        "version": "1.0.0",
        "sourceRevision": "example-wallet-v1.0.0"
      }
    }
  ]
}
```

`cwd` is optional and resolves relative to the manifest file. `args` and `env` are optional.
`expected.artifactDigest` can pin the adapter's self-reported SHA256 value, but that value is still
not cryptographic runtime attestation. The complete schema is
[`src/conformance/adapter-manifest.schema.json`](../src/conformance/adapter-manifest.schema.json).

Run the checks with:

```bash
psbt-lab adapter check ./adapters.json
psbt-lab adapter check ./adapters.json --json
```

The command exits with status 1 when any required check fails.

## JSONL Protocol

The adapter reads one JSON object per line from stdin and writes one response object per line to
stdout. It must speak `psbt-lab.adapter/0.2`, preserve the request `id`, and produce responses that
match the strict schemas in `src/protocol/schema.ts`.

The baseline conformance profile requires:

- `hello`, declaring the `parser` role plus the `native-parse` and `roundtrip` operations
- `native-parse` accepting the valid bounded PSBT probe through the implementation's native parser
- `native-parse` rejecting malformed PSBT bytes with class `psbt.native_parse_failed`
- Exact self-reported name, version, and source revision matching the manifest

Conformance requires `roundtrip` to preserve every PSBT field semantically. Legal key ordering
changes are allowed.

The `native-parse` operation receives `{ "psbt": "<canonical-base64>" }`. The adapter may bound and
decode base64 before calling its native PSBT parser, but it must not use a second structural PSBT
parser to decide the result. A successful response includes `nativeParser` equal to the adapter's
self-reported implementation name.

## Security Boundary

Manifests are executable configuration. The CLI uses argument arrays and `shell: false`, validates
and bounds the file, limits request time and output size, and does not print command arguments or
environment values. Those controls do not sandbox the configured executable. Only run manifests
you trust, and prefer a networkless, read-only container with dropped capabilities.

The conformance report proves that an adapter follows the transport and parser baseline during that
run. It does not prove the identity of a malicious binary, audit wallet security, authorize mainnet
signing, or add the adapter to the built-in 18-scenario matrix automatically.
