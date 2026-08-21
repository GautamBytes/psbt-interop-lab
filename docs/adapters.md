# External Adapter Guide

`psbt-lab adapter check` lets a wallet or library maintainer validate a local adapter without
changing PSBT Interop Lab source. The same manifest can enroll conforming adapters in the full
matrix while preserving the 52 bundled scenarios.

## Generate a TypeScript Adapter

Create a protocol-correct bitcoinjs-lib parser adapter as a starting point:

```bash
psbt-lab adapter init ./wallet-adapter --name example-wallet
cd ./wallet-adapter
npm ci
npm test
npm run conformance
```

`--template typescript` is the only template and the default. Adapter names must be lowercase
kebab-case. The destination must not exist and its parent directory must already exist. The command
uses only templates shipped in the installed package; it performs no network access, dependency
installation, Git initialization, or generated-code execution. It never overwrites an existing
file, directory, or symbolic link.

The generated lockfile exact-pins the lab version and its HTTPS registry tarball. That one entry
cannot embed an integrity digest because the template is shipped inside the same tarball whose
digest it would need to contain. All other generated dependencies retain their published integrity
values. After the release is available from npm, maintainers whose policy requires SRI for the lab
entry can run the documented `npm install --package-lock-only --ignore-scripts` refresh and review
the resulting lockfile before committing it.

The generated adapter supports the baseline PSBTv0 parser profile: `hello`, `native-parse`, and
`roundtrip`. Its self-reported `artifactDigest` is the SHA256 of the compiled adapter entrypoint.
That value makes runs reproducible and can be pinned through `expected.artifactDigest`, but it is
not runtime attestation and does not commit to the dependency tree. The generated manifest leaves
the expected digest unpinned so the first build can pass conformance; pin it after deciding how the
adapter will be built and distributed.

Replace the sample parser and generated identity with the implementation under test before using
the adapter as interoperability evidence. Signing support is deliberately absent from this
template because signing requires an implementation-specific key and fixture authorization design.

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
        "--env",
        "PSBT_LAB_FIXTURE_COMMITMENTS",
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
`PSBT_LAB_FIXTURE_COMMITMENTS` is reserved and cannot be set in manifest `env`; the matrix runner
injects its run-scoped value. A Docker command must include
`--env PSBT_LAB_FIXTURE_COMMITMENTS`, as above, so Docker forwards that injected value into the
container without placing it in command arguments.
`expected.artifactDigest` can pin the adapter's self-reported SHA256 value, but that value is still
not cryptographic runtime attestation. The complete schema is
[`src/conformance/adapter-manifest.schema.json`](../src/conformance/adapter-manifest.schema.json).

Run the checks with:

```bash
psbt-lab adapter check ./adapters.json
psbt-lab adapter check ./adapters.json --json
```

The command exits with status 1 when any required check fails.

After conformance passes, run the built-in and external matrix together:

```bash
psbt-lab matrix --adapter-manifest ./adapters.json
psbt-lab run --suite proof --adapter-manifest ./adapters.json
```

For wallet CI, run only the capability-generated external scenarios and write standard CI reports:

```bash
psbt-lab matrix --external-only --adapter-manifest ./adapters.json \
  --junit psbt-interop.xml --sarif psbt-interop.sarif
```

`--external-only` starts only the isolated Bitcoin Core fixture service. It does not build or run
the ten bundled adapter process identities. It cannot be combined with `--scenario`, `--category`, or a
custom suite, and requires an adapter manifest.

The root composite action wraps this focused path:

```yaml
- uses: GautamBytes/psbt-interop-lab@v0.10.1
  with:
    adapter-manifest: ./adapters.json
```

It installs the exact `psbt-interop-lab@0.10.1` release with lifecycle scripts disabled, checks the
adapter, runs the matrix, and uploads the replay, JUnit, and SARIF outputs. `package-spec` can point
to a trusted
packed tarball for pre-release validation. The separately installed
[`examples/wallet-ci-adapter`](../examples/wallet-ci-adapter) package is the executable reference
consumer.

## Export a Parser Issue Bundle

After replacing the generated parser with the implementation under test, use the same trusted
manifest for bounded differential fuzzing and deterministic replay:

```bash
psbt-lab fuzz --runtime local --adapter-manifest ./wallet-adapter/adapter-manifest.json \
  --fixture bip174-minimal-v0 --seed 42 --cases 64 --issue-bundle parser-issue
psbt-lab parse-matrix --runtime local \
  --adapter-manifest ./wallet-adapter/adapter-manifest.json \
  --suite-manifest parser-issue/regression-suite.json
```

`parser-issue/` is created only when a minimized differential case exists. It contains
`manifest.json`, `regression-suite.json`, and `issue.md`. The manifest uses
`psbt-lab.issue-bundle/0.2`, records the exact identities negotiated from successful adapter hello
responses, normalizes classifications and accepted parser facts, and commits the issue and suite
bytes with SHA256. The manifest and issue draft include a separate `Lab semantic assessment` for
the minimized candidate's current output amounts. Adapters still report only their native parser
behavior; the lab-owned assessment does not change those classifications or the parser-only replay
suite. Existing files, directories, and symbolic links are never overwritten.

The issue draft is evidence for investigation and does not assign fault to an implementation.
Adapter commands, arguments, environment, raw diagnostic strings, and local paths are excluded.
Only frozen public test fixtures can enter this fuzzing path; private wallet PSBTs and production
transactions are not accepted. Keep the executable adapter manifest separate and review it as
trusted local code before replay.

The manifest `id` is the stable registry and report identity. It may differ from `expected.name`.
It must not collide with `rust-bitcoin`, `btcsuite-go`, `bitcoinjs-lib`, `bdkpython`,
`bdk-wallet-current`, `rust-psbt-v2`, `libwally`, `musig2-rust-signer-1`,
`musig2-scure-signer-2`, `hwi-simulator`, or another ID in the same manifest. Every response must
continue reporting the expected name, version, source revision, and optional pinned artifact
digest. The configured timeout caps every request.

## Matrix Participation

Each external adapter receives a native-parse and semantic-roundtrip scenario for the built-in
P2WPKH, nested P2SH-P2WPKH, P2WSH, Taproot key-path, and Taproot script-path fixtures. A cell is
reported as unsupported when its declared PSBT version, script type, parser role, or
operation-specific roundtrip support does not match.

A signing scenario is added only when `hello` declares all of the following:

- `roundtrip` and `sign` operations
- `parser` and `signer` roles
- PSBTv0 and the matching script type
- Matching `operationScriptTypes` entries for both `roundtrip` and `sign`
- The `fixture-commitment-sha256` feature

Signing requests currently use the built-in `p2wpkh`, `happy-path` P2WSH, and `p2tr-keypath`
fixtures where the adapter declares support. They contain `psbt`, `network: "regtest"`, and the
deterministic fixture ID. These fixtures use the public key derived from
the 32-byte test scalar `1`; this key is public test material and must never be used for real funds.
The adapter must return the signed PSBT in `output.psbt` and must reject signing unless the fixture
ID and unsigned transaction match the run-scoped SHA256 commitment supplied at startup. Caller
supplied keys or commitment values must not be accepted.

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

Custom suite signing additionally requires the adapter to advertise `user-fixture-template-v1`.
The request then includes the deterministic fixture ID and its canonical fixture-spec SHA256. This
feature is intentionally separate from general signing support; an adapter must independently
validate the public template and run-scoped unsigned-transaction commitment.

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
signing, or make an untrusted manifest safe. Matrix signing is restricted to deterministic regtest
fixtures and does not repair or rewrite wallet PSBTs.
