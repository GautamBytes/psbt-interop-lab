# PSBT Interop Lab MVP Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the local proof fail closed on misleading Core or adapter output, bound replay and parsing work, harden container and CI isolation, and document residual risks accurately.

**Architecture:** Keep the TypeScript CLI as orchestrator and the native adapters unchanged except for test fixture digests. Add small pure contract validators beside the proof runner, strengthen existing RPC/parser/replay boundaries, and preserve both proof scenarios and artifact schema. Treat runtime and GitHub CI as separate trust boundaries.

**Tech Stack:** Node.js 22/24, TypeScript 7, Ajv 8, Vitest 4, Bitcoin Core 31.1, Docker Compose, GitHub Actions, Rust 1.97 with rust-bitcoin 0.32.101, Python 3.13 with bdkpython 2.3.1.

## Global Constraints

- One trusted developer runs the CLI locally.
- Every PSBT is suite-generated on isolated Bitcoin Core regtest.
- No arbitrary user PSBT, mainnet signing, public API, web UI, upload, or multi-tenant behavior.
- The local Docker daemon and host account are trusted.
- Adapter identity fields are compatibility assertions, not cryptographic provenance.
- Replay hashes prove internal consistency, not authenticity against a malicious local editor.
- GitHub-hosted CI receives no secrets, keeps read-only repository permission, and runs the Docker proof only on the main branch or manual dispatch.
- Existing CLI commands, proof scenario IDs, manifest schema, and normal proof output remain compatible.
- Every behavior change follows red-green-refactor.

---

### Task 1: Pin Bitcoin Core RPC and runtime identity

**Files:**
- Modify: `test/core/rpc.test.ts`
- Modify: `src/core/rpc.ts`
- Modify: `test/core/fixtures.test.ts`
- Modify: `src/core/fixtures.ts`

**Interfaces:**
- Consumes: `CoreRpc.call<T>(method, params, wallet?)` and `prepareFixtures(rpc)`.
- Produces: exact JSON-RPC response-ID validation and exported `BITCOIN_CORE_VERSION = 310100` enforcement.

- [ ] **Step 1: Write the failing RPC response-ID tests**

Add these cases inside `describe("CoreRpc")`:

```ts
test.each([null, "psbt-lab-999", 1])(
  "rejects a response with mismatched id %j",
  async (id) => {
    const server = await serve((_request, response) => {
      response.end(JSON.stringify({ result: 42, error: null, id }));
    });
    const rpc = new CoreRpc({ url: server.url, username: "u", password: "p" });

    await expect(rpc.call("getblockcount", {})).rejects.toThrow(/response id/i);
  },
);

test("rejects a response without an id", async () => {
  const server = await serve((_request, response) => {
    response.end(JSON.stringify({ result: 42, error: null }));
  });
  const rpc = new CoreRpc({ url: server.url, username: "u", password: "p" });

  await expect(rpc.call("getblockcount", {})).rejects.toThrow(/invalid envelope/i);
});
```

- [ ] **Step 2: Run the RPC test and verify red**

Run: `pnpm test test/core/rpc.test.ts`

Expected: the new cases resolve successfully because `RpcEnvelope` does not yet validate `id`.

- [ ] **Step 3: Require the exact request ID in the RPC envelope**

Change the envelope and validation flow to carry `id`, then compare it before handling the result:

```ts
interface RpcEnvelope {
  id: unknown;
  result: unknown;
  error: RpcErrorValue | null;
}

function isRpcEnvelope(value: unknown): value is RpcEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const envelope = value as Record<string, unknown>;
  if (!("id" in envelope) || !("result" in envelope) || !("error" in envelope)) {
    return false;
  }
  // Keep the existing typed error checks.
}

if (!isRpcEnvelope(decoded)) {
  throw new CoreRpcTransportError(`Bitcoin Core RPC ${method} returned an invalid envelope`);
}
if (decoded.id !== id) {
  throw new CoreRpcTransportError(`Bitcoin Core RPC ${method} returned a mismatched response id`);
}
```

- [ ] **Step 4: Run focused RPC tests and verify green**

Run: `pnpm test test/core/rpc.test.ts`

Expected: all RPC tests pass, including wrong, missing, null, and numeric IDs.

- [ ] **Step 5: Write the failing Core version test**

Extend the fixture test with a minimal caller that reaches `getnetworkinfo` and reports the wrong
version:

```ts
test("refuses an unexpected Bitcoin Core version", async () => {
  const rpc: RpcCaller = {
    async call<T>(method: string): Promise<T> {
      if (method === "getblockchaininfo") return { chain: "regtest", blocks: 103 } as T;
      if (method === "getnetworkinfo") {
        return { version: 310000, subversion: "/Satoshi:31.0.0/", connections: 0 } as T;
      }
      throw new Error(`Unexpected RPC ${method}`);
    },
  };

  await expect(prepareFixtures(rpc)).rejects.toThrow(/Core 31\.1/i);
});
```

- [ ] **Step 6: Run the fixture test and verify red**

Run: `pnpm test test/core/fixtures.test.ts`

Expected: failure reaches the unexpected third RPC instead of rejecting the version.

- [ ] **Step 7: Enforce the exact numeric Core version**

Add near the fixture constants and check immediately after parsing network metadata:

```ts
export const BITCOIN_CORE_VERSION = 310100;

if (network.version !== BITCOIN_CORE_VERSION) {
  throw new Error(
    `PSBT Interop Lab requires Bitcoin Core 31.1 (${BITCOIN_CORE_VERSION}); received ${network.version}`,
  );
}
```

Do not pin `subversion`; the numeric RPC field is the machine contract and avoids vendor-string
format fragility.

- [ ] **Step 8: Run focused and aggregate tests**

Run: `pnpm test test/core/rpc.test.ts test/core/fixtures.test.ts`

Expected: both files pass.

- [ ] **Step 9: Commit Task 1**

```bash
git add src/core/rpc.ts src/core/fixtures.ts test/core/rpc.test.ts test/core/fixtures.test.ts
git commit -m "fix: pin Core RPC identity"
```

---

### Task 2: Verify adapter contracts and PSBT bytes independently

**Files:**
- Create: `src/scenarios/contracts.ts`
- Create: `test/scenarios/contracts.test.ts`
- Modify: `src/scenarios/proof.ts`
- Modify: `src/protocol/schema.ts`
- Modify: `test/protocol/schema.test.ts`
- Modify: `test/protocol/adapter-process.test.ts`
- Modify: `test/fixtures/fake-adapter.mjs`
- Modify: `test/scenarios/proof.test.ts`

**Interfaces:**
- Consumes: validated `AdapterResponse` objects and canonical PSBT base64 accepted by `extractWireFacts`.
- Produces: `assertAdapterHello(response, expected)`, `assertByteIdenticalRoundtrip(response, source, label)`, `RUST_ADAPTER_CONTRACT`, and `BDK_ADAPTER_CONTRACT`.

- [ ] **Step 1: Write failing canonical digest tests**

Define `VALID_DIGEST = \`sha256:${"a".repeat(64)}\`` in `test/protocol/schema.test.ts`, replace
accepted short digests, and add:

```ts
test.each([
  "sha256:deadbeef",
  `sha256:${"A".repeat(64)}`,
  `sha256:${"a".repeat(63)}`,
  `sha256:${"a".repeat(65)}`,
])("rejects noncanonical implementation digest %s", (artifactDigest) => {
  const result = validateAdapterResponse({
    protocol: "psbt-lab.adapter/0.1",
    id: "hello-1",
    status: "ok",
    implementation: { name: "fake", version: "1.0.0", artifactDigest },
    output: {},
  });
  expect(result.ok).toBe(false);
});
```

- [ ] **Step 2: Run schema tests and verify red**

Run: `pnpm test test/protocol/schema.test.ts`

Expected: short and uppercase digests are accepted.

- [ ] **Step 3: Tighten the schema and update TypeScript fixture digests**

Use this exact schema pattern:

```ts
artifactDigest: {
  type: "string",
  pattern: "^sha256:[0-9a-f]{64}$",
},
```

Change all TypeScript and fake-adapter fixture digests to `sha256:` plus 64 lowercase hex
characters. Native Rust/Python unit tests may keep arbitrary digest parameters because they test
their internal response builders, not the JSONL schema boundary.

- [ ] **Step 4: Run protocol and process tests and verify green**

Run: `pnpm test test/protocol`

Expected: schema and adapter-process tests pass.

- [ ] **Step 5: Write failing pure contract tests**

Create `test/scenarios/contracts.test.ts` with these fixtures and response builders:

```ts
import { describe, expect, test } from "vitest";
import type {
  AdapterImplementation,
  AdapterResponse,
  JsonValue,
} from "../../src/protocol/types.js";
import {
  assertAdapterHello,
  assertByteIdenticalRoundtrip,
  RUST_ADAPTER_CONTRACT,
} from "../../src/scenarios/contracts.js";

const MINIMAL_PSBT =
  "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=";
const IMPLEMENTATION: AdapterImplementation = {
  name: "rust-bitcoin",
  version: "0.1.0",
  artifactDigest: `sha256:${"a".repeat(64)}`,
  sourceRevision: "bitcoin-crate-0.32.101",
};

function success(
  output: Record<string, JsonValue>,
  implementation: AdapterImplementation = IMPLEMENTATION,
): AdapterResponse {
  return {
    protocol: "psbt-lab.adapter/0.1",
    id: "request-1",
    status: "ok",
    implementation,
    output,
  };
}

function hello(
  implementation: Partial<AdapterImplementation> = {},
  output: Record<string, JsonValue> = {
    operations: [...RUST_ADAPTER_CONTRACT.operations],
    psbtVersions: [0],
  },
): AdapterResponse {
  return success(output, { ...IMPLEMENTATION, ...implementation });
}
```

Cover these behaviors:

```ts
test("rejects a lying byte-identical response", () => {
  const source = MINIMAL_PSBT;
  const changedBytes = Buffer.from(source, "base64");
  changedBytes[8] = changedBytes[8] === 1 ? 2 : 1;
  const changed = changedBytes.toString("base64");
  const response = success({ psbt: changed, byteIdentical: true });

  expect(() => assertByteIdenticalRoundtrip(response, source, "rust-bitcoin")).toThrow(/changed/i);
});

test("returns a genuinely identical PSBT", () => {
  const response = success({ psbt: MINIMAL_PSBT, byteIdentical: true });
  expect(assertByteIdenticalRoundtrip(response, MINIMAL_PSBT, "rust-bitcoin")).toBe(MINIMAL_PSBT);
});

test("rejects a wrong adapter source revision", () => {
  const response = hello({ sourceRevision: "bitcoin-crate-0.32.100" });
  expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/source revision/i);
});

test("rejects a missing required operation", () => {
  const response = hello({}, { operations: ["hello", "roundtrip"], psbtVersions: [0] });
  expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/operation sign/i);
});

test("rejects an adapter without PSBTv0 support", () => {
  const response = hello({}, {
    operations: [...RUST_ADAPTER_CONTRACT.operations],
    psbtVersions: [2],
  });
  expect(() => assertAdapterHello(response, RUST_ADAPTER_CONTRACT)).toThrow(/PSBTv0/i);
});
```

The changed-value case flips the unsigned transaction version byte while preserving valid PSBT
framing, so it reaches the independent equality check.

- [ ] **Step 6: Run contract tests and verify red**

Run: `pnpm test test/scenarios/contracts.test.ts`

Expected: import failure because the new module does not exist.

- [ ] **Step 7: Implement focused contract validators**

Create `src/scenarios/contracts.ts` with these public contracts:

```ts
import type {
  AdapterOperation,
  AdapterResponse,
  AdapterSuccessResponse,
  JsonValue,
} from "../protocol/types.js";
import { extractWireFacts } from "../psbt/wire-facts.js";

export interface ExpectedAdapterContract {
  name: string;
  version: string;
  sourceRevision: string;
  operations: readonly AdapterOperation[];
}

export const RUST_ADAPTER_CONTRACT = {
  name: "rust-bitcoin",
  version: "0.1.0",
  sourceRevision: "bitcoin-crate-0.32.101",
  operations: ["hello", "roundtrip", "sign", "fixture-finalize-input"],
} as const satisfies ExpectedAdapterContract;

export const BDK_ADAPTER_CONTRACT = {
  name: "bdkpython",
  version: "2.3.1",
  sourceRevision: "bdk-ffi-v2.3.1",
  operations: ["hello", "roundtrip", "finalize"],
} as const satisfies ExpectedAdapterContract;

function requireSuccess(response: AdapterResponse, operation: string): AdapterSuccessResponse {
  if (response.status !== "ok") {
    throw new Error(
      `${response.implementation.name} ${operation} failed: ${response.error.class}: ${response.error.message}`,
    );
  }
  return response;
}

function outputString(response: AdapterSuccessResponse, key: string): string {
  const value = response.output[key];
  if (typeof value !== "string") {
    throw new Error(`${response.implementation.name} omitted string output ${key}`);
  }
  return value;
}

function stringArray(value: JsonValue | undefined, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Adapter hello omitted string array ${label}`);
  }
  return value as string[];
}

function numberArray(value: JsonValue | undefined, label: string): number[] {
  if (!Array.isArray(value) || value.some((entry) => !Number.isSafeInteger(entry))) {
    throw new Error(`Adapter hello omitted integer array ${label}`);
  }
  return value as number[];
}

export function assertAdapterHello(
  response: AdapterResponse,
  expected: ExpectedAdapterContract,
): AdapterSuccessResponse {
  const success = requireSuccess(response, "hello");
  const implementation = success.implementation;
  if (implementation.name !== expected.name) throw new Error("Unexpected adapter name");
  if (implementation.version !== expected.version) throw new Error("Unexpected adapter version");
  if (implementation.sourceRevision !== expected.sourceRevision) {
    throw new Error(`Unexpected ${expected.name} source revision`);
  }
  const operations = stringArray(success.output["operations"], "operations");
  for (const operation of expected.operations) {
    if (!operations.includes(operation)) throw new Error(`${expected.name} omitted operation ${operation}`);
  }
  const versions = numberArray(success.output["psbtVersions"], "psbtVersions");
  if (!versions.includes(0)) throw new Error(`${expected.name} does not support PSBTv0`);
  return success;
}

export function assertByteIdenticalRoundtrip(
  response: AdapterResponse,
  source: string,
  label: string,
): string {
  const success = requireSuccess(response, "roundtrip");
  const returned = outputString(success, "psbt");
  if (success.output["byteIdentical"] !== true) throw new Error(`${label} did not confirm byte identity`);
  extractWireFacts(source);
  extractWireFacts(returned);
  if (!Buffer.from(source, "base64").equals(Buffer.from(returned, "base64"))) {
    throw new Error(`${label} changed the PSBT during roundtrip`);
  }
  return returned;
}
```

Keep helper errors bounded and never include raw response values or PSBTs.

- [ ] **Step 8: Run contract tests and verify green**

Run: `pnpm test test/scenarios/contracts.test.ts`

Expected: all identity, capability, and byte-comparison cases pass.

- [ ] **Step 9: Wire validators into the proof**

Replace raw hello success checks and both `byteIdentical` branches:

```ts
const rustHello = assertAdapterHello(
  await request(rust, "hello", {}),
  RUST_ADAPTER_CONTRACT,
);
const bdkHello = assertAdapterHello(
  await request(bdk, "hello", {}),
  BDK_ADAPTER_CONTRACT,
);

const happyRoundtripPsbt = assertByteIdenticalRoundtrip(
  await request(rust, "roundtrip", { psbt: fixtures.happy.initialPsbt }),
  fixtures.happy.initialPsbt,
  "rust-bitcoin",
);

const bdkRoundtripPsbt = assertByteIdenticalRoundtrip(
  await request(bdk, "roundtrip", { psbt: fixtures.regression.initialPsbt }),
  fixtures.regression.initialPsbt,
  "BDK Python",
);
```

Pass the returned validated strings into the existing sign operations. Remove the now-unused
`outputBoolean` helper from `proof.ts`; keep `outputString` for signing/finalization outputs.

- [ ] **Step 10: Run scenario and full TypeScript tests**

Run: `pnpm test test/scenarios test/protocol`

Expected: all tests pass.

- [ ] **Step 11: Commit Task 2**

```bash
git add src/protocol/schema.ts src/scenarios/contracts.ts src/scenarios/proof.ts test/protocol test/scenarios test/fixtures/fake-adapter.mjs
git commit -m "fix: verify adapter PSBT contracts"
```

---

### Task 3: Bound PSBT decoding and harden replay file access

**Files:**
- Modify: `test/psbt/wire-facts.test.ts`
- Modify: `src/psbt/wire-facts.ts`
- Modify: `test/runner/artifacts.test.ts`
- Modify: `src/runner/replay.ts`

**Interfaces:**
- Consumes: `extractWireFacts(encoded, limits)` and `verifyReplay(directory)`.
- Produces: encoded-size rejection before base64 decode, `MAX_REPLAY_CHECKPOINTS = 1_000`, and descriptor-based non-following replay reads.

- [ ] **Step 1: Write the failing encoded-size test**

Add:

```ts
test("rejects oversized canonical base64 before decoding", () => {
  const oversized = Buffer.alloc(9).toString("base64");
  expect(() => extractWireFacts(oversized, { maxPsbtBytes: 8 })).toThrow(/size limit/i);
});
```

This test establishes the public error; implementation review confirms the check occurs before
`Buffer.from(encoded, "base64")`.

- [ ] **Step 2: Move the encoded bound before allocation**

Pass the decoded limit into the decoder and reject any base64 string longer than the maximum
canonical encoded length:

```ts
function decodeCanonicalBase64(encoded: string, maxDecodedBytes: number): Buffer {
  const maxEncodedLength = 4 * Math.ceil(maxDecodedBytes / 3);
  if (encoded.length > maxEncodedLength) {
    throw new PsbtWireError("PSBT exceeds the configured size limit");
  }
  // Keep canonical syntax and roundtrip checks.
}

const buffer = decodeCanonicalBase64(encoded, resolved.maxPsbtBytes);
```

Keep the decoded byte-length check as defense in depth.

- [ ] **Step 3: Run parser tests**

Run: `pnpm test test/psbt/wire-facts.test.ts`

Expected: all parser tests pass.

- [ ] **Step 4: Write failing replay checkpoint-count and symlink tests**

Import `symlink` and `unlink`, then add:

```ts
test("replay rejects more than 1000 checkpoints before opening files", async () => {
  const root = await temporaryRoot();
  const run = await ArtifactRun.create(root, "run-many");
  const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
  const value = manifest("run-many", checkpoint);
  value.checkpoints = Array.from({ length: 1_001 }, () => checkpoint);
  await run.writeManifest(value);

  await expect(verifyReplay(run.directory)).rejects.toThrow(/checkpoint limit/i);
});

test("replay rejects a checkpoint symlink", async () => {
  const root = await temporaryRoot();
  const run = await ArtifactRun.create(root, "run-link");
  const checkpoint = await run.checkpoint("happy-path", "core-created", MINIMAL_PSBT);
  await run.writeManifest(manifest("run-link", checkpoint));
  const target = join(run.directory, "target.psbt");
  await writeFile(target, `${MINIMAL_PSBT}\n`);
  await unlink(join(run.directory, checkpoint.psbtPath));
  await symlink(target, join(run.directory, checkpoint.psbtPath));

  await expect(verifyReplay(run.directory)).rejects.toThrow(/regular file/i);
});
```

- [ ] **Step 5: Run replay tests and verify red**

Run: `pnpm test test/runner/artifacts.test.ts`

Expected: checkpoint-count test does not reject early; symlink behavior must produce the normalized
regular-file error after hardening.

- [ ] **Step 6: Read through one non-following descriptor and cap work**

Replace `lstat` then `readFile` with:

```ts
import { constants } from "node:fs";
import { open, realpath, stat, type FileHandle } from "node:fs/promises";

const MAX_REPLAY_CHECKPOINTS = 1_000;

async function readRegularFile(path: string, maxBytes: number): Promise<string> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error("Replay checkpoint must be a regular file");
    if (metadata.size > maxBytes) throw new Error("Replay checkpoint exceeds its size limit");
    return await handle.readFile("utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error("Replay checkpoint must be a regular file");
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

if (manifest.checkpoints.length > MAX_REPLAY_CHECKPOINTS) {
  throw new Error(`Replay manifest exceeds the ${MAX_REPLAY_CHECKPOINTS} checkpoint limit`);
}
```

The descriptor prevents a final-component symlink swap between metadata inspection and read. Do not
claim protection from malicious replacement of ancestor directories by the trusted local account.

- [ ] **Step 7: Run parser, replay, and full TypeScript tests**

Run: `pnpm test test/psbt/wire-facts.test.ts test/runner/artifacts.test.ts`

Expected: focused tests pass.

Run: `pnpm test`

Expected: complete TypeScript suite passes.

- [ ] **Step 8: Commit Task 3**

```bash
git add src/psbt/wire-facts.ts src/runner/replay.ts test/psbt/wire-facts.test.ts test/runner/artifacts.test.ts
git commit -m "fix: bound PSBT replay inputs"
```

---

### Task 4: Harden Core Compose, CI availability, and build contexts

**Files:**
- Modify: `compose.yaml`
- Modify: `.github/workflows/ci.yml`
- Create: `adapters/rust-bitcoin/.dockerignore`
- Create: `adapters/bdkpython-2.3.1/.dockerignore`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: existing Docker images, named `core-data` volume, and GitHub-hosted runners.
- Produces: explicit Core runtime limits, bounded CI jobs, and minimal adapter build contexts.

- [ ] **Step 1: Harden the Core service without changing RPC exposure**

Add under `core`:

```yaml
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    cap_drop:
      - ALL
    pids_limit: 128
    mem_limit: 1g
    security_opt:
      - no-new-privileges:true
```

Keep `core-data:/home/bitcoin/.bitcoin` writable and keep the RPC port bound to `127.0.0.1`.

- [ ] **Step 2: Validate normalized Compose configuration**

Run: `docker compose config --format json`

Expected: valid JSON; `services.core.read_only=true`, memory limit `1073741824`, process limit `128`,
all capabilities dropped, `no-new-privileges:true`, loopback host port, and the named data volume.

- [ ] **Step 3: Bound CI concurrency and job duration**

Add after `permissions`:

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Add `timeout-minutes: 10` to `typescript`, `timeout-minutes: 15` to `rust-adapter`, and
`timeout-minutes: 10` to `bdk-adapter`. Keep Docker proof at 20 minutes and keep its existing event
guard.

- [ ] **Step 4: Minimize adapter Docker contexts**

Create `adapters/rust-bitcoin/.dockerignore`:

```text
.git
target
```

Create `adapters/bdkpython-2.3.1/.dockerignore`:

```text
.git
__pycache__
*.py[cod]
```

Add these Python patterns to `.gitignore`:

```text
__pycache__/
*.py[cod]
```

- [ ] **Step 5: Run static and container smoke checks**

Run: `pnpm lint`

Expected: Biome passes all tracked files.

Run: `docker compose build core rust-adapter bdk-adapter`

Expected: all images build; native adapter tests pass inside builders.

Run: `docker compose up -d --wait core`

Expected: Core reaches healthy state with the read-only root and writable named data volume.

- [ ] **Step 6: Commit Task 4**

```bash
git add compose.yaml .github/workflows/ci.yml .gitignore adapters/rust-bitcoin/.dockerignore adapters/bdkpython-2.3.1/.dockerignore
git commit -m "chore: harden containers and CI"
```

---

### Task 5: Document the verified trust boundary and residual risks

**Files:**
- Create: `psbt-interop-lab-threat-model.md`
- Modify: `SECURITY.md`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/sources.md`

**Interfaces:**
- Consumes: the implemented runtime, adapter, replay, Compose, and CI controls.
- Produces: a repository-grounded threat model and accurate user-facing security claims.

- [ ] **Step 1: Write the threat model in the required section order**

Create `psbt-interop-lab-threat-model.md` with:

```markdown
# PSBT Interop Lab Threat Model

## 1. Executive Summary

This model covers the local generated-regtest MVP and its GitHub-hosted build pipeline. Under the
confirmed assumptions, no high or critical runtime threat remains: the operator, host account, and
Docker daemon are trusted, and the signer uses only a public valueless regtest key. The main security
objectives are result integrity, host containment, artifact confidentiality, and bounded execution.

## 2. Scope And Assumptions

List the confirmed local runtime and separate CI assumptions verbatim from the design spec. State
that arbitrary PSBTs, production keys, mainnet, public services, hardware devices, and compromised
host/Docker/kernel behavior are out of scope.

## 3. System Model

Describe CLI, Core RPC, Rust adapter, BDK adapter, wire parser, artifact store, replay, and CI. Include
a Mermaid flowchart showing host-to-Core loopback JSON-RPC, host-to-networkless-adapter JSONL, local
artifact writes, offline replay reads, and the separate GitHub runner boundary.

## 4. Assets And Security Objectives

Cover proof outcome/checkpoint integrity, host files, artifact metadata confidentiality, runner
availability, and CI/release integrity.

## 5. Attacker Model

Include malformed or buggy adapter output, accidental operator misconfiguration, untrusted pull
request code in CI, and local artifact corruption. Exclude trusted-host-account, Docker-daemon,
kernel, and base-image compromise from the supported guarantee.

## 6. Entry Points And Attack Surfaces

Anchor each surface to paths and symbols: `CoreRpc.call`, `AdapterProcess.request`,
`assertAdapterHello`, `assertByteIdenticalRoundtrip`, `extractWireFacts`, `verifyReplay`,
`ArtifactRun`, `compose.yaml`, and `.github/workflows/ci.yml`.

## 7. Top Abuse Paths

Explain false PASS through adapter self-report, mismatched Core RPC reply, oversized parser/replay
input, container escape/resource exhaustion, mutable artifact tampering, and CI compute abuse.

## 8. Threat Model Table

Use IDs `TM-001` through `TM-007`; include asset, preconditions, path, impact, controls, residual
risk, and status. Mark false PASS and mismatched RPC as mitigated low residual risk; resource paths
as mitigated low; artifact forgery as accepted low under trusted-local scope; production input and
Docker compromise as out of scope.

## 9. Criticality Calibration

Explain why local trusted-regtest scope caps realistic impact. State that arbitrary production PSBT
or public-service support would require a new threat model and could raise severity materially.

## 10. Focus Paths

Trace the independent roundtrip check, replay verification, and untrusted CI pull-request flow step
by step with evidence anchors.
```

Replace instruction prose in the finished document with concrete repository evidence and final
risk judgments. Do not claim manifest signatures, image attestation, production signing safety, or
protection from the trusted local account.

- [ ] **Step 2: Correct replay and adapter claims in existing docs**

Update README and architecture text to say replay verifies internal checkpoint consistency without
rerunning adapters; it does not authenticate a mutable artifact directory. Update `SECURITY.md` to
say adapter identity is a pinned compatibility assertion, while Dockerfile digests and dependency
hashes provide build reproducibility rather than runtime attestation.

Document the new controls with exact anchors:

```markdown
- The runner compares canonical returned PSBT bytes independently of adapter claims.
- Core RPC response IDs and Bitcoin Core numeric version `310100` are required.
- Replay opens final checkpoint paths without following symlinks and caps a manifest at 1,000
  checkpoints.
- Core and adapters have read-only roots, dropped capabilities, process/memory limits, and
  `no-new-privileges`; Core alone keeps its named regtest data volume writable.
```

- [ ] **Step 3: Update the official source ledger**

Add the official Node `fsPromises.open`/`FileHandle` documentation and Docker Compose service
resource/security references used for `read_only`, `tmpfs`, `cap_drop`, `pids_limit`, `mem_limit`,
and `security_opt`. Keep the research snapshot date and existing pins unchanged.

- [ ] **Step 4: Self-review security documentation**

Run: `rg -n "guarantee|secure|authentic|attest|trusted|arbitrary|mainnet|public" README.md SECURITY.md docs/architecture.md psbt-interop-lab-threat-model.md`

Expected: every strong claim has an explicit scope or limitation.

Run: `rg -n "TBD|TODO|FIXME|XXX" psbt-interop-lab-threat-model.md SECURITY.md README.md docs`

Expected: no placeholders.

- [ ] **Step 5: Commit Task 5**

```bash
git add psbt-interop-lab-threat-model.md SECURITY.md README.md docs/architecture.md docs/sources.md
git commit -m "docs: record MVP threat model"
```

---

### Task 6: Complete verification, integration, and repository cleanup

**Files:**
- Modify only if verification finds a scoped defect in a file changed by Tasks 1-5.
- Inspect: generated `artifacts/<run-id>/manifest.json`, `report.json`, and `report.md`.
- Local Git configuration: remove stale `/private/tmp/psbt-interop-lab-build` remote and branch upstream after commits are integrated.

**Interfaces:**
- Consumes: all hardened code, configuration, containers, and documentation.
- Produces: a clean working tree, passing proof/replay evidence, and no misleading temporary Git remote.

- [ ] **Step 1: Run TypeScript quality gates**

Run each command separately:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
git diff --check
```

Expected: zero lint/type/build errors, all tests pass, and no whitespace errors.

- [ ] **Step 2: Run native adapter quality gates**

Run:

```bash
cargo fmt --check --manifest-path adapters/rust-bitcoin/Cargo.toml
cargo clippy --locked --all-targets --manifest-path adapters/rust-bitcoin/Cargo.toml -- -D warnings
cargo test --locked --manifest-path adapters/rust-bitcoin/Cargo.toml
python3 -m unittest -v adapters/bdkpython-2.3.1/test_adapter.py
```

Expected: Rust formatting/Clippy/tests and Python tests pass.

- [ ] **Step 3: Run dependency advisory checks**

Run the repository's established npm, RustSec, and OSV commands recorded in the original MVP
verification notes. Do not update dependencies as part of this hardening unless a confirmed advisory
directly affects the supported scope.

Expected: no relevant known advisories, or a documented residual finding with severity and scope.

- [ ] **Step 4: Rebuild and run the complete proof**

Run:

```bash
docker compose build --no-cache core rust-adapter bdk-adapter
pnpm proof
```

Expected terminal outcome:

```text
PSBT Interop Lab: PASSED
PASS  happy-path
PASS  bdk-finalize-regression
```

- [ ] **Step 5: Replay and inspect the new artifact**

Run `node dist/cli.js replay artifacts/<new-run-id>` using the directory printed by `pnpm proof`.

Expected: five checkpoints verified and both scenarios passed.

Inspect reports with `rg` for `cHNidP`, `private`, `secret`, and WIF-shaped values. Expected: raw
PSBT appears only in private `.psbt` checkpoint files; reports contain no raw PSBT or key value.

- [ ] **Step 6: Stop Core and review final diff**

Run:

```bash
docker compose stop core
git status --short
git diff HEAD~5 --stat
git diff HEAD~5 --check
```

Expected: Core stops cleanly; only approved files changed; no generated artifacts are tracked.

- [ ] **Step 7: Integrate commits into `/Users/gautammanch/psbt-interop-lab`**

Before integration, require the primary working tree to be clean. Fetch the implementation branch
from the isolated working copy, then fast-forward or cherry-pick only the reviewed commits. Re-run
`git status --short --branch` in the primary tree.

- [ ] **Step 8: Remove stale temporary remote tracking**

Only when `git remote get-url origin` exactly equals `/private/tmp/psbt-interop-lab-build`, run:

```bash
git branch --unset-upstream
git remote remove origin
```

Expected: `git remote -v` is empty and `git status --short --branch` shows local `codex/mvp` without
a stale upstream. Do not add a replacement remote without the user's actual repository URL.
