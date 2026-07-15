# Task 1 Report: Pin Bitcoin Core RPC and Runtime Identity

## Scope

Implemented Task 1 in the four requested files:

- `src/core/rpc.ts`
- `test/core/rpc.test.ts`
- `src/core/fixtures.ts`
- `test/core/fixtures.test.ts`

`CoreRpc` now requires an `id` field in a JSON-RPC response envelope and rejects it unless it exactly matches the generated request ID. Fixture preparation now exports and enforces `BITCOIN_CORE_VERSION = 310100` immediately after parsing `getnetworkinfo`; `subversion` remains unpinned.

## TDD Evidence

### RPC response identity

RED command:

```sh
pnpm test test/core/rpc.test.ts
```

The terminal wrapper did not surface the standard reporter summary, so the same focused run was repeated with Vitest's verbose reporter to capture the failure details:

```sh
pnpm exec vitest run test/core/rpc.test.ts --reporter=verbose
```

Relevant RED output: 4 failed, 5 passed. The null, wrong-string, numeric, and absent-ID cases each failed with `promise resolved "42" instead of rejecting`.

Minimal implementation: added `id: unknown` to `RpcEnvelope`, required the `id` property in `isRpcEnvelope`, and compared `decoded.id` with the generated request ID before error/result handling.

GREEN commands:

```sh
pnpm test test/core/rpc.test.ts
pnpm exec vitest run test/core/rpc.test.ts --reporter=verbose
```

Relevant GREEN output: 1 test file passed; 9 tests passed.

### Core runtime identity

RED command:

```sh
pnpm test test/core/fixtures.test.ts
```

Relevant RED output: 1 failed, 8 passed. The new version test reached `getdescriptorinfo` and failed with `Unexpected RPC getdescriptorinfo`, proving the version guard did not yet exist.

Minimal implementation: exported `BITCOIN_CORE_VERSION = 310100` and rejected any parsed `getnetworkinfo.version` other than that exact value with an error naming Bitcoin Core 31.1.

GREEN command:

```sh
pnpm test test/core/fixtures.test.ts
```

Relevant GREEN output: 1 test file passed; 9 tests passed.

## Final Verification

Focused aggregate command:

```sh
pnpm test test/core/rpc.test.ts test/core/fixtures.test.ts
pnpm exec vitest run test/core/rpc.test.ts test/core/fixtures.test.ts --reporter=verbose
```

Relevant output: 2 test files passed; 18 tests passed.

Full TypeScript test command:

```sh
pnpm test
pnpm exec vitest run --reporter=verbose
```

Relevant output: 8 test files passed; 56 tests passed.

Committed-diff review command:

```sh
git show --check --format=fuller 060cfae
```

Relevant output: exit code 0 with no whitespace errors. Review found no implementation issues: missing IDs remain invalid envelopes, mismatched IDs fail before both RPC-error and result handling, and the version check uses only the numeric machine contract.

## Commit

`060cfaeed4cf6a07ee90ef14806f8d6f2af5ca1c fix: pin Core RPC identity`

## Concerns

No code concerns found. The worktree contains an untracked `node_modules` directory, which was left untouched and was not committed. Git also warned that the commit identity was derived automatically from the local username and hostname.

## Formatting Fix Evidence

Applied only Biome's indicated wrapping change to the mismatched-ID `CoreRpcTransportError` throw in `src/core/rpc.ts`.

Lint command:

```sh
pnpm lint
```

Relevant output: `Checked 30 files in 17ms. No fixes applied.` Exit code 0.

RPC test command:

```sh
pnpm test test/core/rpc.test.ts
```

Relevant output: `Test Files  1 passed (1)` and `Tests  9 passed (9)`. Exit code 0.
