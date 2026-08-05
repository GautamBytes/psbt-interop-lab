# Contributing

PSBT Interop Lab accepts focused compatibility scenarios, adapter integrations, diagnostic fixes,
and documentation corrections. Open an issue before starting a large adapter or protocol expansion
so maintainers can agree on the fixture boundary and evidence requirements.

## Development setup

Install Node.js 22 or 24, pnpm 10.30.2, and Docker with Compose. Then run:

```bash
pnpm install --frozen-lockfile
pnpm check:validators
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

The website has a separate dependency lockfile and test suite:

```bash
cd website
npm ci
npm test
npm run typecheck
npm run build
```

## What a compatibility contribution must include

A scenario or adapter change should provide:

- A deterministic public regtest fixture with no wallet or production transaction data.
- An executable assertion that fails when the claimed behavior regresses.
- The implementation identity and capability boundary used by the assertion.
- A stable rule ID and authoritative source for standards claims.
- Replayable evidence with secrets and host-specific paths excluded from reports.

Do not classify a differential parser result as an upstream bug without independent evidence. The
lab records observed behavior first and keeps ambiguous results neutral.

## Adding an adapter

Start from the generated TypeScript adapter project:

```bash
pnpm build
node dist/cli.js adapter init ./example-adapter --name example-adapter
cd ./example-adapter
npm ci
npm test
npm run conformance
```

Replace the generated parser and identity with the implementation under test. Keep the JSONL
transport on standard input and output, write diagnostics to standard error, and declare only
capabilities the process implements. Read [the adapter guide](docs/adapters.md) before adding a
signing operation.

## Pull requests

Keep each pull request reviewable. Include the commands you ran and distinguish unit-only checks
from the complete Docker matrix. Update the source ledger when a version or standards claim
changes. Generated conformance data and validators must remain reproducible from their source
registries.

Report security problems through the process in [SECURITY.md](SECURITY.md), not a public issue.
