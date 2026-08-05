# Release Process

Only a maintainer with npm and GitHub release access can publish PSBT Interop Lab. Release commits
must come from `main`, and the npm version, Git tag, and GitHub release must match.

## Prepare the release pull request

1. Update `package.json`, the lockfile, `CHANGELOG.md`, versioned install examples, and website
   release facts.
2. Run the complete verification set:

   ```bash
   pnpm check:validators
   pnpm lint
   pnpm typecheck
   pnpm test
   pnpm build
   node dist/cli.js matrix --no-build
   cd website
   npm ci
   npm test
   npm run typecheck
   npm run build
   ```

3. Run `npm pack --dry-run` and inspect the included files. The package must exclude local
   artifacts and development credentials.
4. Merge the release pull request after CI passes.

## Publish from the merge commit

Confirm that the checkout matches `origin/main` and has no tracked or untracked release inputs.
Then create the package and checksum:

```bash
npm pack
shasum -a 256 psbt-interop-lab-<version>.tgz
npm publish ./psbt-interop-lab-<version>.tgz --access public
```

Verify the published version with `npm view psbt-interop-lab@<version> version`. Create and push the
matching annotated tag, then create the GitHub release from that tag. Attach the package tarball
and SHA256 checksum when they are part of the release record.

Provenance requires npm trusted publishing from a supported hosted CI runner. Do not add
`--provenance` to the local command unless the release process has moved to that environment.

## Post-publish checks

Run the pinned public entry point in a clean directory:

```bash
npx --yes psbt-interop-lab@<version> --version
npx --yes psbt-interop-lab@<version> self-test
```

Confirm that the npm page, GitHub release, tag, changelog, and website all name the same version.
If publication fails after npm accepts the version, do not reuse or overwrite it. Document the
failure and prepare a patch release.
