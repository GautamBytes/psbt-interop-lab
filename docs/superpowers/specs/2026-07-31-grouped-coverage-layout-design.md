# Grouped Coverage Layout

## Goal

Replace the homepage coverage section's sixteen equal-weight checklist rows with a compact,
scannable layout that preserves every technical claim while removing the multi-screen vertical
list and the empty space below the section introduction.

## Content Structure

Keep the existing section introduction and documentation link. Group the sixteen existing coverage
claims into four named areas:

1. **Transaction coverage**
   - Legacy P2PKH, nested SegWit, P2WSH, and Taproot fixtures
   - Signing, combining, finalization, and policy acceptance
   - Transaction intent, RBF, locktime, sighash, and derivations
   - Unknown and proprietary metadata preservation
2. **Adversarial safety**
   - Cryptographically measured ECDSA and Taproot sighash mutations
   - Adversarial signer and deterministic combiner conflicts
   - Malformed native-parser rejection without crashes
   - Promote exact parser classifications and structural facts
3. **Protocol frontiers**
   - BIP373 MuSig2 nonce exchange, partial verification, and aggregation
   - HWI-compatible simulator confirmation and key-origin policy
   - All official BIP370 and BIP371 valid and invalid vectors
   - Native PSBTv2 constructors and bidirectional Taproot handoffs
4. **Developer workflow**
   - Wallet CI Action with external-only, JUnit, and SARIF output
   - Target one scenario or category for faster iteration
   - Run bounded bundled parser checks without Docker
   - Capture baselines and compare replay-verified artifacts

## Layout

Desktop keeps the existing two-column section composition. The left introduction uses a narrower
track, while the right side becomes a two-by-two unframed grid. Hairline rules divide the four
groups; the groups do not use floating cards, shadows, or rounded containers. Each group has a
small monospace category label, a short heading, and four compact checked rows.

At tablet widths, the introduction and coverage grid stack. The grouped grid remains two columns
while space permits. At mobile widths, it becomes one column and replaces internal vertical rules
with horizontal separators.

## Visual Treatment

- Preserve the current dark/light themes and orange project accent.
- Use orange only for category labels and the existing link.
- Keep green check icons as semantic pass markers, but reduce their prominence and row spacing.
- Use the existing body and monospace typography.
- Avoid animation; this section is for fast scanning and should remain stable.

## Accessibility

- Render each coverage area as a labelled section with an `h3`.
- Keep each area's claims in a semantic list.
- Preserve the existing section `aria-labelledby` relationship.
- Ensure text and dividers maintain the existing theme contrast.

## Validation

- Update the homepage test to assert all four group headings and representative claims.
- Run website tests, typecheck, lint, and production build.
- Verify the section at desktop and mobile widths in both themes.
- Confirm the section is materially shorter and no longer leaves a large empty left column.
