# Grouped Coverage Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the homepage's sixteen-row coverage ledger with four compact semantic groups while preserving every claim.

**Architecture:** Keep the content local to `Sections.tsx` as a typed `coverageGroups` constant and render each group as a labelled section containing a semantic list. Replace the single-column ledger CSS with an unframed two-by-two grid that collapses to two columns at tablet widths and one column on mobile.

**Tech Stack:** React 19, TypeScript, Phosphor icons, CSS, Vitest, Testing Library, Vite

## Global Constraints

- Preserve all sixteen existing coverage claims verbatim.
- Keep the current dark and light theme tokens.
- Use unframed groups with hairline dividers, not floating cards, shadows, or rounded containers.
- Keep orange for category labels and green check icons for verified claims.
- Use semantic `section`, `h3`, `ul`, and `li` elements.
- Add no dependency and no animation.

---

### Task 1: Lock The Grouped Information Architecture In Tests

**Files:**
- Modify: `website/src/App.test.tsx`
- Test: `website/src/App.test.tsx`

**Interfaces:**
- Consumes: The homepage rendered by `App`.
- Produces: A regression test requiring four named coverage groups, four claims per group, and representative claims in the correct group.

- [ ] **Step 1: Write the failing grouped-coverage test**

Add this test after the main homepage rendering test:

```tsx
it("groups the complete coverage surface into four scannable areas", () => {
  render(<App />);

  const groups = [
    ["Transaction coverage", "Legacy P2PKH, nested SegWit, P2WSH, and Taproot fixtures"],
    [
      "Adversarial safety",
      "Cryptographically measured ECDSA and Taproot sighash mutations",
    ],
    ["Protocol frontiers", "BIP373 MuSig2 nonce exchange, partial verification, and aggregation"],
    ["Developer workflow", "Wallet CI Action with external-only, JUnit, and SARIF output"],
  ] as const;

  for (const [heading, representativeClaim] of groups) {
    const group = screen.getByRole("heading", { level: 3, name: heading }).closest("section");
    expect(group).not.toBeNull();
    expect(within(group as HTMLElement).getAllByRole("listitem")).toHaveLength(4);
    expect(within(group as HTMLElement).getByText(representativeClaim)).toBeInTheDocument();
  }
});
```

- [ ] **Step 2: Run the test and verify the old flat list fails**

Run:

```bash
npm test -- --run src/App.test.tsx
```

Expected: FAIL because the four level-three coverage headings do not exist.

- [ ] **Step 3: Commit the failing test with the implementation in Task 2**

Do not commit a knowingly red branch. Carry this test into Task 2 and commit the completed grouped section together.

### Task 2: Render Four Semantic Coverage Groups

**Files:**
- Modify: `website/src/components/Sections.tsx`
- Modify: `website/src/App.test.tsx`

**Interfaces:**
- Consumes: `coverageGroups`, a readonly array of `{ id, label, title, items }`.
- Produces: Four `.coverage-group` sections inside `.coverage-groups`.

- [ ] **Step 1: Replace the flat coverage array**

Define the grouped data:

```tsx
const coverageGroups = [
  {
    id: "transactions",
    label: "Transaction paths",
    title: "Transaction coverage",
    items: [
      "Legacy P2PKH, nested SegWit, P2WSH, and Taproot fixtures",
      "Signing, combining, finalization, and policy acceptance",
      "Transaction intent, RBF, locktime, sighash, and derivations",
      "Unknown and proprietary metadata preservation",
    ],
  },
  {
    id: "safety",
    label: "Failure probes",
    title: "Adversarial safety",
    items: [
      "Cryptographically measured ECDSA and Taproot sighash mutations",
      "Adversarial signer and deterministic combiner conflicts",
      "Malformed native-parser rejection without crashes",
      "Promote exact parser classifications and structural facts",
    ],
  },
  {
    id: "protocols",
    label: "Modern protocols",
    title: "Protocol frontiers",
    items: [
      "BIP373 MuSig2 nonce exchange, partial verification, and aggregation",
      "HWI-compatible simulator confirmation and key-origin policy",
      "All official BIP370 and BIP371 valid and invalid vectors",
      "Native PSBTv2 constructors and bidirectional Taproot handoffs",
    ],
  },
  {
    id: "workflow",
    label: "Maintainer tools",
    title: "Developer workflow",
    items: [
      "Wallet CI Action with external-only, JUnit, and SARIF output",
      "Target one scenario or category for faster iteration",
      "Run bounded bundled parser checks without Docker",
      "Capture baselines and compare replay-verified artifacts",
    ],
  },
] as const;
```

- [ ] **Step 2: Replace the flat list markup**

Render the data as semantic grouped sections:

```tsx
<div className="coverage-groups">
  {coverageGroups.map((group) => {
    const headingId = `coverage-${group.id}`;
    return (
      <section className="coverage-group" key={group.id} aria-labelledby={headingId}>
        <span className="coverage-group__label">{group.label}</span>
        <h3 id={headingId}>{group.title}</h3>
        <ul>
          {group.items.map((item) => (
            <li key={item}>
              <CheckCircle aria-hidden="true" weight="fill" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </section>
    );
  })}
</div>
```

- [ ] **Step 3: Run the focused test**

Run:

```bash
npm test -- --run src/App.test.tsx
```

Expected: PASS, including the new four-group test.

### Task 3: Build The Responsive Unframed Grid

**Files:**
- Modify: `website/src/styles.css`

**Interfaces:**
- Consumes: `.coverage-groups`, `.coverage-group`, `.coverage-group__label`.
- Produces: A two-by-two desktop/tablet grid and one-column mobile stack.

- [ ] **Step 1: Replace the flat-list CSS**

Replace `.coverage-list` rules with:

```css
.coverage-groups {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  border-top: 1px solid var(--border-strong);
  border-bottom: 1px solid var(--border-strong);
}

.coverage-group {
  min-width: 0;
  padding: 28px 30px 30px;
}

.coverage-group:nth-child(odd) {
  border-right: 1px solid var(--border);
}

.coverage-group:nth-child(-n + 2) {
  border-bottom: 1px solid var(--border);
}

.coverage-group__label {
  display: block;
  margin-bottom: 10px;
  color: var(--orange);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
}

.coverage-group h3 {
  margin: 0 0 22px;
  font-size: 17px;
}

.coverage-group ul {
  margin: 0;
  padding: 0;
  list-style: none;
}

.coverage-group li {
  display: grid;
  grid-template-columns: 16px minmax(0, 1fr);
  align-items: start;
  gap: 10px;
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.55;
}

.coverage-group li + li {
  margin-top: 13px;
}

.coverage-group li svg {
  width: 16px;
  height: 16px;
  margin-top: 2px;
  color: var(--green);
}
```

- [ ] **Step 2: Add mobile collapse rules**

Inside `@media (max-width: 560px)`, add:

```css
.coverage-groups {
  grid-template-columns: 1fr;
}

.coverage-group,
.coverage-group:nth-child(odd),
.coverage-group:nth-child(-n + 2) {
  border-right: 0;
  border-bottom: 1px solid var(--border);
}

.coverage-group:last-child {
  border-bottom: 0;
}

.coverage-group {
  padding: 24px 4px;
}
```

- [ ] **Step 3: Run all website checks**

Run:

```bash
npm test
npm run typecheck
npm run build
```

Expected: 38 or more tests pass, typecheck exits zero, and Vite builds successfully.

- [ ] **Step 4: Commit the grouped section**

```bash
git add website/src/components/Sections.tsx website/src/styles.css website/src/App.test.tsx
git commit -m "style: group homepage coverage"
```

### Task 4: Visual Verification And Pull Request

**Files:**
- Verify: `website/src/components/Sections.tsx`
- Verify: `website/src/styles.css`

**Interfaces:**
- Consumes: The built website.
- Produces: Desktop and mobile screenshots plus a reviewable pull request.

- [ ] **Step 1: Start the website**

Run:

```bash
npm run dev -- --host 127.0.0.1
```

Expected: Vite prints a reachable local URL.

- [ ] **Step 2: Capture and inspect screenshots**

Use Playwright at `1440x1000`, `820x1000`, and `390x844`. Verify:

- all four groups are visible and balanced;
- no text clips or overlaps;
- the desktop section is materially shorter than the old ledger;
- tablet keeps a readable two-column grid;
- mobile stacks one group per row;
- dark and light themes retain adequate contrast.

- [ ] **Step 3: Run the web-interface-guidelines review**

Fetch the current guideline source and review the modified component and CSS. Fix actionable
accessibility, layout, or interaction findings before the final commit.

- [ ] **Step 4: Push and raise the PR**

```bash
git push -u origin codex/grouped-coverage-layout
gh pr create \
  --base main \
  --head codex/grouped-coverage-layout \
  --title "style: group homepage coverage" \
  --body "<verified summary and test results>"
```

Expected: GitHub returns the new pull request URL.
