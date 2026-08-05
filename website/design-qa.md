# Website Design QA

## Reference

- Approved target: `exec-0ecd2c2e-7e45-4c41-9530-160a8738fce1.png`
- Direction: centered protocol-map hero and semantic-diff report treatment
- Review date: 2026-08-05

## Fresh visual checks

- Homepage at 1440 x 1024: the hero, audience paths, and compatibility report introduction render
  without overlap or clipping.
- Homepage at an emulated 390 x 844 viewport: the hero copy, actions, install command, metrics,
  search control, and mobile navigation trigger remain inside the viewport.
- Contributing page at 1440 x 1024: the introduction, table of contents, prose, and code blocks keep
  the established documentation layout.
- The walkthrough uses direct summary and MuSig2 captures from a complete v0.9.0 matrix artifact
  created on the review date. The artifact records 47 passed scenarios, zero failures, and one
  known finding.

## Interaction checks

- Audience cards route wallet, library, and protocol-review users to focused starting points.
- Documentation search matches headings, descriptions, and Markdown content.
- Search and image dialogs trap keyboard focus, close on Escape, and restore the opening control.
- Mobile navigation closes on Escape and returns focus to its trigger.
- The initial theme follows the operating-system preference until the visitor chooses a theme.
- First-party documentation routes update the browser title and description. The static homepage
  metadata remains the social-card source for this client-rendered site.

## Technical checks

- Automated website tests: 55 passed.
- TypeScript: passed.
- Production build: passed.
- Complete Docker matrix: 47 passed, zero failed, one known compatibility finding.

## Findings

- P0: none
- P1: none
- P2: none

Result: passed.
