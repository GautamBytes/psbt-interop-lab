# Website Documentation Routes Design

## Goal

Keep visitors inside the PSBT Interop Lab website when they open Docs, Adapter Kit, or Security, while displaying the repository's authoritative documentation rather than duplicated website copy.

## Routes And Sources

- `/docs` renders `README.md`.
- `/adapter-kit` renders `docs/adapters.md`.
- `/security` renders `SECURITY.md`.
- `/` remains the existing project homepage.

The Vite application imports each Markdown file as raw text from the repository root. The website therefore changes whenever the source document changes, and no generated copy is committed.

## Experience

All routes share the existing sticky header, theme control, search dialog, mobile navigation, and footer. Documentation pages use a constrained article layout with a title band, sticky section navigation on desktop, readable Markdown typography, syntax-friendly code blocks, responsive tables, and a GitHub source link. The current orange, black, white, green, and neutral visual system remains unchanged.

Internal documentation links are rewritten to website routes when a corresponding page exists. Repository links without a website page continue to GitHub. Header, mobile menu, search results, adapter calls to action, and footer links use internal routes.

## Architecture

`App` owns the shared shell and chooses a page from `window.location.pathname`. A small route helper provides route constants, History API navigation, popstate handling, and internal-link detection without adding a router dependency. `MarkdownPage` renders raw Markdown through `react-markdown` and `remark-gfm`; custom components provide internal links, heading IDs, code, table, and article styling.

## Accessibility And Failure Handling

Navigation updates the document title, moves focus to the main content heading, and preserves browser back/forward behavior. Links remain normal anchors, so open-in-new-tab and copied URLs work. Unknown paths render a small not-found page with a link home. Wide code and tables scroll within their own containers rather than widening the viewport.

## Verification

Automated tests cover all three routes, internal navigation, source Markdown rendering, link rewriting, unknown paths, and existing homepage interactions. Production build, TypeScript, npm audit, and desktop/mobile browser screenshots must pass with no console errors or horizontal overflow.
