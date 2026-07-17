# Website Documentation Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-party Docs, Adapter Kit, and Security pages that render the repository's authoritative Markdown inside the existing website.

**Architecture:** Keep the current Vite React SPA and add a lightweight History API router. Import repository Markdown as raw strings, render it through a shared Markdown page component, and rewrite known documentation links to internal routes.

**Tech Stack:** React 19, TypeScript, Vite 7, react-markdown, remark-gfm, Vitest, Testing Library, CSS.

## Global Constraints

- `/docs`, `/adapter-kit`, and `/security` must be directly loadable and support browser back/forward.
- Content must come directly from `README.md`, `docs/adapters.md`, and `SECURITY.md`.
- Existing homepage visuals and interactions must remain unchanged.
- Tables and code blocks must never create page-level horizontal overflow.
- Existing GitHub links remain available for source inspection.

---

### Task 1: Route Contract And Failing Tests

**Files:**
- Modify: `website/src/App.test.tsx`
- Create: `website/src/routes.test.ts`

**Interfaces:**
- Produces: expected route paths, internal navigation behavior, and Markdown page assertions.

- [x] Add tests that set `/docs`, `/adapter-kit`, `/security`, and an unknown pathname before rendering `App`.
- [x] Assert each documentation route renders a heading and recognizable source-document text.
- [x] Assert header links use internal URLs and an internal click changes content without a full reload.
- [x] Run `npm test` and verify the new assertions fail because routing does not exist.

### Task 2: Routing And Markdown Rendering

**Files:**
- Create: `website/src/routes.ts`
- Create: `website/src/hooks/useRoute.ts`
- Create: `website/src/components/SiteLink.tsx`
- Create: `website/src/components/MarkdownPage.tsx`
- Create: `website/src/pages/NotFoundPage.tsx`
- Modify: `website/src/App.tsx`
- Modify: `website/vite.config.ts`
- Modify: `website/src/vite-env.d.ts`

**Interfaces:**
- Produces: `routes`, `resolveRoute(pathname)`, `navigate(href)`, `useRoute()`, and `MarkdownPage`.

- [x] Allow Vite to read Markdown from the repository parent and declare `*?raw` modules.
- [x] Implement route resolution and History API navigation with `popstate` support.
- [x] Import the three Markdown sources using `?raw` and render the selected page through `MarkdownPage`.
- [x] Add heading IDs, GitHub source links, internal Markdown link rewriting, and a not-found page.
- [x] Run the focused route tests and verify they pass.

### Task 3: Shared Navigation And Documentation Layout

**Files:**
- Modify: `website/src/components/Header.tsx`
- Modify: `website/src/components/MobileMenu.tsx`
- Modify: `website/src/components/SearchDialog.tsx`
- Modify: `website/src/components/Sections.tsx`
- Modify: `website/src/content.ts`
- Modify: `website/src/App.tsx`
- Modify: `website/src/styles.css`

**Interfaces:**
- Consumes: internal route constants and `SiteLink`.
- Produces: consistent internal navigation and responsive documentation presentation.

- [x] Replace Docs, Adapter Kit, and Security GitHub destinations with internal routes.
- [x] Keep Matrix as a homepage anchor and make it work from documentation routes.
- [x] Add title band, sticky table of contents, article typography, code, table, blockquote, and mobile styles.
- [x] Add active navigation state and retain the GitHub icon/source links.
- [x] Run the full website test suite and resolve regressions.

### Task 4: Verification And Handoff

**Files:**
- Modify: `website/design-qa.md`

**Interfaces:**
- Produces: verified build and QA evidence for the three new routes.

- [x] Run `npm test`, `npm run lint`, `npm run build`, `npm audit --omit=dev`, and `git diff --check`.
- [x] Verify `/docs`, `/adapter-kit`, and `/security` at desktop and mobile widths in the browser.
- [x] Confirm direct loading, back/forward, internal search links, zero console errors, and zero horizontal overflow.
- [x] Record results in `website/design-qa.md` and commit the completed feature.
