# PSBT Interop Lab Website Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a polished, responsive website that explains PSBT Interop Lab and gives developers a direct path to install, evaluate, and extend it.

**Architecture:** Add a standalone Vite React application under `website/`. Keep presentation components, typed factual content, and interaction state separate; the existing CLI package and npm files remain unchanged.

**Tech Stack:** React 19, TypeScript, Vite, Vitest, Testing Library, Phosphor Icons, CSS custom properties.

## Global Constraints

- Match the approved 1440 x 1024 visual target and support 390 x 844 without horizontal overflow.
- Use the exact approved hero text and only claims supported by PSBT Interop Lab 0.4.0.
- Keep the website dependency tree isolated from the CLI package.
- Use a generated bitmap for the hero texture and an icon library for interface icons.
- Use no gradients, decorative orbs, nested cards, or radii larger than 8px.
- Keep every primary interaction keyboard accessible.

---

### Task 1: Standalone Website Foundation

**Files:**
- Create: `website/package.json`
- Create: `website/vite.config.ts`
- Create: `website/src/main.tsx`
- Create: `website/src/App.tsx`
- Create: `website/src/styles.css`

**Interfaces:**
- Produces: a Vite application with `dev`, `build`, `test`, and `lint` commands.

- [ ] Bootstrap the Product Design React starter in `website/`.
- [ ] Pin dependencies and configure the development server for local visual verification.
- [ ] Add a smoke test that renders the approved hero headline.
- [ ] Run the smoke test and production build.

### Task 2: Visual System And Page Content

**Files:**
- Create: `website/public/hero-protocol-map.png`
- Create: `website/src/content.ts`
- Create: `website/src/components/Brand.tsx`
- Create: `website/src/components/Header.tsx`
- Create: `website/src/components/Hero.tsx`
- Create: `website/src/components/CompatibilityReport.tsx`
- Create: `website/src/components/Sections.tsx`
- Modify: `website/src/styles.css`

**Interfaces:**
- Produces: typed `scenarios`, `implementations`, `workflowSteps`, and `docLinks` content consumed by page components.

- [ ] Generate and install the bitmap hero texture from the approved mock.
- [ ] Implement the sticky header and centered hero with exact approved copy.
- [ ] Implement the compatibility-report console using the real duplicate-global-key finding.
- [ ] Implement workflow, coverage, safety, adapter, and final call-to-action sections.
- [ ] Add desktop, tablet, and mobile responsive styling.

### Task 3: Core Interactions

**Files:**
- Create: `website/src/components/SearchDialog.tsx`
- Create: `website/src/components/InstallCommand.tsx`
- Create: `website/src/components/ThemeToggle.tsx`
- Create: `website/src/components/MobileMenu.tsx`
- Create: `website/src/App.test.tsx`

**Interfaces:**
- Produces: working search, command copy, theme, report selection, and mobile navigation behavior.

- [ ] Add failing interaction tests for every core control.
- [ ] Implement accessible dialog, menu, button, and status behavior.
- [ ] Add visible hover, focus, selected, and copied states.
- [ ] Run the full website test suite and fix failures.

### Task 4: Verification And Repository Handoff

**Files:**
- Create: `website/design-qa.md`
- Modify: `README.md`

**Interfaces:**
- Produces: a tested production build, visual QA record, local preview URL, and repository documentation link.

- [ ] Run website tests, lint, typecheck, and production build.
- [ ] Start the development server and capture 1440 x 1024 and 390 x 844 screenshots.
- [ ] Compare both screenshots with the approved target and fix P0, P1, and P2 issues.
- [ ] Record the passing result in `website/design-qa.md`.
- [ ] Link the website development commands from the root README and commit the complete change.

