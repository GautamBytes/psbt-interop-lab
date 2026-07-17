# PSBT Interop Lab Website Design

## Goal

Build a responsive public website that gives Bitcoin wallet and library maintainers enough evidence
to understand PSBT Interop Lab, install version 0.4.0, inspect current compatibility coverage, and
reach the project documentation and source.

## Visual Target

The selected visual target is the generated mock at:

`/Users/gautammanch/.codex/generated_images/019f5be1-8baf-7ae0-9435-bb071714aa6d/exec-0ecd2c2e-7e45-4c41-9530-160a8738fce1.png`

It combines the first concept's hero headline with the third concept's centered composition,
navigation, spacing, command bar, and semantic-diff report layout. The Swift AI SDK site is moodboard
inspiration only; its branding, copy, and artwork must not be reproduced.

## Page Structure

The page uses a sticky, compact navigation bar followed by an unframed full-width hero. The hero
contains the project label, the headline "Catch PSBT handoff failures before users do.", the exact
supporting copy approved by the user, primary and secondary actions, an install command, and four
factual coverage markers.

The first viewport reveals the start of a wide compatibility-report section. That report uses a
real known finding from the current suite: btcsuite PSBT 1.2.0 accepts a duplicate global unsigned
transaction key that the strict baseline expects native parsers to reject. It must be described as a
compatibility finding, not as a vulnerability or a fabricated signing failure.

Below the report, unframed sections explain the workflow, current implementation coverage, safety
boundary, and adapter extension path. The final call to action links to npm and GitHub.

## Interactions

- Navigation links scroll to page sections or open the real GitHub documentation.
- The install command copies to the clipboard and displays a short success state.
- The theme control switches between dark and light themes and respects reduced motion.
- Search opens a keyboard-accessible dialog containing links to the most relevant documentation.
- The report scenario list changes the visible evidence panel between representative pass, finding,
  and capability states without claiming results the project does not produce.
- The mobile navigation collapses into an accessible menu.

## Visual System

- Near-black base, cool neutral surfaces, white text, Bitcoin orange emphasis, green pass states,
  amber compatibility findings, and restrained red only for actual failures.
- Clean sans-serif headings and monospaced technical content.
- Borders and dividers carry structure; radii do not exceed 8px.
- No gradients, decorative orbs, nested cards, fake browser frames, or handcrafted icons.
- A generated bitmap provides the PSBT map and handoff texture behind the hero.
- Icons come from the closest established icon library rather than custom SVG markup.

## Architecture

The site is a standalone Vite + React + TypeScript app in `website/`. It has its own dependencies,
build, tests, and linting so the published CLI keeps its single production dependency and unchanged
npm tarball. Content is represented as typed local data; the initial site has no backend, wallet
connection, analytics, cookies, or user-supplied PSBT upload.

## Responsive And Accessibility Requirements

- Match the 1440 x 1024 selected target at desktop scale.
- Work without horizontal overflow at 390 x 844.
- Keep the headline, command, report table, and navigation readable at all supported widths.
- Provide visible focus states, semantic headings, labels, dialog behavior, and sufficient contrast.
- Respect `prefers-reduced-motion` and do not rely on motion to communicate status.

## Verification

- Unit tests cover command copying, search, theme selection, report scenario selection, and mobile
  navigation.
- Production build completes without warnings that indicate broken output.
- Desktop and mobile screenshots are compared against the selected mock.
- Browser console errors, overlap, clipping, and horizontal overflow are blocking failures.

