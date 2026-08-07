# Frontend Quality Pass Design

## Goal

Make the existing Mirage panel frontend production-quality without redesigning its visual language or adding dependencies.

## Scope

- Show explicit loading, error, empty, and retry states for dashboard/session/data queries.
- Make interactive rows and icon-only controls keyboard and screen-reader accessible.
- Add missing accessible names and status/alert semantics.
- Replace page-local hardcoded colors with existing design tokens where touched.
- Enable strict TypeScript and a deterministic coverage gate only if the current baseline can be captured without weakening behavior checks.

## Boundaries

Keep the current routes, API response shapes, responsive shell, design tokens, motion behavior, and component library. Do not add ESLint, rewrite charts, redesign navigation, or change backend contracts.

## Testing

Each behavior gets a focused Vitest regression test first: failed query renders an actionable error and retry; interactive rows expose links/buttons; icon-only controls have accessible names; loading/error regions expose `status`/`alert`. Run focused tests red, implement the smallest change, then run the full frontend suite and production build.
