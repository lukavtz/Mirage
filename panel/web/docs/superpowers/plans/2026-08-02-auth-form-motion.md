# Auth Form Motion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to complete this task.

**Goal:** Give Mirage login an owned visual language, inline validation, and a theme reveal that starts at the chosen control.

**Architecture:** `Login.tsx` owns the two field errors and theme transition origin. `ThemeProvider` remains the persistence authority. `index.css` owns the native View Transition pseudo-elements and existing reduced-motion fallback suppresses the reveal.

**Tech Stack:** React 19, TypeScript, Motion 12, Tailwind CSS v4, native View Transitions API.

## Global Constraints
- No new dependencies.
- Keep login, TOTP, i18n, theme persistence, and responsive behavior intact.
- Do not show browser-native form validation UI.

---

### Task 1: Replace native validation with accessible inline field errors

**Files:**
- Modify: `src/lib/i18n.tsx`
- Modify: `src/pages/Login.tsx`

- [ ] Add English/Russian `auth.username_required` and `auth.password_required` messages.
- [ ] Add `fieldErrors` state, `noValidate`, pre-request validation, `aria-invalid`, `aria-describedby`, and animated field-local messages.
- [ ] Remove `required` from login inputs so the browser cannot show a native popup.

### Task 2: Restyle form and add theme reveal

**Files:**
- Modify: `src/pages/Login.tsx`
- Modify: `src/index.css`

- [ ] Convert username/password to 56px graphite input planes; retain autofocus and autocomplete.
- [ ] Turn the submit highlight into a contained sweep and retain the existing motion interactions.
- [ ] Route theme selection through `startViewTransition`, using selected button geometry as CSS variables.
- [ ] Add a root `clip-path` reveal plus instant fallback for reduced motion.

### Task 3: Verify

**Files:** none.

- [ ] Run `npm run build`.
- [ ] Browser smoke empty submit, field correction, eye toggle, and both theme choices.
