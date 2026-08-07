# Auth Form and Theme Motion Design

## Goal
Replace the stock-looking login controls and browser-required popup with a Mirage-specific authentication surface and a theme transition that visibly originates at the selected Sun or Moon segment.

## Form
- Login form uses `noValidate`; `handleSubmit` validates trimmed username and password before any API call.
- Missing values show localized inline messages below their respective fields. Inputs expose `aria-invalid` and reference the message with `aria-describedby`. Native browser validation bubbles never appear.
- Each input is a 56px graphite plane with a 1px token border, 12px radius, 16px horizontal padding, and a focus ring. Username and password retain their existing autofill metadata.
- Password eye is centered in the input plane, remains keyboard-focusable, and keeps its existing Motion icon transition.
- Submit is a 56px high, full-width graphite button with a controlled highlight sweep, existing spring press/lift, and arrow movement.

## Theme transition
- Selecting a theme keeps the segmented control and persists through `ThemeProvider`.
- When browser View Transitions are available and reduced motion is not requested, `startViewTransition` wraps the synchronous `setTheme` update. The new root reveals through a CSS `clip-path: circle()` expanding from the selected button’s center.
- Without View Transitions or with reduced motion, the theme updates immediately.

## Constraints
- No new dependencies.
- Preserve API, login/TOTP flow, language selection, and mobile image hiding.

## Verification
- Build passes.
- Browser: empty submit renders two inline errors with no native popup; valid field edits clear their respective error; eye toggles input type; light/dark controls switch artwork and active segment; theme transition is enabled only when motion is allowed.
