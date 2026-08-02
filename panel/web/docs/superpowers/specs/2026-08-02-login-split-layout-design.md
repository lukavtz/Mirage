# Login Split Layout Design

## Goal
Match the supplied login reference while preserving the existing login and TOTP flows.

## Layout
- Desktop (`lg` and wider): a left, image-led brand panel and a right auth panel. The left panel uses `auth-light.webp` in light mode and `auth-dark.webp` in dark mode with `object-cover` so it fills the panel without distortion.
- Mobile: hide the decorative image panel; the auth panel remains full width.
- Keep the current form fields, validation, submission states, TOTP transition, language toggle, and theme persistence unchanged.

## Controls, motion, and copy
- Keep language switching as compact text control.
- Theme control is a two-segment Sun/Moon group. The active background moves between segments with Motion `layoutId`; each segment has spring hover/tap feedback and sets its named theme directly.
- Login fields and submit are `444px` wide on desktop. The description has a 56px visual margin before the first field.
- The password eye stays vertically centered in the input line. It uses a spring press and an `AnimatePresence` Eye/EyeOff swap; it remains keyboard-focusable.
- The submit button uses restrained spring lift/press feedback and arrow movement; disabled state has no interaction transform.
- Footer reads `© 2026 Mirage. All rights reserved.` and stays aligned to the lower-left of the image panel.

## Assets
- Convert `assets/auth/auth_white.png` to `public/auth-light.webp` and `assets/auth/auth_black.png` to `public/auth-dark.webp` with FFmpeg WebP at quality 90 and original 997×1577 dimensions.

## Verification
- `npm run build` succeeds.
- Manual browser smoke: image matches each theme, theme control works, and the image panel is absent at mobile width.
