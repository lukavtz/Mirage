# Login Split Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to complete this task.

**Goal:** Apply the supplied light and dark artwork to the desktop login panel and refine the controls and footer to match the reference.

**Architecture:** `Login.tsx` continues to own login and TOTP state. Static WebP files are served by Vite from `public/`; a native `<picture>` element selects the correct image from React theme state. No auth, routing, i18n, or dependency changes.

**Tech Stack:** React 19, TypeScript, Tailwind CSS v4, Vite, FFmpeg.

## Global Constraints
- Preserve existing form, TOTP, language, and theme behavior.
- No new packages.
- Hide the decorative panel below Tailwind `lg`.

---

### Task 1: Publish optimized artwork

**Files:**
- Create: `public/auth-light.webp`
- Create: `public/auth-dark.webp`

- [ ] Convert the two supplied 997×1577 PNG files with FFmpeg:

```powershell
ffmpeg -y -i ..\..\assets\auth\auth_white.png -c:v libwebp -q:v 90 public\auth-light.webp
ffmpeg -y -i ..\..\assets\auth\auth_black.png -c:v libwebp -q:v 90 public\auth-dark.webp
```

- [ ] Verify both are WebP and retain 997×1577 dimensions with `ffprobe`.

### Task 2: Apply the split login composition

**Files:**
- Modify: `src/pages/Login.tsx`

- [ ] Replace the CSS-only left-panel decoration with a themed `<img>` using the published WebP asset, `object-cover`, and a readable dark overlay.
- [ ] Preserve logo and footer layering above the artwork; change footer copy to `© 2026 Mirage. All rights reserved.`.
- [ ] Keep the panel hidden below `lg`.
- [ ] Convert the theme control to a clearly bounded 44px icon-only button with `title` and its existing `aria-label`.

### Task 3: Verify

**Files:** none.

- [ ] Run `npm run build`.
- [ ] Start Vite and manually verify light, dark, desktop, and mobile login states.
