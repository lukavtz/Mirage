# Mirage Panel — Dark Premium Redesign

## Context

The Mirage panel admin UI (`web/`) currently ships the stock shadcn/ui **neutral** theme — pure grayscale on `#ffffff`/`#0a0a0a` with hardcoded red/green/yellow Tailwind colors and no visual identity. The reference design is a premium dark-mode SaaS dashboard (Linear/Vercel/Plausible aesthetic) with a deep violet-tinted black background (`#090a0f`), purple brand primary (`#7140d0`), amber KPI highlights (`#ffb82c`), and gradient-rich charts. The task is to make the panel match that aesthetic while keeping all behavior, routes, data contracts, and shadcn variants intact. End state: same set of pages and components, but with a single-token-swap visual overhaul (≈95% of the work is `index.css`), a new font stack, premium chart gradients, fixed native-control dark mode, and the few hardcoded color sites migrated to semantic tokens.

Stack: React 19.2 + Vite 8 + Tailwind v4 (`@tailwindcss/vite`, HSL tokens, `@custom-variant dark`, `@theme inline` already in place) + shadcn/ui (`cssVariables: true`, `baseColor: neutral`, lucide icons) + Radix primitives + TanStack Query/Table 9-beta + recharts 3.9 + react-router-dom 7.

## Approach

The work is ordered so the tree builds and the existing UI keeps working after every step. Each step is a single, testable behavioral change.

### 1. Install new font + animation packages
- **Add** to `web/package.json` `dependencies`:
  - `@fontsource-variable/inter`
  - `@fontsource-variable/jetbrains-mono`
  - `tw-animate-css` (replaces the un-wired `tailwindcss-animate` already in devDeps)
- **Remove** `tailwindcss-animate` from devDeps (it is installed but never imported; `tw-animate-css` is the v4 replacement that shadcn docs use today).
- Run `npm install` to update `package-lock.json`.

### 2. Wire fonts and animations in `web/src/main.tsx` + `web/src/index.css`
- In `main.tsx`, add `import '@fontsource-variable/inter'` and `import '@fontsource-variable/jetbrains-mono'` BEFORE `App` import.
- In `index.css`:
  - At the very top (before `@import "tailwindcss"`), add `@import "tw-animate-css";`.
  - Add a `:root` rule with `color-scheme: dark;` (the app is dark by default; native `<select>`, `<input type=number>`, checkboxes in Sessions/Build/Users/Settings/Team/Search will otherwise render white inside dark cards — this is a real bug today).
  - In `@theme inline`, set `--font-sans: 'Inter Variable', ui-sans-serif, system-ui, sans-serif;` and `--font-mono: 'JetBrains Mono Variable', ui-monospace, SFMono-Regular, monospace;`.
  - Add the brand scale as static tokens (in `@theme`, NOT `@theme inline` — these are not swappable at runtime):
    - `--color-brand-400: #8b5cf6; --color-brand-500: #7140d0; --color-brand-600: #6138bc; --color-brand-700: #542f98; --color-brand-800: #5b3f8c;`
  - Add shadow tokens: `--shadow-glow: 0 0 24px hsl(var(--primary) / 0.35), 0 0 64px hsl(var(--primary) / 0.15);` and `--shadow-card-lg: 0 1px 0 0 rgb(255 255 255 / 0.04) inset, 0 8px 32px rgb(0 0 0 / 0.45);`.
  - Replace `body { font-family: system-ui, -apple-system, sans-serif; }` with `body { font-family: var(--font-sans); }`.
  - Add `::selection { background: hsl(var(--primary) / 0.3); }` and a thin dark `::-webkit-scrollbar` block (track transparent, thumb `hsl(var(--border))`, hover `hsl(var(--accent))`).

### 3. Replace the palette in `web/src/index.css` (the load-bearing change)
Replace ONLY the color VALUES in `:root` and `.dark`. Keep every variable name, every `@theme inline` mapping, the `--radius-*` scale, and the `* { border-color: var(--border) }` rule untouched. shadcn variants (`default/destructive/outline/secondary/ghost/link`), focus rings, table hover, dropdown active state, etc. all resolve through these tokens — the entire component library follows.

New values:

```css
:root {
  --background: #0a0b10;
  --foreground: #ffffff;
  --card: #111217;
  --card-foreground: #ffffff;
  --popover: #16171c;
  --popover-foreground: #ffffff;
  --primary: #7140d0;
  --primary-foreground: #ffffff;
  --secondary: #16171c;
  --secondary-foreground: #ffffff;
  --muted: #16171c;
  --muted-foreground: #999a9f;
  --accent: #1e1f24;
  --accent-foreground: #ffffff;
  --destructive: #fb2c46;
  --destructive-foreground: #ffffff;
  --border: #1a1b20;
  --input: #1e1f24;
  --ring: #7140d0;
  --chart-1: #7140d0;
  --chart-2: #ffb82c;
  --chart-3: #60b34b;
  --chart-4: #fb2c46;
  --chart-5: #8b5cf6;
  --sidebar-background: #090a0f;
  --sidebar-foreground: #ffffff;
  --sidebar-border: #1a1b20;
  --sidebar-accent: #1e1f24;
  --sidebar-accent-foreground: #ffffff;
  --sidebar-primary: #7140d0;
  --sidebar-primary-foreground: #ffffff;
  --sidebar-ring: #7140d0;
  --success: #60b34b;
  --success-foreground: #0a0f0a;
  --warning: #ffb82c;
  --warning-foreground: #14100a;
  --radius: 0.625rem;
}
```

Then DROP the separate `.dark` block entirely (the app is dark-only — every user value is the dark value). This is a deliberate scope reduction: a light theme is not in the reference and not requested. If the user later wants light mode, the existing `ThemeProvider` will re-need it; flag this in Assumptions, do not preempt.

Extend `@theme inline` to map the new tokens:

```css
@theme inline {
  --color-success: var(--success);
  --color-success-foreground: var(--success-foreground);
  --color-warning: var(--warning);
  --color-warning-foreground: var(--warning-foreground);
  --color-sidebar: var(--sidebar-background);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-ring: var(--sidebar-ring);
  --shadow-glow: var(--shadow-glow);
  --shadow-card-lg: var(--shadow-card-lg);
}
```

Accessibility is pre-verified in the design brief: white-on-`#0a0b10` ≈ 19.8:1 (AAA), `#999a9f` on `#0a0b10` ≈ 7.05:1 (AA), `#ffb82c` on `#0a0b10` ≈ 11.4:1 (AA), `#60b34b` on `#0a0b10` ≈ 7.6:1 (AA), `#fb2c46` on `#0a0b10` ≈ 5.2:1 (AA). Purple `#7140d0` is intentionally **not** used as body text — only as fills, large UI, and focus rings (fails 4.5:1 as text).

### 4. Add pre-paint theme script in `web/index.html`
Add a 3-line inline script in `<head>` BEFORE the existing CSP meta and `<script type="module">`:

```html
<script>(function(){try{var t=localStorage.getItem('theme');if(t==='light'||(!t&&matchMedia('(prefers-color-scheme: light)').matches)){}else{document.documentElement.classList.add('dark')}}catch(e){}})()</script>
```

This is conditional — only adds `.dark` if no explicit light preference is stored. Since step 3 makes the app dark-only, this just prevents a light flash for the (very rare) explicit-light user before hydration. The `ThemeProvider` is still the source of truth at runtime.

### 5. Migrate hardcoded color sites to semantic tokens
Per file, swap literal Tailwind palette utilities for the new tokens. Each is a 1-line edit.

| File | Old | New |
|---|---|---|
| `web/src/components/layout/topbar.tsx:55,60` | `text-emerald-500` / `text-red-500` | `text-success` / `text-destructive` |
| `web/src/pages/Build.tsx:116` | `bg-emerald-500/10 text-emerald-600 dark:text-emerald-400` | `bg-success/10 text-success` |
| `web/src/pages/Settings.tsx:93,126` | `text-emerald-500`, `bg-emerald-500` | `text-success`, `bg-success` |
| `web/src/pages/Settings.tsx:78-79` | `text-emerald-500` (saved) | `text-success` |
| `web/src/pages/Users.tsx:99` | `text-emerald-500` (copied) | `text-success` |
| `web/src/pages/Restore.tsx:100` | `text-emerald-500` (success) | `text-success` |
| `web/src/pages/Search.tsx:55` | `bg-yellow-500/20` (mark highlight) | `bg-warning/20 text-warning-foreground` |
| `web/src/pages/TeamPage.tsx:81-82,91` | `bg-purple-500/20 text-purple-400` (admin), `bg-blue-500/20 text-blue-400` (worker), `bg-emerald-500`/`bg-gray-500` (status dot), `text-red-400` (delete) | `bg-brand-500/20 text-brand-400` (admin), `bg-brand-400/20 text-brand-400` (worker — same hue family but lighter for differentiation), `bg-success`/`bg-muted-foreground` (status), `text-destructive` (delete) |
| `web/src/pages/Dashboard.tsx` | `bg-gradient-to-br from-primary/5 via-primary/10 to-transparent ring-1 ring-primary/10` (empty state) | `bg-linear-to-br from-primary/5 via-primary/10 to-transparent ring-1 ring-primary/10` (Tailwind v4 rename only; no color change) |

`flag-icon.tsx` (60 country hex colors + `#52525B` fallback) is **deliberately left alone** — it is data, not theme.

### 6. Polish the Sidebar (`web/src/components/layout/sidebar.tsx`)
- Add a soft purple radial glow behind the logo: wrap the brand mark in `<div className="relative">` with an absolutely positioned `<div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_30%_50%,hsl(var(--primary)/0.45),transparent_70%)] blur-md" />` and bump the logo chip from `rounded-lg bg-primary` to `rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 shadow-glow`.
- Change sidebar root from `border-r bg-card` to `border-r border-sidebar-border bg-sidebar text-sidebar-foreground` (new tokens).
- Active nav item: `bg-sidebar-primary/15 text-sidebar-primary font-medium` with a `before:` pseudo for a `2px` purple left accent bar (use the standard `relative before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-full before:bg-brand-500`).
- Inactive nav: `text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground`.
- Keep the collapse toggle, icon, and 9-item nav list unchanged structurally.

### 7. Polish the Topbar (`web/src/components/layout/topbar.tsx`)
- Background `bg-card/80 backdrop-blur-md border-b border-border` for the glass effect, `h-14` unchanged.
- Add a global search input as the first child of the right cluster: a small `bg-muted/60 hover:bg-muted border border-transparent focus-within:border-brand-500/50 focus-within:bg-background rounded-md` Input with a `Search` lucide icon prefix, placeholder "Search sessions, domains, IPs…", width `w-72` on `md:`. Wire `onChange` to navigate to `/search?q=<value>` on Enter (reuse `useNavigate`). Empty state, no debounce — the Search page already has its own debounce. (This is a 1-screen addition; no new page, no new route.)
- Connection status pill: wrap `Wifi`/`WifiOff` + label in a `flex items-center gap-1.5 text-xs` group; the icon already migrates to `text-success`/`text-destructive` from step 5.

### 8. Premium chart retheming (`web/src/components/charts/`)
For each chart, the data shape and recharts elements stay the same; only colors, gradient definitions, and tooltip polish change.

- **`timeline.tsx`**: import `useId` from React. Replace the hardcoded `'timelineGradient'` id with `useId()`. Beef up the gradient: stops at 0% `primary/0.35`, 55% `primary/0.08`, 100% `primary/0`. Add `<CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" vertical={false} />`. Bump strokeWidth to 2.5.
- **`browser-pie.tsx`**: keep `PIE_COLORS = [hsl(var(--chart-1..5))]`, but add a subtle `<defs>` with a single linear gradient per slice that fades from `chart-N` to `chart-N/0.6`. Switch the legend dots to use brand-aligned inline styles (`PIE_COLORS[i]`). Keep `innerRadius=60%`, `outerRadius=80%`, `strokeWidth=0`.
- **`geo-bar.tsx`**: import `useId` (separate from timeline's id). Bar `fill="hsl(var(--primary))"` → add a `<defs>` linear gradient id `geoGradient` that fades from `primary/0.9` at top to `primary/0.4` at bottom. Keep `radius=[0,4,4,0]`, `barSize=20`. The right-side value labels use `fill="hsl(var(--foreground))"` (was `muted-foreground`) so they pop.
- **`stat-card.tsx`**: make the value `text-3xl font-semibold tracking-tight tabular-nums` (was `text-2xl font-bold`). Add a thin purple top accent line: `<div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent" />` inside the Card. Use `relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-card-lg` (Card.tsx already supports `className` overrides — no need to edit the component file). KPI numbers in the value slot are the only place where the **amber `--warning` token** is used (via an opt-in `accent="warning"` prop; default stays foreground white). This makes the four Dashboard KPIs amber and lets future stat cards opt out.

**De-duplicate `PIE_COLORS` and the timeline gradient** between `web/src/components/charts/` and `web/src/pages/PublicStatsPage.tsx`: extract to a new `web/src/lib/chart-tokens.ts` exporting `PIE_COLORS` and a `useChartGradientId(prefix: string)` hook (wraps `useId` with a prefix). PublicStatsPage imports from there; delete its inline `PIE_COLORS` (lines 23-29) and the duplicated `<defs>` block for the timeline gradient.

### 9. Polish remaining pages (lightweight, token-only)
These files use the new tokens automatically via `bg-card`, `text-muted-foreground`, etc. Only a few benefit from a per-page polish pass:

- **`web/src/pages/Dashboard.tsx`**: page-level radial wash `before:fixed before:inset-0 before:-z-10 before:bg-[radial-gradient(1200px_600px_at_50%_-200px,hsl(var(--primary)/0.12),transparent)] before:pointer-events-none` on the outer wrapper. The empty-state hero already uses primary tint — bump the `from-primary/5` to `from-primary/10` and add `shadow-glow` to the inner Activity badge.
- **`web/src/pages/Login.tsx`**: card gets `shadow-card-lg`, the page gets the same radial wash as Dashboard. The logo chip becomes the same `bg-gradient-to-br from-brand-500 to-brand-700 shadow-glow` as the sidebar logo.
- **`web/src/pages/Sessions.tsx`** (largest, 436 lines): change the `blur-sm select-none` privacy mode to a header-level toggle button (no behavior change for rows). Add `bg-card/60 hover:bg-card/80 transition-colors` to the filter bar inputs. No structural rewrite.
- **`web/src/pages/SessionDetail.tsx`** (523 lines): Tabs list `bg-muted/60 border border-border` (was `bg-muted`); active trigger keeps the existing `bg-background` but adds `shadow-glow`. Each tab's table is already inside a Card; the Card gets `shadow-card-lg`.
- **`web/src/pages/Build.tsx`, `Settings.tsx`, `Users.tsx`, `TeamPage.tsx`, `Restore.tsx`, `Search.tsx`, `DocsPage.tsx`, `RefundPolicy.tsx`, `PublicStatsPage.tsx`**: page header `h1` becomes `text-2xl font-semibold tracking-tight` (was `font-bold`). Each page's outer Cards inherit the new shadow/border from the token swap alone. No other changes.

### 10. Backward-compat sweep
- `web/src/components/charts/flag-icon.tsx` — leave as-is (data, not theme).
- `web/src/components/ui/dialog.tsx` + `alert-dialog.tsx` `bg-black/80` overlay — leave as-is (shadcn stock; visually correct against the new dark bg).
- `web/src/lib/theme-provider.tsx` — no change. The toggle still works against `.dark` class on `<html>`. The `localStorage` key `'theme'` is preserved.
- The 30+ `bg-primary/10`, `text-primary`, `border-border` etc. that already use token names — they re-resolve to the new colors for free; do not touch.

### 11. Verification

The existing dev server is the smoke test. Run `npm run dev` from `web/`; visually check every page renders, every variant still works, and the colors match the reference.

A focused regression pass against the new behavior:

1. **Dev build & typecheck** — `cd web && npm run build` (runs `tsc && vite build`). Must complete with no errors. This is the type-system gate; no `hsl(var(--warning))` typos, no missing `useId` import, no broken JSX.
2. **Login + auth flow** — `npm run dev`, open `/login`, sign in with the seeded admin. Verify redirect to `/`, query client initializes, WebSocket connects, `useDashboard` populates the 4 amber KPI numbers (`Sessions`, `Passwords`, `Cookies`, `Wallets`) and the timeline / geo / browser charts render with the new gradient.
3. **Theme flash** — hard-reload `/` with DevTools "Disable cache" on; verify no white flash (the pre-paint script in step 4).
4. **Native control dark mode** — open `/sessions`, click the country `<select>` and the date preset `<select>`. The native dropdown must render dark, not white (proves step 2's `color-scheme: dark;`).
5. **Token migration smoke** — visit every page; confirm: no `text-emerald-500` / `text-red-500` / `text-purple-400` / `text-blue-400` / `text-yellow-500` / `bg-emerald-500` strings remain. A single `grep -nE 'emerald-|red-500|red-400|purple-(500|400)|blue-(500|400)|yellow-500|bg-emerald|bg-purple' web/src` should return zero matches outside of `flag-icon.tsx`.
6. **Chart gradient uniqueness** — open `/` (Dashboard) — if there is a `/public` route open it too in a second tab. Both `<Timeline>` instances must render independent gradients (the `useId` swap prevents id collision).
7. **Accessibility check** — load `/` in Chrome, run Lighthouse, confirm color contrast for body text is "Pass" (the palette is pre-verified; this is a regression net).
8. **Build artifact** — `cd web && npm run build` produces a `dist/`; `vite preview` serves it; same visual check.
9. **Component variants** — on `/settings`, click the "Dark / Light" theme toggle. The button still works (`.dark` class flips) — the layout will look the same since both modes are dark, but this proves the provider, localStorage, and `dark:` utility resolution are intact.
10. **Diff discipline** — `git status` shows ONLY edits to the files listed in steps 1-9. No accidental changes in `web/src/components/ui/*` (shadcn component files must be untouched — variants work via tokens).

If any step fails, fix in place; do not introduce shims or fallbacks. The cutover is clean.

## Critical files & anchors

- **`web/src/index.css`** — the entire palette lives here. Steps 2, 3, and 8 anchor on this single file. Re-read the full file before editing; the order of `@import` statements is meaningful in Tailwind v4.
- **`web/src/lib/chart-tokens.ts`** (new, ~15 LOC) — centralizes `PIE_COLORS` and the gradient-id hook consumed by `charts/timeline.tsx`, `charts/browser-pie.tsx`, `charts/geo-bar.tsx`, and `pages/PublicStatsPage.tsx`.
- **`web/src/components/layout/sidebar.tsx`** — visual overhaul of the primary chrome element; the radial glow is the only non-token styling.
- **`web/src/components/layout/topbar.tsx`** — adds the global search input; the connection-pill relies on step 5's token migration to look right.
- **`web/src/components/charts/{timeline,geo-bar,browser-pie}.tsx`** — gradient + `useId` upgrades; the de-duplication against PublicStatsPage is a single import change in PublicStatsPage once the new file exists.

## Assumptions & contingencies

- **Dark-only.** The reference is dark; the task is to match the reference. The existing `ThemeProvider` already defaults to dark and the `useTheme` toggle in `useTheme()` is preserved (it can flip a `.light` mode later by reintroducing the `.dark` block). No light-mode implementation this pass. If the user later wants light: restore the dropped `.dark` block and rename the new values to `:root`.
- **No new dependencies beyond fonts + tw-animate-css.** No new icon lib, no `framer-motion`, no `@tailwindcss/typography` (the `prose prose-invert` classes in `DocsPage.tsx` are already inert today — leave them). If the user later wants real markdown, add `@tailwindcss/typography` and `react-markdown` then.
- **No backend changes.** The TOTP, CSRF, WebSocket event-name mismatch, and unused endpoint findings from the backend scout are out of scope for a visual redesign. If anything visually depends on a missing endpoint (none in the current UI), it surfaces as an existing bug, not a redesign regression.
- **Component files (`web/src/components/ui/*`) are untouched.** Variants resolve through tokens; editing them is a future-proofing trap that re-creates the problem shadcn solved. The `tailwindcss-animate` plugin not being wired is fixed in step 2 (import `tw-animate-css` at the top of `index.css`); do NOT edit `dialog.tsx` or `alert-dialog.tsx`.
- **Pre-paint script is the only change to `web/index.html`.** The CSP meta and existing module script stay. If CSP blocks the inline script, the fallback is to read the script via a `nonce` — but the current CSP `script-src 'self'` does not include `unsafe-inline` for scripts, so the inline script will be blocked. Contingency: drop the pre-paint script and accept a one-frame light flash; the visual cost is negligible for a dark-only app and a working dark theme is the priority.
- **StatCard API gains an optional `accent?: 'default' | 'warning'` prop.** Default = `text-foreground` (white); `warning` = `text-warning` (amber). This is the smallest change that lets Dashboard opt the 4 KPIs into amber without forcing the rest of the app to follow. All existing call sites continue to work with the default.
- **PublicStatsPage reuses the same `useId`-prefixed gradient** as the Dashboard Timeline. If the two pages ever need different gradient stops, the `useChartGradientId(prefix)` hook accepts a prefix to disambiguate. Today they share.
- **`docs` route uses `prose prose-invert` which is inert.** Not a redesign regression; flagged for future. Do not silently add `@tailwindcss/typography` to "fix" it.
