# Eidos Web Panel — Design System

## 1. Design Language

**Vibe:** Dark-tech, data-dense, precision  
**Inspiration:** ByteCode C2, ShardC2, Pulse-C2, shadcn/ui dark theme  
**Motto:** *«Информация — первична. Эстетика — в точности.»*

Тёмная тема не для красоты, а для длительной работы с данными. Минимум отвлечений, максимум плотности информации.

---

## 2. Colour System

### Core Palette

```
Background:     #0A0A0B  (slate-950)
Surface:        #18181B  (zinc-900)
Surface Raised: #27272A  (zinc-800)
Border:         #3F3F46  (zinc-700)

Text Primary:   #FAFAFA  (zinc-50)
Text Secondary: #A1A1AA  (zinc-400)
Text Muted:     #71717A  (zinc-500)

Accent:         #6366F1  (indigo-500)
Accent Hover:   #818CF8  (indigo-400)
Accent Muted:   #312E81  (indigo-950)

Success:        #22C55E  (green-500)
Warning:        #F59E0B  (amber-500)
Danger:         #EF4444  (red-500)
Info:           #3B82F6  (blue-500)
```

### Status Badges

```
Online:   bg-emerald-500/10 text-emerald-400 border-emerald-500/20
Offline:  bg-zinc-500/10 text-zinc-400 border-zinc-500/20
New:      bg-blue-500/10 text-blue-400 border-blue-500/20
Banned:   bg-red-500/10 text-red-400 border-red-500/20
```

### Country Flag Badges

```
Pill-shaped: rounded-full px-1.5 py-0.5 text-[10px] font-mono
┌──────────────────────────────────┐
│ 🇷🇺 RU (456)  │ 7px emoji + code │
│ 🇺🇸 US (324)  │                  │
└──────────────────────────────────┘
```

---

## 3. Typography

```
Font Family: "Geist", -apple-system, sans-serif
Monospace:   "Geist Mono", "SF Mono", monospace

Scale:
  xs:    11px / 14px   (table cells, badges)
  sm:    13px / 18px   (body, descriptions)
  base:  14px / 20px   (default text)
  lg:    16px / 24px   (h3, card titles)
  xl:    20px / 28px   (h2)
  2xl:   24px / 32px   (h1)
  3xl:   30px / 38px   (dashboard big number)

Font Weight:
  Regular:  400 (body, table data)
  Medium:   500 (navigation, labels)
  Semibold: 600 (headings, stat numbers)
  Bold:     700 (emphasized)
```

**Geist** — от Vercel, идеально для data-heavy интерфейсов. Open source. Можно качать через `@fontsource/geist`.

---

## 4. Spacing & Layout

```
Section padding: p-6 (24px)
Card padding:     p-4 (16px)
Gap grid:         gap-4 (16px)
List gap:         gap-2 (8px)

Sidebar:           w-56 (224px), collapsed: w-14 (56px)
Header:            h-14 (56px)
Max content:       max-w-7xl (1280px)
```

### Layout Shell

```
┌──────────┬────────────────────────────────────────────┐
│          │  Topbar                                    │
│          │  ├ Logo + Status ─── User + Logout         │
│          ├────────────────────────────────────────────┤
│ Sidebar  │                                            │
│          │  Content Area                              │
│ ┌──────┐ │  ┌─────────────────────────────────────┐  │
│ │ Dash │ │  │ Card  │ Card  │ Card  │ Card        │  │
│ │ Logs │ │  ├─────────────────────────────────────┤  │
│ │ Build│ │  │                                     │  │
│ │Search│ │  │ Chart / Table                       │  │
│ │ Bans │ │  │                                     │  │
│ │⚙ Set.│ │  └─────────────────────────────────────┘  │
│ └──────┘ │                                            │
└──────────┴────────────────────────────────────────────┘
```

- Sidebar: коллапсируемая на `w-14` (только иконки)
- Topbar: нефиксированная, скроллится с контентом
- Breadcrumbs: только в SessionDetail (Session → Detail)

---

## 5. UI Components

### 5.1 Stat Card

```
┌──────────────────────┐
│ [icon] 1,284         │  ← text-2xl font-bold tabular-nums
│ Sessions Total       │  ← text-sm text-zinc-400
│ ▲ 12% from yesterday│  ← text-xs text-emerald-400 (optional trend)
└──────────────────────┘
```

### 5.2 Data Table (TanStack)

```
┌──────┬─────────────┬──────────┬──────┬───────────┬──────────┐
│  #   │  IP         │ Country  │  OS  │ Passwords │  Date    │
├──────┼─────────────┼──────────┼──────┼───────────┼──────────┤
│ 1    │ 85.26.134.55│ 🇷🇺 RU   │ Win11│   12      │ 2 min ago│
│ 2    │ 192.168.1.10│ 🇺🇸 US   │ Win10│    5      │ 5 min ago│
│ 3    │ 10.0.0.15   │ 🇩🇪 DE   │ Win11│   34      │ 8 min ago│
└──────┴─────────────┴──────────┴──────┴───────────┴──────────┘
├─── Sortable columns (click header)
├─── Resizable columns (drag edge)
├─── Column visibility toggle (dropdown)
├─── Row click → SessionDetail
├─── Pagination: « 1 2 3 … 26 »
└─── Rows per page: 25 | 50 | 100
```

### 5.3 Session Detail — Tabbed View

```
┌──────────────────────────────────────────────────────┐
│  ← Sessions  /  85.26.134.55  🇷🇺 RU                   │
│  HWID: ABC123...  |  OS: Win11 Pro  |  john           │
├───────┬──────┬──────┬──────┬───────┬────────┬────────┤
│Passw. │Cook. │Cards │Wallets│ Files │ SysInfo│  Notes │
├───────┴──────┴──────┴──────┴───────┴────────┴────────┤
│ url           │ username       │ password    │ browser│
│ ──────────────┼────────────────┼─────────────┼────────┤
│ google.com    │ john@gmail.com │ •••••••••   │ Chrome │
│ facebook.com  │ john           │ •••••••••   │ Chrome │
│ github.com    │ john           │ •••••••••   │ Edge   │
├───────────────┴────────────────┴─────────────┴────────┤
│ Password reveal: 👁 toggle                             │
│ Bulk select + copy + export                            │
└────────────────────────────────────────────────────────┘
```

### 5.4 Search Page

```
┌──────────────────────────────────────────────────────┐
│ 🔍  [______________________________]  Search          │
│ Filters: [All ▾]                                      │
│                                                       │
│ ┌───────┬─────────────────┬──────────┬──────────────┐ │
│ │ Type  │ URL / Domain    │ Username │ Password     │ │
│ ├───────┼─────────────────┼──────────┼──────────────┤ │
│ │ 🔑 pw │ google.com      │ john     │ •••••        │ │
│ │ 🍪 ck │ .facebook.com   │ —        │ session=abc  │ │
│ │ 💳 cc │ stripe.com      │ John Doe │ 4111••••1111 │ │
│ └───────┴─────────────────┴──────────┴──────────────┘ │
│                                                       │
│ Search across: passwords, cookies, cards, sessions    │
│ Highlight matched fields in yellow                    │
└──────────────────────────────────────────────────────┘
```

### 5.5 Build Page

```
┌──────────────────────────────────────────────────────┐
│  🏗 Build Stealer                                     │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Config                                           │  │
│  │                                                   │  │
│  │ C2 Host:    [127.0.0.1        ]  Port: [8443   ] │  │
│  │ TG Token:   [680547773:AAE... ]                   │  │
│  │ TG Chat ID: [-1003951628380   ]                   │  │
│  │ Build Tag:  [my_first_build   ]                   │  │
│  │                                                   │  │
│  │ ☑ Enable Screenshot                               │  │
│  │ ☐ Enable Persistence                              │  │
│  │ ☑ Enable Grabber                                  │  │
│  │ ☑ Include MirageDecryptor.dll                     │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Last Build: 2 min ago                            │  │
│  │ Tag: my_first_build | Size: 121 KB | SHA256: abc │  │
│  │ [Download]                                       │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  [🛠 Build]                                            │
└──────────────────────────────────────────────────────┘
```

### 5.6 Settings Page

```
┌──────────────────────────────────────────────────────┐
│  ⚙ Settings                                           │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Panel                                            │  │
│  │  Server Port:  [8080          ]  [Save Port]     │  │
│  │  Auth Token:   abc123def456...  [Regenerate]     │  │
│  │  API Rate Limit: [100] req/min                   │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Telegram                                         │  │
│  │  Bot Token:  [680547773:AAE... ]  [Test]       │  │
│  │  Chat ID:    [-1003951628380   ]  [Test]        │  │
│  │  ☑ Forward new logs to Telegram                  │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Database                                         │  │
│  │  Sessions: 1,284 | Passwords: 12,453 | Size: 8MB│  │
│  │  [Vacuum] [Export All] [Import]                  │  │
│  └─────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

---

## 6. Charts

All charts via **Recharts** with consistent dark theme.

### 6.1 Timeline (AreaChart)

```
📈 Sessions — Last 30 Days
    ▁▂▃▅▇▆▄▃▂▁▃▅▇▆▄▃▂▁▃▅▇▆▄▃▂
    ────────────────────────────
      Jun 02          Jun 16           Jul 02
```

- Area fill: `fill="url(#gradient)"` from accent/20 to transparent
- Line: `stroke="var(--accent)" strokeWidth={2}`
- X-axis: date (every 5th tick)
- Y-axis: count

### 6.2 Browser Pie (PieChart)

```
          Chrome (68%)
    ████████████████████░░░░
    ████████████████████░░░░  Edge (18%)
    ████████████████████░░░░  Firefox (10%)
                              Opera (4%)
```

- Donut variant (inner radius = 60%)
- Label: name + percentage outside
- Hover: tooltip with exact count

### 6.3 Geo Distribution (BarChart)

```
🇷🇺 RU ████████████████░░░░ 456
🇺🇸 US ██████████░░░░░░░░░░ 324
🇩🇪 DE ██████░░░░░░░░░░░░░░ 189
🇬🇧 GB ████░░░░░░░░░░░░░░░░ 123
```

- Horizontal bars
- Flag emoji + country code + count + bar
- Color: accent shade based on count

---

## 7. Motion

```
Default transition: cubic-bezier(0.16, 1, 0.3, 1)
  → Used for: sidebar collapse, modals, tooltips

Table row hover: background-color 150ms ease
  → bg-zinc-800/50 on hover

Notifications: slide-in-right 200ms, fade-out 300ms
  → Fixed bottom-right, stack vertically

Page transitions: opacity 150ms + translateY(4px) → (0)
  → Framer Motion AnimatePresence
```

---

## 8. Responsive Breakpoints

```
sm:  640px   — Mobile (single column, collapsed sidebar)
md:  768px   — Tablet (sidebar icons only)
lg:  1024px  — Desktop (full sidebar)
xl:  1280px  — Wide (max content width)
```

Mobile layout:
- Sidebar → bottom navigation bar or hamburger
- Tables → horizontal scroll or card view
- Charts → stacked vertically
- Session tabs → accordion instead of tabs
