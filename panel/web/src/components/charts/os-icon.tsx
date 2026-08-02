interface OsIconProps {
  os: string
  size?: number
  className?: string
}

/**
 * Brand-colored OS icon. Maps free-form OS strings (e.g. "Windows 10",
 * "macOS 14.5", "Linux x86_64") to a brand icon. Case-insensitive `includes()`
 * — the actual OS string comes from client-controlled User-Agent parsing.
 *
 * Windows path: Font Awesome brands viewBox 448x512, license CC BY 4.0.
 * Apple path: simple-icons (CC0).
 * Linux (Tux), Android: common brand SVGs.
 * Unknown / unrecognized: monitor glyph, --muted-foreground color.
 */
const OS_DEFS: Array<{ keys: string[]; viewBox: string; d: string; color: string }> = [
  {
    keys: ['windows'],
    viewBox: '0 0 448 512',
    d: 'M0 93.7l183.6-25.3v177.4H0V93.7zm0 324.6l183.6 25.3V268.4H0v149.9zm203.8 28L448 480V268.4H203.8v177.9zm0-380.6v180.1H448V32L203.8 65.7z',
    color: '#0078D4',
  },
  {
    keys: ['macos', 'os x', 'darwin'],
    viewBox: '0 0 24 24',
    d: 'M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z',
    color: 'currentColor',
  },
  {
    keys: ['linux', 'ubuntu', 'debian', 'fedora', 'arch', 'mint'],
    viewBox: '0 0 24 24',
    d: 'M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 0 0-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.604.058.4.116.778.018 1.024-.31.69-.354 1.16-.143 1.515.207.349.625.451 1.024.567.107.03.211.06.314.097.199.07.354.131.466.247.067.067.117.154.155.243.029.075.05.155.066.232.026.087.05.166.084.243.072.184.181.34.297.485.058.075.122.144.184.214.135.158.292.305.46.444.674.566 1.55.94 2.614 1.066.69.075 1.39.067 2.06-.045.39-.067.78-.166 1.16-.296.31-.107.61-.232.91-.366.18-.083.36-.166.54-.243.18-.083.36-.166.54-.243.41-.166.83-.31 1.27-.39.6-.1 1.2-.13 1.8-.1.6.03 1.2.1 1.8.21.39.07.78.17 1.16.29.31.1.61.22.91.36.18.08.36.16.54.24.18.08.36.16.54.24.38.13.77.23 1.16.3.67.11 1.37.12 2.06.04 1.06-.13 1.94-.5 2.61-1.07.17-.14.33-.29.46-.44.06-.07.13-.14.18-.21.12-.15.23-.3.3-.49.03-.08.05-.16.08-.24.02-.08.04-.16.07-.23.04-.09.09-.18.16-.25.11-.12.26-.18.46-.25.1-.04.21-.07.31-.1.4-.12.82-.22 1.02-.57.21-.36.16-.83-.14-1.52-.1-.25-.04-.62.06-1.02.03-.2.05-.4.05-.6 0-.21-.04-.41-.13-.6-.21-.41-.55-.54-.86-.68-.31-.13-.6-.2-.8-.4-.21-.24-.4-.57-.66-.84a.42.42 0 0 0-.11-.13c.12-.81-.01-1.66-.29-2.49-.59-1.77-1.83-3.47-2.71-4.52-.75-1.07-.97-1.93-1.05-3.02-.07-1.49 1.05-5.97-3.18-6.3-.16-.01-.32-.02-.48-.02-.5 0-1.01.06-1.51.18-.5.12-1 .31-1.45.55-.45.24-.85.52-1.21.83-.36.31-.66.65-.9 1-.24.35-.42.7-.54 1.04-.12.34-.18.67-.18.99 0 .32.06.65.18.99.12.34.3.69.54 1.04.24.35.54.69.9 1 .36.31.76.59 1.21.83.45.24.95.43 1.45.55.5.12 1.01.18 1.51.18.16 0 .32-.01.48-.02.61-.05 1.18-.16 1.7-.34-.34.43-.78.83-1.31 1.18-.53.35-1.13.64-1.78.85-.65.21-1.34.34-2.05.36-.71.02-1.42-.07-2.11-.26-.69-.19-1.35-.47-1.96-.84-.61-.37-1.16-.83-1.62-1.35-.46-.52-.83-1.1-1.09-1.7-.26-.6-.41-1.23-.43-1.85-.02-.62.09-1.23.32-1.81.23-.58.58-1.12 1.04-1.6.46-.48 1.02-.89 1.66-1.21.64-.32 1.36-.55 2.13-.66.77-.11 1.58-.11 2.42.04.84.15 1.71.43 2.59.88.88.45 1.77 1.07 2.65 1.88.88.81 1.76 1.81 2.6 3 .84 1.19 1.64 2.57 2.36 4.13.72 1.56 1.36 3.3 1.88 5.18.52 1.88.92 3.91 1.16 6.03.24 2.12.32 4.34.21 6.58-.11 2.24-.4 4.5-.88 6.71-.48 2.21-1.14 4.36-1.96 6.38-.82 2.02-1.8 3.9-2.9 5.56-1.1 1.66-2.32 3.1-3.62 4.24-1.3 1.14-2.68 1.99-4.08 2.5-1.4.51-2.83.69-4.23.51-1.4-.18-2.78-.71-4.08-1.59-1.3-.88-2.52-2.11-3.62-3.66-1.1-1.55-2.08-3.42-2.9-5.55-.82-2.13-1.48-4.51-1.96-7.05-.48-2.54-.78-5.23-.88-7.99-.1-2.76-.02-5.59.27-8.38.29-2.79.77-5.55 1.44-8.18.67-2.63 1.53-5.13 2.55-7.39 1.02-2.26 2.2-4.27 3.5-5.93 1.3-1.66 2.71-2.97 4.18-3.84 1.47-.87 3-1.31 4.53-1.25z',
    color: 'currentColor',
  },
  {
    keys: ['android'],
    viewBox: '0 0 24 24',
    d: 'M17.523 15.342a1.04 1.04 0 1 1 0-2.08 1.04 1.04 0 0 1 0 2.08m-11.046 0a1.04 1.04 0 1 1 0-2.08 1.04 1.04 0 0 1 0 2.08m11.42-6.018 2.077-3.595a.416.416 0 0 0-.152-.567.416.416 0 0 0-.567.152l-2.105 3.642A13.075 13.075 0 0 0 12 8.005c-1.832 0-3.558.428-5.05 1.197L4.846 5.56a.416.416 0 0 0-.567-.152.416.416 0 0 0-.152.567l2.077 3.595C2.547 11.502.347 15.32 0 19.78h24c-.347-4.46-2.547-8.278-6.103-10.456',
    color: 'currentColor',
  },
  {
    keys: ['ios', 'iphone', 'ipad'],
    viewBox: '0 0 24 24',
    d: 'M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z',
    color: 'currentColor',
  },
  {
    // FreeBSD — generic daemon-derived silhouette.
    keys: ['freebsd', 'bsd'],
    viewBox: '0 0 24 24',
    d: 'M12 2a3 3 0 0 0-3 3 3 3 0 0 0 .18 1H7a2 2 0 0 0-2 2v3.18A3 3 0 0 0 4 14a3 3 0 0 0 1 .82V18a2 2 0 0 0 2 2h2.18A3 3 0 0 0 12 22a3 3 0 0 0 2.82-2H17a2 2 0 0 0 2-2v-3.18A3 3 0 0 0 20 14a3 3 0 0 0-1-.82V8a2 2 0 0 0-2-2h-2.18A3 3 0 0 0 12 2zm0 2a1 1 0 0 1 1 1 1 1 0 0 1-1 1 1 1 0 0 1-1-1 1 1 0 0 1 1-1zM6 14a1 1 0 0 1 1 1 1 1 0 0 1-1 1 1 1 0 0 1-1-1 1 1 0 0 1 1-1zm12 0a1 1 0 0 1 1 1 1 1 0 0 1-1 1 1 1 0 0 1-1-1 1 1 0 0 1 1-1zm-6 4a1 1 0 0 1 1 1 1 1 0 0 1-1 1 1 1 0 0 1-1-1 1 1 0 0 1 1-1z',
    color: '#AB2B28',
  },
]

const UNKNOWN_DEF: { keys: string[]; viewBox: string; d: string; color: string } = {
  keys: [],
  viewBox: '0 0 24 24',
  d: 'M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16zM3.27 6.96 12 12.01l8.73-5.05L12 1.95zM5 15.36V9.24l5 2.89v6.08zm7 4.04-5-2.89v-6.08l5 2.89zm2-1.13L9 15.36V9.24l8 4.62v6.08z',
  color: 'var(--muted-foreground)',
}

function findOs(os: string) {
  const lower = (os || '').toLowerCase()
  for (const def of OS_DEFS) {
    for (const key of def.keys) {
      if (lower.includes(key)) return def
    }
  }
  return UNKNOWN_DEF
}

export function OsIcon({ os, size = 18, className }: OsIconProps) {
  const def = findOs(os)
  // Brand glyphs that use currentColor need a per-theme color on the wrapper.
  // Apple/Linux/Android/iOS all map to readable defaults in both themes.
  const themeColor = pickThemeColor(def.keys)
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={def.viewBox}
      width={size}
      height={size}
      className={className}
      style={themeColor ? { flexShrink: 0, color: themeColor } : { flexShrink: 0 }}
      fill={themeColor ? 'currentColor' : def.color}
      aria-label={os || 'unknown'}
    >
      <path d={def.d} />
    </svg>
  )
}

// Brand color per theme. White-on-white would be invisible in light mode, so
// we set Apple to the foreground token (black in light, white in dark) and
// keep the OS-specific brand hue for the others.
function pickThemeColor(keys: string[]): string | undefined {
  if (keys.includes('macos') || keys.includes('os x') || keys.includes('darwin')) {
    return 'var(--foreground)'
  }
  if (keys.includes('ios') || keys.includes('iphone') || keys.includes('ipad')) {
    return 'var(--foreground)'
  }
  if (keys.includes('android')) {
    return '#3DDC84'
  }
  if (keys.includes('linux') || keys.includes('ubuntu') || keys.includes('debian') || keys.includes('fedora') || keys.includes('arch') || keys.includes('mint')) {
    return 'var(--muted-foreground)'
  }
  if (keys.includes('freebsd') || keys.includes('bsd')) {
    return undefined // explicit hex stays on the def
  }
  if (keys.includes('windows')) {
    return undefined
  }
  return undefined
}

export function normalizeOsLabel(os: string): string {
  const lower = (os || '').toLowerCase()
  if (lower.includes('windows')) return 'Windows'
  if (lower.includes('macos') || lower.includes('os x') || lower.includes('darwin')) return 'macOS'
  if (lower.includes('ios') || lower.includes('iphone') || lower.includes('ipad')) return 'iOS'
  if (lower.includes('android')) return 'Android'
  if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian') || lower.includes('fedora') || lower.includes('arch') || lower.includes('mint')) return 'Linux'
  return os || 'Unknown'
}
