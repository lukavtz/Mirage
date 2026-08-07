import '@testing-library/jest-dom/vitest'

class ResizeObserverMock { observe() {} unobserve() {} disconnect() {} }
;(globalThis as any).ResizeObserver = ResizeObserverMock

if (!('matchMedia' in window)) {
  (window as any).matchMedia = () => ({
    matches: false,
    media: '',
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })
}

if (!('localStorage' in globalThis)) {
  const store: Record<string, string> = {}
  const ls: any = {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => { store[k] = v },
    removeItem: (k: string) => { delete store[k] },
    clear: () => { for (const k in store) delete store[k] },
    key: (i: number) => Object.keys(store)[i] ?? null,
    get length() { return Object.keys(store).length },
  }
  ;(globalThis as any).localStorage = ls
}
