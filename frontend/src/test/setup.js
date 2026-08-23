import '@testing-library/jest-dom/vitest'

// Node 22+ exposes an experimental global `localStorage` that is inert unless
// started with --localstorage-file. jsdom sees the global already present and
// declines to install its own, so `window.localStorage` is undefined and the
// theme provider throws on mount. An in-memory Storage is what jsdom would
// have given us.
if (!window.localStorage) {
  const store = new Map()
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
      key: (i) => [...store.keys()][i] ?? null,
      get length() { return store.size }
    }
  })
}

// jsdom has no layout engine, so matchMedia is absent and the theme provider
// asks it what the operating system prefers.
if (!window.matchMedia) {
  window.matchMedia = (query) => ({
    matches: false,
    media: query,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent: () => false
  })
}

// Recharts measures its container to lay out, and jsdom reports every element
// as 0x0 — charts would render nothing at all.
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, value: 800 })
Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 400 })
