import { createContext, useContext, useEffect, useMemo, useState } from 'react'

// Two places need colour, and they cannot be served the same way.
//
// Anything Tailwind styles, or any inline `style` prop, resolves CSS custom
// properties — so those flip automatically when the theme attribute changes, and
// the palette lives in index.css as the single source of truth.
//
// Recharts is the exception. It passes colours through to SVG *presentation
// attributes*, and `stroke="var(--x)"` is not resolved there the way it is in
// CSS. Charts therefore need concrete values, which is what TOKENS provides.
// Keeping that table small and chart-only stops it drifting into a second
// palette competing with the stylesheet.

const STORAGE_KEY = 'aegisai-theme'

export const TOKENS = {
  dark: {
    grid: '#232b3d',
    axis: '#7c8aab',
    tooltipBg: '#131a29',
    tooltipBorder: '#232b3d',
    rail: '#3f4a63',
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6',
    neutral: '#64748b',
    brand: '#7c5cff',
    needle: '#e6e9f0'
  },
  light: {
    grid: '#e2e6ee',
    axis: '#5c6880',
    tooltipBg: '#ffffff',
    tooltipBorder: '#d4dae6',
    rail: '#a8b2c5',
    // Severity hues are darkened for light backgrounds: the dark-theme values
    // are tuned against near-black and drop below readable contrast on white.
    critical: '#d92020',
    high: '#c2570a',
    medium: '#a16207',
    low: '#15803d',
    info: '#1d4ed8',
    neutral: '#5c6880',
    brand: '#5b3fd9',
    needle: '#1a1f2b'
  }
}

const ThemeContext = createContext({ theme: 'dark', tokens: TOKENS.dark, toggle: () => {} })

function initialTheme() {
  if (typeof window === 'undefined') return 'dark'
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (stored === 'light' || stored === 'dark') return stored
  // No stored choice: follow the operating system rather than imposing one.
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    // `color-scheme` makes the browser's own chrome — scrollbars, form
    // controls, the canvas behind the page — match, which a class alone cannot.
    document.documentElement.style.colorScheme = theme
    window.localStorage.setItem(STORAGE_KEY, theme)
  }, [theme])

  // Follow the system only while the reader has expressed no preference of
  // their own; an explicit choice must survive the OS flipping at sunset.
  useEffect(() => {
    const query = window.matchMedia?.('(prefers-color-scheme: light)')
    if (!query) return undefined
    const onChange = (e) => {
      if (!window.localStorage.getItem(STORAGE_KEY)) setTheme(e.matches ? 'light' : 'dark')
    }
    query.addEventListener('change', onChange)
    return () => query.removeEventListener('change', onChange)
  }, [])

  const value = useMemo(
    () => ({
      theme,
      tokens: TOKENS[theme] ?? TOKENS.dark,
      setTheme,
      toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
    }),
    [theme]
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  return useContext(ThemeContext)
}

/** Chart colours for the active theme. */
export function useTokens() {
  return useContext(ThemeContext).tokens
}
