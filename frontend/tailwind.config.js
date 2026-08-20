/** @type {import('tailwindcss').Config} */
//
// Colours resolve to the CSS custom properties defined in src/index.css, so
// every Tailwind utility follows the active theme without a `dark:` variant on
// each element. The palette has exactly one home; this file only names it.
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      colors: {
        base: {
          bg: 'var(--bg)',
          panel: 'var(--panel)',
          card: 'var(--card)',
          card2: 'var(--card2)',
          border: 'var(--border)',
          border2: 'var(--border2)'
        },
        brand: {
          DEFAULT: 'var(--brand)',
          soft: 'var(--brand-soft)',
          dim: 'var(--brand-dim)'
        },
        content: {
          DEFAULT: 'var(--text)',
          muted: 'var(--text-muted)',
          dim: 'var(--text-dim)'
        },
        sev: {
          critical: 'var(--sev-critical)',
          criticalBg: 'var(--sev-critical-bg)',
          high: 'var(--sev-high)',
          highBg: 'var(--sev-high-bg)',
          medium: 'var(--sev-medium)',
          mediumBg: 'var(--sev-medium-bg)',
          low: 'var(--sev-low)',
          lowBg: 'var(--sev-low-bg)',
          info: 'var(--sev-info)',
          infoBg: 'var(--sev-info-bg)',
          neutral: 'var(--sev-neutral)',
          neutralBg: 'var(--sev-neutral-bg)'
        }
      },
      boxShadow: {
        panel: 'var(--shadow-panel)',
        glow: 'var(--shadow-glow)'
      }
    }
  },
  plugins: []
}
