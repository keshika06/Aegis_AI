/** @type {import('tailwindcss').Config} */
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
          bg: '#0a0e17',
          panel: '#0f1420',
          card: '#131a29',
          card2: '#161d2e',
          border: '#232b3d',
          border2: '#2a3348'
        },
        brand: {
          DEFAULT: '#7c5cff',
          soft: '#8b6bffb3',
          dim: '#3d3266'
        },
        sev: {
          critical: '#ef4444',
          criticalBg: '#3a1518',
          high: '#f97316',
          highBg: '#3a220f',
          medium: '#eab308',
          mediumBg: '#3a300f',
          low: '#22c55e',
          lowBg: '#12301d',
          info: '#3b82f6',
          infoBg: '#12213a',
          neutral: '#64748b',
          neutralBg: '#1c2333'
        }
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.02)',
        glow: '0 0 24px rgba(124,92,255,0.15)'
      }
    }
  },
  plugins: []
}
