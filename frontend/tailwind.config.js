/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#090d16',
          card: '#0f172a',
          cardHover: '#17233f',
          border: '#1e293b',
          borderLight: '#334155',
          text: '#f8fafc',
          muted: '#94a3b8',
          accent: '#06b6d4',
          cyan: '#06b6d4',
          emerald: '#10b981',
          crimson: '#ef4444',
          amber: '#f59e0b',
          purple: '#a855f7'
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      }
    },
  },
  plugins: [],
}
