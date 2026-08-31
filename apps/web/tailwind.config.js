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
        background: '#0B0F19',
        card: '#111827',
        'card-border': '#1F2937',
        primary: '#3B82F6',
        secondary: '#6366F1',
        accent: '#06B6D4',
        critical: '#EF4444',
        high: '#F97316',
        medium: '#F59E0B',
        low: '#10B981',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
