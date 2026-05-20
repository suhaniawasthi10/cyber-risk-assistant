/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0c0c0d',
        surface: '#141416',
        ink: '#e8e8e6',
        muted: '#8a8a87',
        line: '#262626',
        critical: '#d9504a',
        warning: '#d9a441',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      maxWidth: {
        content: '860px',
      },
    },
  },
  plugins: [],
}
