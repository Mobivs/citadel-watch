/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./frontend/**/*.html",
    "./frontend/js/**/*.js",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'neon-blue': '#00D9FF',
        'dark-bg': '#0A0E27',
        'card-bg': 'rgba(15, 23, 42, 0.6)',
      },
      backdropBlur: {
        'glass': '20px',
      }
    }
  },
  plugins: [],
}
