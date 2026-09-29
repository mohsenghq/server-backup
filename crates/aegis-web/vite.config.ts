import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// The E2E suite points the dev proxy at the server it starts
// (AEGIS_E2E_API); 127.0.0.1:8080 is the default CI also uses.
const api = process.env.AEGIS_E2E_API ?? 'http://127.0.0.1:8080'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': api,
      '/health': api,
    },
  },
})
