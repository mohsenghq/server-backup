import { defineConfig, devices } from '@playwright/test'

// Playwright E2E for the aegis web UI. The webServer config starts the
// Vite dev server, which proxies /api to a running aegis-server on
// AEGIS_E2E_API (default 127.0.0.1:8080). CI starts a real aegis-server
// (with an in-process SSH target) before running these tests.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    channel: 'chrome', // use the system Chrome; avoids browser downloads
  },
  projects: [{ name: 'chrome', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev -- --port 5173 --strictPort',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
})
