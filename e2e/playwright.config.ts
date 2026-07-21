import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  retries: 1,
  workers: 1, // un seul worker car on lance un seul serveur indic
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8099',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'INDIC_BIND=127.0.0.1:8099 INDIC_DATA_DIR=data cargo run -- serve',
    cwd: '..',
    port: 8099,
    // premier démarrage = build + bootstrap des feeds (téléchargements)
    timeout: 600_000,
    reuseExistingServer: !process.env.CI,
  },
});
