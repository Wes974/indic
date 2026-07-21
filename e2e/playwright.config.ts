import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  // Doit rester > la somme des attentes d'un test : certains enchaînent deux
  // waits de LOOKUP (30 s) sur des lookups réseau à froid.
  timeout: 90_000,
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
    // INDIC_SKIP_BOOTSTRAP : pas de téléchargement des feeds offline (~40 Mo) —
    // les lookups restent servis par RDAP/rDNS, ce que testent ces specs.
    command:
      'INDIC_BIND=127.0.0.1:8099 INDIC_DATA_DIR=data INDIC_SKIP_BOOTSTRAP=1 cargo run -- serve',
    cwd: '..',
    port: 8099,
    // large : le premier run compile le binaire
    timeout: 600_000,
    reuseExistingServer: !process.env.CI,
  },
});
