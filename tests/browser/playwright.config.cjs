const {defineConfig} = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.cjs',
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  timeout: 45_000,
  globalTimeout: 180_000,
  expect: {timeout: 10_000},
  reporter: [['list'], ['html', {open: 'never'}]],
  use: {
    browserName: 'chromium',
    baseURL: 'https://127.0.0.1:18765',
    ignoreHTTPSErrors: true, // Disposable fixture certificate only.
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'python3 -B tests/browser/fixture.py',
    cwd: '../..',
    url: 'https://127.0.0.1:18765/__ready',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 30_000,
    gracefulShutdown: {signal: 'SIGTERM', timeout: 5_000},
  },
});
