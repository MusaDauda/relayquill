import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, chromium } from '@playwright/test';

const e2eDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(e2eDir, '..', '..');

function resolveChromiumExecutablePath() {
  const override = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH?.trim();
  if (override) {
    return override;
  }
  try {
    const cachedExecutable = chromium.executablePath();
    if (cachedExecutable && fs.existsSync(cachedExecutable)) {
      return cachedExecutable;
    }
  } catch {
    // Fall back to Playwright's bundled headless shell selection.
  }
  return undefined;
}

const executablePath = resolveChromiumExecutablePath();

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.(mjs|ts)$/,
  testIgnore: ['**/*.test.*'],
  outputDir: path.join(repoRoot, 'test-results'),
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 30_000,
  expect: {
    timeout: 5_000
  },
  reporter: [['list']],
  use: {
    headless: true,
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    ignoreHTTPSErrors: false,
    launchOptions: {
      ...(executablePath ? { executablePath } : {})
    }
  }
});
