import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.HELM_CONSOLE_BASE_URL ?? "http://127.0.0.1:5173";
const mode = process.env.HELM_CONSOLE_SMOKE_MODE ?? "mock";
const shouldStartVite = process.env.HELM_CONSOLE_SMOKE_EXTERNAL_SERVER !== "1";

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.pw.ts",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: shouldStartVite
    ? {
        command: "npm run dev -- --host 127.0.0.1 --port 5173",
        url: baseURL,
        reuseExistingServer: true,
        timeout: 30_000,
        env: {
          ...process.env,
          HELM_CONSOLE_SMOKE_MODE: mode,
        },
      }
    : undefined,
});
