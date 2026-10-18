import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: ["**/*.spec.ts"],
  testIgnore: ["**/unit/**"],
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    // Specs open modules by name, so every sidebar group starts open. The
    // console's own default (only the open module's group) is tested in
    // smoke-tabs.spec.ts with an empty storage state (13.23.0-beta).
    storageState: {
      cookies: [],
      origins: [{
        origin: "http://127.0.0.1:4173",
        localStorage: [{
          name: "vecta_nav_open_groups_v2",
          value: JSON.stringify({ Home: true, "Keys & certificates": true, "Data & integrations": true, Monitor: true, Respond: true, Platform: true })
        }]
      }]
    }
  },
  webServer: {
    command: "npm run preview -- --host 127.0.0.1 --port 4173 --strictPort",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
