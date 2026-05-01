import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: true,
    // Virtualization tests use IntersectionObserver scheduling that runs
    // 6–8 s under workspace-orchestrated parallel execution. The 5 s
    // default trips that under contention; 15 s gives the headroom
    // without masking real perf regressions.
    testTimeout: 15000,
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/**/*.stories.{ts,tsx}",
        "src/test/**",
      ],
    },
  },
});

