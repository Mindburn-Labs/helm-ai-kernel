import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const segmentAnalyticsNodeShim = fileURLToPath(
  new URL("./src/shims/segment-analytics-node.ts", import.meta.url),
);

export default defineConfig({
  plugins: [react()],
  define: {
    "process.env.COPILOTKIT_TELEMETRY_DISABLED": JSON.stringify("true"),
    "process.env.DO_NOT_TRACK": JSON.stringify("true"),
  },
  resolve: {
    alias: {
      "@segment/analytics-node": segmentAnalyticsNodeShim,
      "lucide-react": fileURLToPath(
        new URL("./node_modules/lucide-react/dist/esm/lucide-react.js", import.meta.url),
      ),
    },
    dedupe: ["react", "react-dom"],
  },
  server: {
    fs: {
      allow: [repoRoot],
    },
    proxy: {
      "/api": "http://127.0.0.1:7714",
      "/v1": "http://127.0.0.1:7714",
      "/mcp": "http://127.0.0.1:7714",
      "/healthz": "http://127.0.0.1:7714",
      "/version": "http://127.0.0.1:7714",
      "/.well-known": "http://127.0.0.1:7714",
    },
  },
  build: {
    sourcemap: true,
    manifest: true,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          icons: ["lucide-react"],
        },
      },
    },
  },
});
