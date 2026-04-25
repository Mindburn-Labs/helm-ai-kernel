/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { execSync } from 'child_process'
import path from 'path'

const commitHash = process.env.VITE_COMMIT_HASH || (() => {
  try { return execSync('git rev-parse --short HEAD').toString().trim(); }
  catch { return 'unknown'; }
})();

const studioBase = process.env.HELM_STUDIO_BASE || '/';
const controlplaneUrl = process.env.VITE_CONTROLPLANE_URL || 'http://localhost:8080';
const studioApiUrl = process.env.VITE_STUDIO_API_URL || 'http://localhost:8090';

export default defineConfig({
  plugins: [react()],
  resolve: {
    // OSS build: rely on npm-workspaces hoisting + `dedupe` for single-copy
    // React resolution. In the helm (commercial) build, React sits inside
    // `apps/helm-studio/node_modules/react` because pnpm nests deps by
    // default; that repo's vite.config.ts can add the alias back.
    dedupe: ['react', 'react-dom'],
  },
  define: {
    __BUILD_HASH__: JSON.stringify(commitHash),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
  },
  // Default to root-served assets so nested routes like /app/:tenant/live/ops
  // resolve bundles correctly in production. Desktop shells can still opt into
  // relative assets by setting HELM_STUDIO_BASE=./ at build time.
  base: studioBase,
  server: {
    // OSS build: serve only the Studio app root and the sibling
    // `packages/design-tokens/` workspace package. `helm/modules/*` (private
    // Mindburn-specific modules) lives in the commercial repo only; the
    // commercial `helm/apps/helm-studio/vite.config.ts` adds that entry back
    // in its own copy.
    fs: {
      allow: [
        path.resolve(__dirname),
        path.resolve(__dirname, '../../packages'),
      ],
    },
    proxy: {
      '/api/v1': {
        target: studioApiUrl,
      },
      '/ws': {
        target: controlplaneUrl,
        ws: true,
      },
      '/api': {
        target: controlplaneUrl,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
  build: {
    // Generate manifest.json mapping entry points to hashed filenames
    // Used by the macOS WebView shell to resolve the correct bundle files
    manifest: true,
    rollupOptions: {
      output: {
        // Stable entry chunk name for desktop shell discovery
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        // §23: Strategic code splitting for performance budgets
        manualChunks(id: string) {
          // React + React DOM: framework core
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) {
            return 'vendor-react'
          }
          // Router
          if (id.includes('node_modules/react-router')) {
            return 'vendor-react'
          }
          // State management + utilities
          if (id.includes('node_modules/zustand') || id.includes('node_modules/lucide-react')) {
            return 'vendor-ui'
          }
          // Canvas: ReactFlow is heavy, isolate it
          if (id.includes('node_modules/@xyflow') || id.includes('node_modules/reactflow')) {
            return 'vendor-canvas'
          }
          // Canvas source code
          if (id.includes('/canvas/') && !id.includes('node_modules')) {
            return 'canvas'
          }
          // Surfaces: each lazy-loaded surface gets its own chunk automatically
        },
      },
    },
  },
})
