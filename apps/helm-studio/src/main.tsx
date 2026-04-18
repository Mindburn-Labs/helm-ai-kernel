import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/jetbrains-mono/400.css'

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from './App'
import { setAvailableCapabilities } from './ext/registry'
import './index.css'

// Hydrate theme from localStorage before React renders (avoid FOUC)
;(() => {
  try {
    const saved = localStorage.getItem('helm-theme')
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.setAttribute('data-theme', saved)
    }
  } catch {
    // Ignore storage access issues and fall back to the default theme.
  }
})()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

/**
 * Load private modules when the commercial profile is selected.
 *
 * OSS↔commercial divergence:
 * - In helm-oss (this file) the body is intentionally empty. There is no
 *   `modules/` tree in this repo, so even a guarded dynamic `import()` of
 *   `../../../modules/studio-*` would be unresolvable.
 * - In helm (commercial) the equivalent `src/main.tsx` keeps a sibling set of
 *   `await import('../../../modules/studio-{titan,research-lab,signals-premium,people-ops,programs,workforce}/src/index')`
 *   calls, each guarded by the same `VITE_STUDIO_PROFILE === 'commercial'`
 *   check so Rollup dead-code-eliminates them from OSS-profile builds.
 *
 * This file is the canonical OSS implementation; the commercial copy is the
 * only intentional byte-level divergence between the two Studio trees (plus
 * `vite.config.ts`). All other files are synced read-only via
 * `helm/tools/oss.lock` + `make sync-oss-kernel`.
 */
async function loadPrivateModules(): Promise<void> {
  if (import.meta.env.VITE_STUDIO_PROFILE !== 'commercial') {
    return
  }
  // Intentionally empty. A commercial build satisfies this via an overlay —
  // see helm/apps/helm-studio/src/main.tsx for the canonical commercial
  // implementation that dynamic-imports each `helm/modules/studio-*` entry.
}

async function bootstrap(): Promise<void> {
  // Declare the OSS kernel capabilities the runtime exposes for this build.
  // Private modules may refuse to register if required capabilities are absent.
  setAvailableCapabilities(['studio.v1'])

  await loadPrivateModules()

  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </React.StrictMode>,
  )
}

void bootstrap()
