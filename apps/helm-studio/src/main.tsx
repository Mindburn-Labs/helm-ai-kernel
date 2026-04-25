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
 * OSS build: no private modules to load. The commercial repo overlays this
 * file (or otherwise overrides the import) to pull in its
 * `helm/modules/studio-*` contributions. See `../MIGRATION_STATUS.md` for
 * the OSS↔commercial divergence contract.
 *
 * The function signature is preserved so the boot sequence in `bootstrap()`
 * stays identical across profiles — OSS builds simply do nothing here.
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
