/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_HELM_CONSOLE_COPILOTKIT_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
