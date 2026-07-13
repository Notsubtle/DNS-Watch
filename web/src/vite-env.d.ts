/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ENV_LABEL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
