/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BRIDGE_URL?: string;
  readonly VITE_BRIDGE_FINGERPRINT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
