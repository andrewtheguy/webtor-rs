/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BRIDGE_URL?: string;
  readonly VITE_BRIDGE_FINGERPRINT?: string;
  /** A directory manifest URL on another host; the gateway host's own by default. */
  readonly VITE_DIRECTORY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
