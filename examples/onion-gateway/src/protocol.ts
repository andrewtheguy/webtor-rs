// What the gateway's service worker tells a page that asked to follow along
// while the Tor client bootstraps. The worker's own interstitial page speaks
// this in plain JavaScript, so the shape is kept deliberately flat.

export type GatewayPhase = 'starting' | 'ready' | 'failed';

export type GatewayLevel = 'info' | 'success' | 'warn' | 'error';

export interface GatewayLine {
  at: number;
  level: GatewayLevel;
  message: string;
}

export interface GatewayProgress {
  type: 'progress';
  onion: string;
  phase: GatewayPhase;
  lines: GatewayLine[];
  /** Why the last bootstrap failed, while `phase` is `failed`. */
  failure: string | null;
}

/** A page's request for the current progress, and for every later change. */
export interface GatewaySubscribe {
  type: 'subscribe';
}
