// Putting the gateway in charge of an onion origin. This runs on the first
// visit to `http://<address>.onion.<root>`, when no service worker controls
// it yet and the server has answered with this app; once the worker is
// active, reloading hands the same request to it.

const SERVICE_WORKER_URL = '/sw.js';

/**
 * When a reload was last asked for, so a worker that fails to take the page
 * over is reported rather than reloaded into forever. Only a recent one
 * counts: the onion page that follows a successful install never runs this
 * code to clear it, so an old value says nothing about the install under way.
 */
const RELOADED_KEY = 'webtor-onion-gateway:reloaded-at';
const RELOAD_LOOP_WINDOW_MS = 15_000;

export type Install =
  | { state: 'installing' }
  | { state: 'reloading' }
  | { state: 'failed'; reason: string };

export function installGateway(onChange: (install: Install) => void): void {
  void (async () => {
    if (!('serviceWorker' in navigator)) {
      throw new Error(
        'This browser offers no service worker here. The gateway needs one, and a ' +
          'browser grants them only to a secure context — Chrome and Firefox treat ' +
          'every *.localhost host as one.',
      );
    }
    const reloadedAt = Number(sessionStorage.getItem(RELOADED_KEY));
    sessionStorage.removeItem(RELOADED_KEY);
    if (Date.now() - reloadedAt < RELOAD_LOOP_WINDOW_MS) {
      throw new Error(
        'The gateway is installed but did not answer this page. Reload to try again; ' +
          'a shift-reload bypasses service workers, so use a plain one.',
      );
    }
    onChange({ state: 'installing' });
    await navigator.serviceWorker.register(SERVICE_WORKER_URL, { type: 'module', scope: '/' });
    // `ready` resolves once a worker is active for this scope. Whether it has
    // claimed *this* page does not matter: the reload is a navigation in its
    // scope, and an active worker answers those either way.
    await navigator.serviceWorker.ready;
    onChange({ state: 'reloading' });
    sessionStorage.setItem(RELOADED_KEY, String(Date.now()));
    location.reload();
  })().catch((error: unknown) => {
    onChange({
      state: 'failed',
      reason: error instanceof Error ? error.message : String(error),
    });
  });
}
