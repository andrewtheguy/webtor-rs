// The worker half of the harness: a whole client living in a dedicated
// worker, where there is no `window`. What the page asks of it arrives as
// messages and what it answers goes back the same way, so the Node side
// drives it through the page like everything else.
//
// A service worker has the same global scope shape as this one, minus the
// `Worker` constructor to start it from a test page; passing here is what
// says the wasm runs in either.
import init, { WebtorClient } from '/crates/webtor-wasm/pkg/webtor_wasm.js';

let client = null;

const handlers = {
  async create({ options, seedUrl }) {
    const started = performance.now();
    const settings = {
      ...options,
      onLog: (message, level) => postMessage({ type: 'log', line: `${level}: ${message}` }),
    };
    if (seedUrl) {
      const response = await fetch(seedUrl);
      if (!response.ok) {
        throw new Error(`Seed ${seedUrl} answered HTTP ${response.status}`);
      }
      settings.directorySeed = await response.text();
    }
    client = await WebtorClient.create(settings);
    return { seconds: Number(((performance.now() - started) / 1000).toFixed(1)) };
  },

  async fetch({ url, options }) {
    if (!client) throw new Error('No worker client; call workerCreate first');
    const started = performance.now();
    const response = await client.fetch(url, options);
    return {
      status: response.status,
      byteLength: response.bytes().length,
      seconds: Number(((performance.now() - started) / 1000).toFixed(1)),
    };
  },

  async close() {
    if (client) await client.close();
    client = null;
    return 'closed';
  },
};

await init();

onmessage = async ({ data: { id, method, args } }) => {
  try {
    const handler = handlers[method];
    if (!handler) throw new Error(`Worker has no method "${method}"`);
    postMessage({ id, result: await handler(args) });
  } catch (error) {
    postMessage({ id, error: error instanceof Error ? error.message : String(error) });
  }
};

postMessage({ type: 'ready' });
