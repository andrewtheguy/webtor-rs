// The pages the gateway serves itself: what a visitor sees while the Tor
// client bootstraps, and what a request that could not be answered gets.
// Both are self-contained documents — the worker answers every request on
// this origin from the onion, so nothing here may load a script or a style
// sheet by URL.

const STYLE = `
  :root { color: #eeeae0; background: #11100d; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; box-sizing: border-box;
    background: radial-gradient(circle at 12% 3%, rgb(151 222 139 / 10%), transparent 25rem), #11100d; }
  main { width: min(720px, 100%); padding: clamp(24px, 5vw, 40px); border: 1px solid #35332d; border-radius: 18px;
    background: rgb(25 24 20 / 94%); box-shadow: 0 30px 90px rgb(0 0 0 / 24%); }
  .eyebrow { margin: 0 0 14px; color: #a5e995; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; }
  h1 { margin: 0 0 18px; font-family: Georgia, "Times New Roman", serif; font-size: 2rem; font-weight: 400; letter-spacing: -0.03em; }
  code { overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #a5e995; }
  p { margin: 0 0 12px; color: #aaa69d; line-height: 1.6; }
  .box { margin-top: 22px; padding: 18px; border: 1px solid #35332d; border-radius: 14px; background: #16150f; }
  .failure { border-color: #5a3a3a; }
  .failure p { color: #e9b7b7; overflow-wrap: anywhere; }
  ul { margin: 0; padding: 0; max-height: 300px; overflow: auto; list-style: none;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; line-height: 1.6; }
  li { display: flex; gap: 12px; padding: 5px 0; border-bottom: 1px solid rgb(255 255 255 / 4%); overflow-wrap: anywhere; }
  li:last-child { border-bottom: 0; }
  .at { flex: none; color: #6f6c65; }
  .success { color: #a5e995; } .warn { color: #e9d38f; } .error { color: #e9b7b7; }
  .dot { display: inline-block; width: 8px; height: 8px; margin-right: 9px; border-radius: 50%; background: #e9d38f;
    animation: pulse 1.4s ease-in-out infinite; vertical-align: middle; }
  @keyframes pulse { 50% { opacity: 0.25; } }
  button { padding: 11px 22px; border: 0; border-radius: 999px; background: #a5e995; color: #11100d; font: inherit; font-weight: 600; cursor: pointer; }
  a { color: #a5e995; }
`;

function escape(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function document(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#11100d">
<title>${escape(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}

/**
 * Shown for a navigation while the Tor client is not yet up. The page asks
 * the worker for its progress, shows every line, and reloads itself once the
 * client is ready — that reload is the request the onion then answers. Asking
 * every ten seconds also keeps the worker alive: a browser stops an idle
 * service worker within about half a minute, and a bootstrap over Snowflake
 * can take longer than that.
 */
export function bootstrapPage(onion: string, requested: string): string {
  return document(
    `Connecting to ${onion}`,
    `<p class="eyebrow">webtor onion gateway</p>
<h1><span class="dot" id="dot"></span><span id="status">Connecting to Tor…</span></h1>
<p>Bootstrapping a Tor client in this origin's service worker, then fetching <code>${escape(requested)}</code> from <code>${escape(onion)}</code>. The page loads on its own when the client is ready.</p>
<div class="box failure" id="failure" hidden>
  <p id="reason"></p>
  <button type="button" onclick="location.reload()">Try again</button>
</div>
<div class="box"><ul id="lines"><li>Waiting for the gateway…</li></ul></div>
<script>
(() => {
  const status = document.getElementById('status');
  const dot = document.getElementById('dot');
  const failure = document.getElementById('failure');
  const reason = document.getElementById('reason');
  const list = document.getElementById('lines');
  const worker = navigator.serviceWorker;
  if (!worker || !worker.controller) {
    status.textContent = 'The gateway is not controlling this page';
    reason.textContent = 'Reload to let the service worker take over.';
    failure.hidden = false;
    return;
  }
  let reloading = false;
  const clock = (at) => new Date(at).toLocaleTimeString([], { hour12: false });
  function render(progress) {
    list.replaceChildren(...progress.lines.map((line) => {
      const item = document.createElement('li');
      const at = document.createElement('span');
      at.className = 'at';
      at.textContent = clock(line.at);
      const message = document.createElement('span');
      message.className = line.level;
      message.textContent = line.message;
      item.append(at, message);
      return item;
    }));
    list.scrollTop = list.scrollHeight;
    if (progress.phase === 'ready' && !reloading) {
      reloading = true;
      status.textContent = 'Connected, loading the page…';
      location.reload();
    } else if (progress.phase === 'failed') {
      status.textContent = 'Could not connect to Tor';
      dot.hidden = true;
      reason.textContent = progress.failure || 'The bootstrap failed for no stated reason.';
      failure.hidden = false;
    }
  }
  worker.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'progress') render(event.data);
  });
  const subscribe = () => worker.controller && worker.controller.postMessage({ type: 'subscribe' });
  subscribe();
  setInterval(subscribe, 10000);
})();
</script>`,
  );
}

/** What a navigation gets when the onion could not answer it. */
export function errorPage(onion: string, title: string, detail: string): string {
  return document(
    `${title} · ${onion}`,
    `<p class="eyebrow">webtor onion gateway</p>
<h1>${escape(title)}</h1>
<p>While fetching from <code>${escape(onion)}</code>:</p>
<div class="box failure"><p>${escape(detail)}</p></div>
<p style="margin-top: 22px"><button type="button" onclick="location.reload()">Try again</button></p>`,
  );
}
