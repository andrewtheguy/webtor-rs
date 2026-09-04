import { useEffect, useState } from 'react';
import {
  gatewayUrl,
  isOnionHost,
  parseGatewayHost,
  parseOnionInput,
  type GatewayHost,
} from './gateway-host';
import { installGateway, type Install } from './install';

/** What `/<address>.onion/path` on the root host means: that path, on that onion's origin. */
function pathStyleTarget(location: Location): string | null {
  const [, first = '', ...rest] = location.pathname.split('/');
  if (!isOnionHost(first)) return null;
  return gatewayUrl(
    first,
    location.host,
    `/${rest.join('/')}${location.search}${location.hash}`,
  );
}

function Landing() {
  const [input, setInput] = useState('');
  const parsed = parseOnionInput(input);
  const rootHost = location.host;

  // The IPFS gateways answer `/ipfs/<cid>` by sending the browser to
  // `<cid>.ipfs.<host>`; this does the same for `/<address>.onion/…`, so a
  // pasted path-style URL still lands on an origin of its own.
  useEffect(() => {
    const target = pathStyleTarget(location);
    if (target) location.replace(target);
  }, []);

  const open = () => {
    if (parsed) location.href = gatewayUrl(parsed.onion, rootHost, parsed.pathAndQuery);
  };

  return (
    <main className="shell">
      <header className="hero">
        <p className="eyebrow">webtor-rs / browser gateway</p>
        <h1>Onion sites, with no Tor installed.</h1>
        <p className="intro">
          Each onion gets an origin of its own here, and a service worker on
          that origin runs a Tor client compiled to WASM: every request the
          page makes is fetched from the onion over circuits the worker builds
          itself. Static content only, and nothing leaves the browser except
          Tor cells to a Snowflake bridge.
        </p>
      </header>

      <section className="proof-card">
        <div className="card-heading">
          <div>
            <p className="step-number">OPEN</p>
            <h2>Browse an onion address</h2>
          </div>
        </div>

        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            open();
          }}
        >
          <label className="field field-wide">
            <span>Onion address or URL</span>
            <input
              type="text"
              value={input}
              spellCheck={false}
              autoFocus
              placeholder="<56 base32 characters>.onion/path"
              onChange={(event) => setInput(event.target.value)}
            />
          </label>
          <div className="actions field-wide">
            <button type="submit" disabled={parsed === null}>
              Open through the gateway
            </button>
          </div>
        </form>

        <div className="address">
          <p className="result-label">Where it goes</p>
          <code>
            {parsed
              ? gatewayUrl(parsed.onion, rootHost, parsed.pathAndQuery)
              : gatewayUrl('<address>.onion', rootHost)}
          </code>
          <p className="hint">
            The first visit to an onion installs the gateway on that origin and
            bootstraps a Tor client, which takes a minute or so with a directory
            snapshot and longer without one; the page then loads on its own.
            Later requests on the same origin reuse the client and its circuits
            while the browser keeps the worker running.
          </p>
        </div>
      </section>
    </main>
  );
}

function Installing({ gateway }: { gateway: GatewayHost }) {
  const [install, setInstall] = useState<Install>({ state: 'installing' });

  useEffect(() => {
    installGateway(setInstall);
  }, []);

  return (
    <main className="shell">
      <section className="proof-card">
        <div className="card-heading">
          <div>
            <p className="step-number">INSTALL</p>
            <h2>
              {install.state === 'failed'
                ? 'The gateway could not be installed'
                : install.state === 'reloading'
                  ? 'Handing this page to the gateway…'
                  : 'Installing the gateway on this origin…'}
            </h2>
          </div>
          <span className={`state state-${install.state === 'failed' ? 'failed' : 'publishing'}`}>
            <span className="state-dot" />
            {install.state}
          </span>
        </div>

        <div className="address">
          <p className="result-label">Onion</p>
          <code>{gateway.onion}</code>
          <p className="hint">
            A service worker for this origin alone; it answers every request
            here from the onion, over a Tor client of its own.
          </p>
        </div>

        {install.state === 'failed' && (
          <div className="failure">
            <p className="result-label">Failed</p>
            <p>{install.reason}</p>
          </div>
        )}

        <p className="hint">
          <a href={`http://${gateway.root}${location.port ? `:${location.port}` : ''}/`}>
            Back to the gateway
          </a>
        </p>
      </section>
    </main>
  );
}

export default function App() {
  const gateway = parseGatewayHost(location.hostname);
  return gateway ? <Installing gateway={gateway} /> : <Landing />;
}
