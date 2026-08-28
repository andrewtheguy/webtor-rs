import { useRef, useState } from 'react';
import {
  startOnionService,
  type LogEntry,
  type RunningService,
  type SelfFetch,
  type ServedRequest,
} from './onion-service';

type State = 'idle' | 'publishing' | 'live' | 'failed';

function clock(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour12: false });
}

export default function App() {
  const [bridge, setBridge] = useState<'websocket' | 'webrtc'>('websocket');
  const [introPoints, setIntroPoints] = useState(3);
  const [state, setState] = useState<State>('idle');
  const [address, setAddress] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [requests, setRequests] = useState<ServedRequest[]>([]);
  const [selfFetch, setSelfFetch] = useState<SelfFetch | null>(null);
  const [fetching, setFetching] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const service = useRef<RunningService | null>(null);

  const publish = async () => {
    setState('publishing');
    setLogs([]);
    setRequests([]);
    setSelfFetch(null);
    setFailure(null);
    try {
      service.current = await startOnionService({
        bridge,
        introPoints,
        onLog: (entry) => setLogs((current) => [...current, entry]),
        onRequest: (request) =>
          setRequests((current) => [request, ...current].slice(0, 40)),
      });
      setAddress(service.current.address);
      setState('live');
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error));
      setState('failed');
    }
  };

  const fetchSelf = async () => {
    if (!service.current) return;
    setFetching(true);
    setFailure(null);
    try {
      setSelfFetch(await service.current.fetchSelf(`/hit-${Date.now()}`));
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error));
    } finally {
      setFetching(false);
    }
  };

  const withdraw = async () => {
    const running = service.current;
    service.current = null;
    setState('idle');
    setAddress(null);
    setSelfFetch(null);
    await running?.stop().catch(() => undefined);
  };

  return (
    <main className="shell">
      <header className="hero">
        <p className="eyebrow">webtor-rs / browser proof of concept</p>
        <h1>A hidden service, in a tab.</h1>
        <p className="intro">
          This page generates a v3 onion identity, establishes its own
          introduction points, uploads a signed descriptor to the responsible
          HSDirs, and answers the streams clients open — all from WASM in the
          browser. No external Tor daemon, application proxy, backend, or port
          forwarded.
        </p>
      </header>

      <section className="proof-card">
        <div className="card-heading">
          <div>
            <p className="step-number">LIVE NETWORK TEST</p>
            <h2>Publish and serve</h2>
          </div>
          <span className={`state state-${state}`}>
            <span className="state-dot" />
            {state}
          </span>
        </div>

        <div className="form-grid">
          <label className="field">
            <span>Bridge</span>
            <select
              value={bridge}
              disabled={state !== 'idle' && state !== 'failed'}
              onChange={(event) =>
                setBridge(event.target.value as 'websocket' | 'webrtc')
              }
            >
              <option value="websocket">Snowflake WebSocket</option>
              <option value="webrtc">Snowflake WebRTC</option>
            </select>
          </label>
          <label className="field">
            <span>Introduction points</span>
            <select
              value={introPoints}
              disabled={state !== 'idle' && state !== 'failed'}
              onChange={(event) => setIntroPoints(Number(event.target.value))}
            >
              {[1, 2, 3, 4, 5, 6].map((count) => (
                <option key={count} value={count}>
                  {count}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="actions">
          {state === 'live' ? (
            <>
              <button type="button" onClick={fetchSelf} disabled={fetching}>
                {fetching ? 'Fetching over Tor…' : 'Fetch it back through Tor'}
              </button>
              <button type="button" className="secondary" onClick={withdraw}>
                Withdraw
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={publish}
              disabled={state === 'publishing'}
            >
              {state === 'publishing' ? 'Publishing…' : 'Publish onion service'}
            </button>
          )}
        </div>

        {address && (
          <div className="address">
            <p className="result-label">Reachable at</p>
            <code>http://{address}/</code>
            <p className="hint">
              Open it in Tor Browser, or curl it through a local Tor:{' '}
              <code>curl --socks5-hostname 127.0.0.1:9050 http://{address}/</code>
              . It answers only while this tab is open.
            </p>
          </div>
        )}

        {selfFetch && (
          <div className="result">
            <p className="result-label">
              Round trip · HTTP {selfFetch.status} in {selfFetch.seconds}s
            </p>
            <pre>{selfFetch.text}</pre>
          </div>
        )}

        {failure && (
          <div className="failure">
            <p className="result-label">Failed</p>
            <p>{failure}</p>
          </div>
        )}

        <div className="panes">
          <div className="pane">
            <p className="result-label">Requests answered ({requests.length})</p>
            {requests.length === 0 ? (
              <p className="hint">Nothing yet.</p>
            ) : (
              <ul className="feed">
                {requests.map((request) => (
                  <li key={`${request.at}-${request.line}`}>
                    <span className="at">{clock(request.at)}</span>
                    <span>{request.line}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="pane">
            <p className="result-label">Progress</p>
            {logs.length === 0 ? (
              <p className="hint">Idle.</p>
            ) : (
              <ul className="feed">
                {logs.map((entry) => (
                  <li key={`${entry.at}-${entry.message}`}>
                    <span className="at">{clock(entry.at)}</span>
                    <span className={`level level-${entry.level}`}>
                      {entry.message}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
