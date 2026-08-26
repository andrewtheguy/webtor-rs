import { useState } from 'react';
import {
  ONION_RELAYS,
  type ProofLog,
  type RoundTripResult,
  runNostrRoundTrip,
} from './nostr-roundtrip';

type RunState = 'idle' | 'running' | 'passed' | 'failed';

function shortRelay(relay: string): string {
  const host = new URL(relay).hostname;
  return `${host.slice(0, 12)}…${host.slice(-10)}`;
}

function formatDuration(milliseconds: number): string {
  const seconds = Math.round(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export default function App() {
  const [message, setMessage] = useState('hello from webtor over Nostr');
  const [bridge, setBridge] = useState<'websocket' | 'webrtc'>('websocket');
  const [relay, setRelay] = useState<'auto' | (typeof ONION_RELAYS)[number]>(
    'auto',
  );
  const [state, setState] = useState<RunState>('idle');
  const [logs, setLogs] = useState<ProofLog[]>([]);
  const [result, setResult] = useState<RoundTripResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const run = async () => {
    setState('running');
    setLogs([]);
    setResult(null);
    setFailure(null);

    try {
      const proof = await runNostrRoundTrip({
        bridge,
        relay,
        message: message.trim(),
        onLog: (entry) => setLogs((current) => [...current, entry]),
      });
      setResult(proof);
      setState('passed');
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error));
      setState('failed');
    }
  };

  return (
    <main className="shell">
      <header className="hero">
        <p className="eyebrow">webtor-rs / browser proof of concept</p>
        <h1>Nostr, through an onion.</h1>
        <p className="intro">
          One page. One in-browser Tor client. Two separate relay sockets. A
          signed event goes out through one and must come back through the
          other.
        </p>
      </header>

      <section className="proof-card" aria-labelledby="proof-heading">
        <div className="card-heading">
          <div>
            <p className="step-number">LIVE NETWORK TEST</p>
            <h2 id="proof-heading">Send + receive proof</h2>
          </div>
          <span className={`state state-${state}`}>
            <span className="state-dot" />
            {state}
          </span>
        </div>

        <div className="form-grid">
          <label className="field field-wide">
            <span>Message</span>
            <input
              value={message}
              maxLength={280}
              disabled={state === 'running'}
              onChange={(event) => setMessage(event.target.value)}
            />
          </label>

          <label className="field">
            <span>Onion relay</span>
            <select
              value={relay}
              disabled={state === 'running'}
              onChange={(event) =>
                setRelay(
                  event.target.value as
                    | 'auto'
                    | (typeof ONION_RELAYS)[number],
                )
              }
            >
              <option value="auto">First reachable</option>
              {ONION_RELAYS.map((url) => (
                <option key={url} value={url}>
                  {shortRelay(url)}
                </option>
              ))}
            </select>
          </label>

          <fieldset
            className="field bridge-field"
            disabled={state === 'running'}
          >
            <legend>Snowflake entry</legend>
            <label className="radio-label">
              <input
                type="radio"
                name="bridge"
                checked={bridge === 'websocket'}
                onChange={() => setBridge('websocket')}
              />
              Direct WebSocket
            </label>
            <label className="radio-label">
              <input
                type="radio"
                name="bridge"
                checked={bridge === 'webrtc'}
                onChange={() => setBridge('webrtc')}
              />
              Volunteer WebRTC
            </label>
          </fieldset>
        </div>

        <div className="action-row">
          <button
            className="run-button"
            type="button"
            disabled={state === 'running' || message.trim().length === 0}
            onClick={() => void run()}
          >
            {state === 'running' ? 'Proof running…' : 'Run round trip'}
          </button>
          <p>
            First bootstrap can take several minutes. Keep this tab in the
            foreground.
          </p>
        </div>
      </section>

      <section className="terminal" aria-label="Proof output" aria-live="polite">
        <div className="terminal-bar">
          <span />
          <span />
          <span />
          <p>transport trace</p>
        </div>
        <div className="terminal-body">
          {logs.length === 0 ? (
            <p className="terminal-empty">
              Ready. The trace will show bootstrap, subscription, publication,
              acknowledgement, and receipt.
            </p>
          ) : (
            <ol>
              {logs.map((entry, index) => (
                <li
                  className={`log-${entry.level}`}
                  key={`${index}-${entry.message}`}
                >
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <div>
                    <strong>{entry.message}</strong>
                    {entry.detail && <code>{entry.detail}</code>}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      </section>

      {result && (
        <section className="result result-pass">
          <p className="result-label">ROUND TRIP PASSED</p>
          <h2>The relay acknowledged it. The subscriber received it.</h2>
          <dl>
            <div>
              <dt>Elapsed</dt>
              <dd>{formatDuration(result.elapsedMs)}</dd>
            </div>
            <div>
              <dt>Relay</dt>
              <dd>{shortRelay(result.relay)}</dd>
            </div>
            <div>
              <dt>Event ID</dt>
              <dd>{result.eventId}</dd>
            </div>
            <div>
              <dt>Ephemeral pubkey</dt>
              <dd>{result.pubkey}</dd>
            </div>
          </dl>
        </section>
      )}

      {failure && (
        <section className="result result-fail">
          <p className="result-label">ROUND TRIP FAILED</p>
          <h2>No proof was completed.</h2>
          <p>{failure}</p>
        </section>
      )}

      <footer>
        <p>
          The message is plaintext on a public relay. Tor hides this browser's
          network address from the relay; it does not encrypt Nostr content.
        </p>
      </footer>
    </main>
  );
}
