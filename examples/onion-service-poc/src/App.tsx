import { useEffect, useRef, useState } from 'react';
import { startListener, type Listener, type ReceivedMessage } from './listener';
import {
  normalizeAddress,
  sendMessage,
  type Delivery,
  type SendVia,
} from './sender';
import { browserReachesOnion } from './tor-browser';
import type { Bridge, LogEntry } from './tor-client';

/** Which end of the conversation this tab is. */
type Side = 'listen' | 'send';

/** Whether the browser's own `fetch` reaches `.onion`, i.e. Tor Browser. */
type BrowserTor = 'probing' | 'available' | 'unavailable';

type ListenState = 'idle' | 'publishing' | 'live' | 'failed';

function clock(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour12: false });
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function Feed({ entries }: { entries: LogEntry[] }) {
  return entries.length === 0 ? (
    <p className="hint">Idle.</p>
  ) : (
    <ul className="feed">
      {entries.map((entry) => (
        <li key={`${entry.at}-${entry.message}`}>
          <span className="at">{clock(entry.at)}</span>
          <span className={`level level-${entry.level}`}>{entry.message}</span>
        </li>
      ))}
    </ul>
  );
}

function BridgeField({
  bridge,
  disabled,
  onChange,
}: {
  bridge: Bridge;
  disabled: boolean;
  onChange: (bridge: Bridge) => void;
}) {
  return (
    <label className="field">
      <span>Bridge</span>
      <select
        value={bridge}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as Bridge)}
      >
        <option value="websocket">Snowflake WebSocket</option>
        <option value="webrtc">Snowflake WebRTC</option>
      </select>
    </label>
  );
}

function ListenSide() {
  const [bridge, setBridge] = useState<Bridge>('websocket');
  const [introPoints, setIntroPoints] = useState(3);
  const [state, setState] = useState<ListenState>('idle');
  const [address, setAddress] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [messages, setMessages] = useState<ReceivedMessage[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  const listener = useRef<Listener | null>(null);

  // Withdraw when this side is left, so the tab is not serving two things.
  useEffect(
    () => () => {
      void listener.current?.stop().catch(() => undefined);
      listener.current = null;
    },
    [],
  );

  const publish = async () => {
    setState('publishing');
    setLogs([]);
    setMessages([]);
    setFailure(null);
    try {
      listener.current = await startListener({
        bridge,
        introPoints,
        onLog: (entry) => setLogs((current) => [...current, entry]),
        onMessage: (message) =>
          setMessages((current) => [message, ...current].slice(0, 100)),
      });
      setAddress(listener.current.address);
      setState('live');
    } catch (error) {
      setFailure(describe(error));
      setState('failed');
    }
  };

  const withdraw = async () => {
    const running = listener.current;
    listener.current = null;
    setState('idle');
    setAddress(null);
    await running?.stop().catch(() => undefined);
  };

  const configurable = state === 'idle' || state === 'failed';

  return (
    <section className="proof-card">
      <div className="card-heading">
        <div>
          <p className="step-number">LISTEN</p>
          <h2>Publish an address and wait</h2>
        </div>
        <span className={`state state-${state}`}>
          <span className="state-dot" />
          {state}
        </span>
      </div>

      <div className="form-grid">
        <BridgeField bridge={bridge} disabled={!configurable} onChange={setBridge} />
        <label className="field">
          <span>Introduction points</span>
          <select
            value={introPoints}
            disabled={!configurable}
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
          <button type="button" className="secondary" onClick={withdraw}>
            Withdraw
          </button>
        ) : (
          <button type="button" onClick={publish} disabled={state === 'publishing'}>
            {state === 'publishing' ? 'Publishing…' : 'Publish onion service'}
          </button>
        )}
      </div>

      {address && (
        <div className="address">
          <p className="result-label">Send messages to</p>
          <code>{address}</code>
          <p className="hint">
            Give this to the other side, or from a shell through a local Tor:{' '}
            <code>
              curl --socks5-hostname 127.0.0.1:9050 -d hello http://{address}
              /message
            </code>
            . It listens only while this tab is open.
          </p>
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
          <p className="result-label">Messages received ({messages.length})</p>
          {messages.length === 0 ? (
            <p className="hint">Nothing yet.</p>
          ) : (
            <ul className="feed">
              {messages.map((message) => (
                <li key={`${message.at}-${message.text}`}>
                  <span className="at">{clock(message.at)}</span>
                  <span>{message.text}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="pane">
          <p className="result-label">Progress</p>
          <Feed entries={logs} />
        </div>
      </div>
    </section>
  );
}

function SendSide() {
  const [bridge, setBridge] = useState<Bridge>('websocket');
  const [addressInput, setAddressInput] = useState('');
  const [message, setMessage] = useState('');
  const [browserTor, setBrowserTor] = useState<BrowserTor>('probing');
  const [via, setVia] = useState<SendVia>('webtor');
  const [sending, setSending] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [failure, setFailure] = useState<string | null>(null);

  // Prefer the browser's Tor when there is one: in Tor Browser it is already
  // bootstrapped, and it spares the tab a Snowflake client of its own.
  useEffect(() => {
    let cancelled = false;
    void browserReachesOnion().then((reachable) => {
      if (cancelled) return;
      setBrowserTor(reachable ? 'available' : 'unavailable');
      if (reachable) setVia('browser');
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const address = normalizeAddress(addressInput);
  const ready = address != null && message.trim() !== '' && !sending;

  const send = async () => {
    if (address == null) return;
    setSending(true);
    setFailure(null);
    try {
      const delivery = await sendMessage({
        address,
        message,
        via,
        bridge,
        onLog: (entry) => setLogs((current) => [...current, entry]),
      });
      setDeliveries((current) => [delivery, ...current].slice(0, 40));
      setMessage('');
    } catch (error) {
      setFailure(describe(error));
    } finally {
      setSending(false);
    }
  };

  return (
    <section className="proof-card">
      <div className="card-heading">
        <div>
          <p className="step-number">SEND</p>
          <h2>Message an address</h2>
        </div>
        <span className={`state state-${sending ? 'publishing' : 'idle'}`}>
          <span className="state-dot" />
          {sending ? 'sending' : 'idle'}
        </span>
      </div>

      <div className="form-grid">
        <label className="field">
          <span>Send via</span>
          <select
            value={via}
            disabled={sending}
            onChange={(event) => setVia(event.target.value as SendVia)}
          >
            <option value="webtor">This tab's Tor client (Snowflake)</option>
            <option value="browser" disabled={browserTor !== 'available'}>
              {browserTor === 'probing'
                ? "The browser's own Tor (checking…)"
                : browserTor === 'available'
                  ? "The browser's own Tor (Tor Browser)"
                  : "The browser's own Tor (not Tor Browser)"}
            </option>
          </select>
        </label>
        {via === 'webtor' && (
          <BridgeField
            bridge={bridge}
            disabled={sending || logs.length > 0}
            onChange={setBridge}
          />
        )}
      </div>

      <div className="form-grid">
        <label className="field field-wide">
          <span>Onion address</span>
          <input
            type="text"
            value={addressInput}
            disabled={sending}
            spellCheck={false}
            placeholder="<56 base32 characters>.onion"
            onChange={(event) => setAddressInput(event.target.value)}
          />
        </label>
      </div>
      <div className="form-grid">
        <label className="field field-wide">
          <span>Message</span>
          <textarea
            value={message}
            disabled={sending}
            rows={4}
            onChange={(event) => setMessage(event.target.value)}
          />
        </label>
      </div>

      <div className="actions">
        <button type="button" onClick={send} disabled={!ready}>
          {sending
            ? 'Sending over Tor…'
            : via === 'browser'
              ? "Send through Tor Browser's Tor"
              : 'Send through Tor'}
        </button>
      </div>

      {failure && (
        <div className="failure">
          <p className="result-label">Failed</p>
          <p>{failure}</p>
        </div>
      )}

      <div className="panes">
        <div className="pane">
          <p className="result-label">Delivered ({deliveries.length})</p>
          {deliveries.length === 0 ? (
            <p className="hint">Nothing sent yet.</p>
          ) : (
            <ul className="feed">
              {deliveries.map((delivery, index) => (
                <li key={`${deliveries.length - index}`}>
                  <span className="at">{delivery.seconds}s</span>
                  <span>
                    via {delivery.via === 'browser' ? 'Tor Browser' : 'Snowflake'}{' '}
                    · HTTP {delivery.status} · {delivery.text.trim()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="pane">
          <p className="result-label">Progress</p>
          <Feed entries={logs} />
        </div>
      </div>
    </section>
  );
}

export default function App() {
  const [side, setSide] = useState<Side | null>(null);

  return (
    <main className="shell">
      <header className="hero">
        <p className="eyebrow">webtor-rs / browser proof of concept</p>
        <h1>Messages between tabs, over Tor.</h1>
        <p className="intro">
          One tab publishes a v3 onion service from WASM and listens on it;
          another posts a message to that address through Tor. No external Tor
          daemon, application proxy, backend, or port forwarded on either end.
        </p>
        <div className="sides">
          <button
            type="button"
            className={side === 'listen' ? '' : 'secondary'}
            onClick={() => setSide('listen')}
          >
            Listen for messages
          </button>
          <button
            type="button"
            className={side === 'send' ? '' : 'secondary'}
            onClick={() => setSide('send')}
          >
            Send a message
          </button>
        </div>
      </header>

      {side === 'listen' && <ListenSide />}
      {side === 'send' && <SendSide />}
    </main>
  );
}
