// The hostnames this gateway answers on, and the URLs it builds from them.
//
// One onion, one origin: `http://<address>.onion.<root>` is where a site
// lives, `<root>` being whatever host the gateway itself was opened on
// (`intor.localhost:5173`, say). The browser then does the isolation — each
// site's cookies, storage and service worker are its own, exactly as a
// subdomain gateway for IPFS keeps one CID's content from another's.

/** The service's own name, `<56 base32 characters>.onion`. */
export type OnionHost = string;

const ONION_HOST = /^[a-z2-7]{56}\.onion$/;
const GATEWAY_HOST = /^([a-z2-7]{56}\.onion)\.(.+)$/;

/** Whether `host` names a v3 onion service. Lowercase only, as on the wire. */
export function isOnionHost(host: string): host is OnionHost {
  return ONION_HOST.test(host);
}

export interface GatewayHost {
  onion: OnionHost;
  /** The host the gateway was opened on, without a port. */
  root: string;
}

/** Take `<onion>.<root>` apart, or `null` for any other hostname. */
export function parseGatewayHost(hostname: string): GatewayHost | null {
  const match = GATEWAY_HOST.exec(hostname.toLowerCase());
  return match ? { onion: match[1], root: match[2] } : null;
}

/**
 * The gateway URL for a path on an onion, where `rootHost` is the gateway's
 * own host with its port (`location.host` on the landing page).
 */
export function gatewayUrl(onion: OnionHost, rootHost: string, pathAndQuery = '/'): string {
  return `http://${onion}.${rootHost}${pathAndQuery}`;
}

export interface OnionLocation {
  onion: OnionHost;
  /** Path, query and fragment, beginning with `/`. */
  pathAndQuery: string;
}

/**
 * An onion address the way people paste one — bare, with `.onion`, or as a
 * whole `http://` URL — or `null` when it is none of those.
 */
export function parseOnionInput(input: string): OnionLocation | null {
  const trimmed = input.trim();
  if (trimmed === '') return null;
  const withScheme = /^[a-z]+:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' || url.username || url.password) return null;
  if (url.port !== '' && url.port !== '80') return null;
  const onion = url.hostname.endsWith('.onion') ? url.hostname : `${url.hostname}.onion`;
  if (!isOnionHost(onion)) return null;
  return { onion, pathAndQuery: `${url.pathname}${url.search}${url.hash}` };
}
