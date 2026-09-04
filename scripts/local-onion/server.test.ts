import { describe, expect, it } from 'bun:test';
import { handle, parseCookies } from './server';

const HOST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion';
const ORIGIN = `http://${HOST}`;

function request(path: string, init: RequestInit & { cookie?: string } = {}): Request {
  const headers = new Headers(init.headers);
  headers.set('host', HOST);
  if (init.cookie) headers.set('cookie', init.cookie);
  return new Request(`${ORIGIN}${path}`, { ...init, headers });
}

function form(fields: Record<string, string>, extra: Record<string, string> = {}): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...extra },
    body: new URLSearchParams(fields).toString(),
  };
}

describe('parseCookies', () => {
  it('reads a Cookie header', () => {
    expect(parseCookies('a=1; b=two%20words; =nameless; novalue')).toEqual({
      a: '1',
      b: 'two words',
    });
    expect(parseCookies(null)).toEqual({});
  });
});

describe('the home page', () => {
  it('counts visits in a cookie and sets two cookies at once', async () => {
    const first = await handle(request('/'));
    expect(first.status).toBe(200);
    expect(first.headers.get('content-type')).toMatch(/text\/html/);
    expect(await first.text()).toContain('<p id="visits">Visit 1</p>');
    const cookies = first.headers.getSetCookie();
    expect(cookies).toHaveLength(2);
    expect(cookies[0]).toBe('visits=1; Path=/');
    expect(cookies[1]).toMatch(/^seen=\d{4}-.*; Path=\/; Max-Age=3600$/);

    const second = await handle(request('/', { cookie: 'visits=4' }));
    expect(await second.text()).toContain('Visit 5');
    expect(second.headers.getSetCookie()[0]).toBe('visits=5; Path=/');
  });

  it('says who is signed in, escaped', async () => {
    const anonymous = await handle(request('/'));
    expect(await anonymous.text()).toContain('<p id="who">Not signed in</p>');
    const signedIn = await handle(request('/', { cookie: 'session=%3Cb%3Eme' }));
    expect(await signedIn.text()).toContain('<p id="who">Signed in as &lt;b&gt;me</p>');
  });

  it('answers GET only', async () => {
    expect((await handle(request('/', { method: 'POST' }))).status).toBe(405);
  });
});

describe('signing in and out', () => {
  it('refuses a POST from another origin, or from none', async () => {
    const none = await handle(request('/login', form({ name: 'x' })));
    expect(none.status).toBe(403);
    expect(await none.text()).toContain('Origin (none)');
    const other = await handle(
      request('/login', form({ name: 'x' }, { origin: 'http://gateway.localhost:5173' })),
    );
    expect(other.status).toBe(403);
    const logout = await handle(request('/logout', { method: 'POST' }));
    expect(logout.status).toBe(403);
  });

  it('signs in with a 303 and a session cookie', async () => {
    const response = await handle(request('/login', form({ name: 'Ada L' }, { origin: ORIGIN })));
    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe('/');
    expect(response.headers.getSetCookie()).toEqual(['session=Ada%20L; Path=/; HttpOnly']);
  });

  it('wants a name', async () => {
    const response = await handle(request('/login', form({ name: '  ' }, { origin: ORIGIN })));
    expect(response.status).toBe(400);
  });

  it('signs out by lapsing the cookie', async () => {
    const response = await handle(
      request('/logout', { method: 'POST', headers: { origin: ORIGIN } }),
    );
    expect(response.status).toBe(303);
    expect(response.headers.getSetCookie()).toEqual(['session=; Path=/; Max-Age=0']);
  });
});

describe('echo', () => {
  it('returns the request as JSON', async () => {
    const response = await handle(
      request('/echo?x=1&y=two', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-custom': 'yes' },
        body: '{"n":1}',
        cookie: 'session=me; visits=3',
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toMatch(/application\/json/);
    const echoed = await response.json();
    expect(echoed).toMatchObject({
      method: 'PUT',
      path: '/echo',
      query: { x: '1', y: 'two' },
      body: '{"n":1}',
      cookies: { session: 'me', visits: '3' },
    });
    expect(echoed.headers['x-custom']).toBe('yes');
    expect(echoed.headers.host).toBe(HOST);
  });
});

it('has nothing elsewhere', async () => {
  const response = await handle(request('/nowhere'));
  expect(response.status).toBe(404);
  expect(await response.text()).toBe('Nothing at /nowhere\n');
});
