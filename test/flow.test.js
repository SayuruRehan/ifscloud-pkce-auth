// End-to-end run of the app against a tiny mock of IFS IAM (Keycloak-style realm).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const CLIENT_ID = 'MAHARA_PKCE_TEST';
const REALM = 'testrealm';
let idp;
let idpUrl;
let appServer;
let appUrl;
const codes = new Map();
const issued = { tokenRequests: [], logouts: [] };

async function startMockIam() {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

  idp = createServer(async (req, res) => {
    const url = new URL(req.url, idpUrl);
    const issuer = `${idpUrl}/auth/realms/${REALM}`;
    const base = `/auth/realms/${REALM}`;
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    if (url.pathname === `${base}/.well-known/openid-configuration`) {
      return json(200, {
        issuer,
        authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${issuer}/protocol/openid-connect/token`,
        end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
        jwks_uri: `${issuer}/protocol/openid-connect/certs`,
        code_challenge_methods_supported: ['plain', 'S256'],
      });
    }
    if (url.pathname === `${base}/protocol/openid-connect/certs`) return json(200, { keys: [jwk] });

    if (url.pathname === `${base}/protocol/openid-connect/logout`) {
      const p = url.searchParams;
      issued.logouts.push(Object.fromEntries(p));
      const back = new URL(p.get('post_logout_redirect_uri'));
      if (p.get('state')) back.searchParams.set('state', p.get('state'));
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }

    if (url.pathname === `${base}/protocol/openid-connect/auth`) {
      // Pretend the user typed their credentials; login_hint picks the user.
      const p = url.searchParams;
      assert.equal(p.get('code_challenge_method'), 'S256');
      const code = randomUUID();
      codes.set(code, {
        challenge: p.get('code_challenge'),
        nonce: p.get('nonce'),
        redirectUri: p.get('redirect_uri'),
        user: p.get('login_hint') ?? 'ALAIN',
      });
      const back = new URL(p.get('redirect_uri'));
      back.searchParams.set('code', code);
      back.searchParams.set('state', p.get('state'));
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }

    if (url.pathname === `${base}/protocol/openid-connect/token`) {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      issued.tokenRequests.push(Object.fromEntries(form));
      const entry = codes.get(form.get('code'));
      codes.delete(form.get('code'));
      if (!entry) return json(400, { error: 'invalid_grant', error_description: 'Code not valid' });
      const expected = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
      if (expected !== entry.challenge) {
        return json(400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
      const sign = (claims) =>
        new SignJWT(claims)
          .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
          .setIssuer(issuer)
          .setSubject(`sub-${entry.user}`)
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
      return json(200, {
        token_type: 'Bearer',
        expires_in: 300,
        scope: 'openid microprofile-jwt',
        access_token: await sign({ azp: CLIENT_ID, upn: entry.user, aud: 'account' }),
        id_token: await sign({ aud: CLIENT_ID, nonce: entry.nonce, preferred_username: entry.user.toLowerCase() }),
      });
    }

    // A fake IFS projection: only ALAIN may read it.
    if (url.pathname.startsWith('/main/ifsapplications/projection/v1/')) {
      const token = req.headers.authorization?.replace(/^Bearer /, '');
      const upn = token && JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).upn;
      return upn === 'ALAIN' ? json(200, { value: [{ Id: 1 }] }) : json(403, { error: { message: 'Forbidden' } });
    }
    json(404, {});
  });
  await new Promise((r) => idp.listen(0, '127.0.0.1', r));
  idpUrl = `http://127.0.0.1:${idp.address().port}`;
}

// Minimal cookie-keeping browser that does not follow redirects.
function browser() {
  let cookie = '';
  return async (url, init = {}) => {
    const res = await fetch(url, { ...init, redirect: 'manual', headers: { ...init.headers, cookie } });
    const set = res.headers.getSetCookie();
    if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
    return res;
  };
}

const form = (data) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(data),
});

// Replays a redirect that targets the fixed REDIRECT_URI / logout port against the test server.
const local = (location) => {
  const u = new URL(location);
  return `${appUrl}${u.pathname}${u.search}`;
};

async function completeLogin(go, login) {
  assert.equal(login.status, 302);
  const atIam = await fetch(new URL(login.headers.get('location')), { redirect: 'manual' });
  return go(local(atIam.headers.get('location')));
}

async function signIn(go, user) {
  return completeLogin(go, await go(`${appUrl}/login`, form({ login_hint: user })));
}

before(async () => {
  await startMockIam();
  Object.assign(process.env, {
    IFS_URL: idpUrl,
    IFS_REALM: REALM,
    IFS_CLIENT_ID: CLIENT_ID,
    REDIRECT_URI: 'http://localhost:3999/callback',
  });
  const { app } = await import('../src/app.js');
  appServer = app.listen(0);
  await new Promise((r) => appServer.once('listening', r));
  appUrl = `http://127.0.0.1:${appServer.address().port}`;
});

after(() => {
  appServer?.close();
  idp?.close();
});

test('authorize request carries PKCE, state, nonce and openid scope', async () => {
  const go = browser();
  const res = await go(`${appUrl}/login`, form({ login_hint: 'ALAIN' }));
  const p = new URL(res.headers.get('location')).searchParams;
  assert.equal(p.get('client_id'), CLIENT_ID);
  assert.equal(p.get('response_type'), 'code');
  assert.equal(p.get('code_challenge_method'), 'S256');
  assert.match(p.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
  assert.ok(p.get('state') && p.get('nonce'));
  assert.equal(p.get('scope'), 'openid microprofile-jwt');
  assert.equal(p.get('login_hint'), 'ALAIN');
  assert.equal(p.get('prompt'), null);
});

test('switching user ends the IAM session first, then logs in the new user', async () => {
  const go = browser();
  await signIn(go, 'ALAIN');
  const switchRes = await go(`${appUrl}/switch-user`, form({ login_hint: 'BOB' }));
  const logout = new URL(switchRes.headers.get('location'));
  assert.match(logout.pathname, /\/protocol\/openid-connect\/logout$/);
  assert.ok(logout.searchParams.get('id_token_hint'), 'logout must carry id_token_hint');
  assert.ok(logout.searchParams.get('state'));

  // IAM logs out and returns to post_logout_redirect_uri with our state; the app starts the new login.
  const atIam = await fetch(logout, { redirect: 'manual' });
  const login = await go(local(atIam.headers.get('location')));
  assert.equal(new URL(login.headers.get('location')).searchParams.get('login_hint'), 'BOB');
  await completeLogin(go, login);
  const home = await (await go(`${appUrl}/`)).text();
  assert.match(home, /Signed in as <span class="user">bob<\/span>/);
});

test('a returning logout with a foreign state does not start a login', async () => {
  const go = browser();
  await signIn(go, 'ALAIN');
  await go(`${appUrl}/switch-user`, form({}));
  const res = await go(`${appUrl}/?state=forged`);
  assert.equal(res.status, 200);
});

test('full sign-in: code + verifier exchanged, ID token validated, user shown', async () => {
  const go = browser();
  const cb = await signIn(go, 'ALAIN');
  assert.equal(cb.headers.get('location'), '/');
  const last = issued.tokenRequests.at(-1);
  assert.equal(last.grant_type, 'authorization_code');
  assert.match(last.code_verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(last.client_secret, undefined, 'public client must not send a secret');
  const home = await (await go(`${appUrl}/`)).text();
  assert.match(home, /Signed in as <span class="user">alain<\/span>/);
  assert.match(home, /valid \(realm JWKS, issuer matches\)/);
});

test('IFS permissions differ per signed-in user', async () => {
  const path = '/main/ifsapplications/projection/v1/CustomerHandling.svc/CustomerInfoSet?$top=1';
  for (const [user, status] of [['ALAIN', '200'], ['BOB', '403']]) {
    const go = browser();
    await signIn(go, user);
    await go(`${appUrl}/probe`, form({ path }));
    const home = await (await go(`${appUrl}/`)).text();
    assert.match(home, new RegExp(`Last API call <span class="badge [a-z]+">${status}`), `${user} should get ${status}`);
  }
});

test('callback with a wrong state is rejected', async () => {
  const go = browser();
  await go(`${appUrl}/login`, form({}));
  await go(`${appUrl}/callback?code=x&state=forged`);
  const home = await (await go(`${appUrl}/`)).text();
  assert.match(home, /State mismatch/);
  assert.doesNotMatch(home, /Signed in as/);
});

test('probe refuses to send the token to another origin', async () => {
  const go = browser();
  await signIn(go, 'ALAIN');
  await go(`${appUrl}/probe`, form({ path: '//evil.example/steal' }));
  const home = await (await go(`${appUrl}/`)).text();
  assert.match(home, /Enter a path relative to IFS_URL/);
});
