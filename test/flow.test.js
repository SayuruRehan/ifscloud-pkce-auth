// End-to-end run of the app against a tiny mock of IFS IAM (Keycloak-style realm).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startMockIam } from './support/mock-iam.js';

const CLIENT_ID = 'MAHARA_PKCE_TEST';
const REALM = 'testrealm';
let idp;
let idpUrl;
let issued;
let appServer;
let appUrl;

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
  idp = await startMockIam({ clientId: CLIENT_ID, realm: REALM });
  ({ url: idpUrl, issued } = idp);
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

test('calls by user keep both users across a switch', async () => {
  const path = '/main/ifsapplications/projection/v1/CustomerHandling.svc/CustomerInfoSet?$top=1';
  const go = browser();
  await signIn(go, 'ALAIN');
  await go(`${appUrl}/probe`, form({ path }));
  const switchRes = await go(`${appUrl}/switch-user`, form({ login_hint: 'BOB' }));
  const atIam = await fetch(new URL(switchRes.headers.get('location')), { redirect: 'manual' });
  await completeLogin(go, await go(local(atIam.headers.get('location'))));
  await go(`${appUrl}/probe`, form({ path }));
  const home = await (await go(`${appUrl}/`)).text();
  assert.match(home, /alain 1 allowed · 0 refused/);
  assert.match(home, /bob 0 allowed · 1 refused/);
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
  assert.match(home, /data-signature="valid"/);
});

test('IFS permissions differ per signed-in user', async () => {
  const path = '/main/ifsapplications/projection/v1/CustomerHandling.svc/CustomerInfoSet?$top=1';
  for (const [user, status] of [['ALAIN', '200'], ['BOB', '403']]) {
    const go = browser();
    await signIn(go, user);
    await go(`${appUrl}/probe`, form({ path }));
    const home = await (await go(`${appUrl}/`)).text();
    assert.match(home, new RegExp(`class="result-head">\\s*<span class="pill [a-z]+" data-status="${status}"`), `${user} should get ${status}`);
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
