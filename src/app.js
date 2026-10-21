import express from 'express';
import session from 'express-session';
import { config } from './config.js';
import { createCodeChallenge, createCodeVerifier, randomToken } from './pkce.js';
import {
  buildAuthorizeUrl,
  buildLogoutUrl,
  discover,
  exchangeCode,
  inspectAccessToken,
  refreshTokens,
  validateIdToken,
} from './oidc.js';
import { renderHome } from './views.js';

const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;
const MAX_TRACE_ENTRIES = 40;
const MAX_HISTORY_ENTRIES = 20;

export const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    name: 'ifs_pkce_demo',
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    // Tokens live only in this server-side (in-memory) session, never in the browser.
    cookie: { httpOnly: true, sameSite: 'lax', secure: config.redirectUri.startsWith('https:') },
  }),
);

function trace(req, step, details = {}) {
  const entries = req.session.trace ?? [];
  entries.push({ at: new Date().toISOString(), step, details });
  req.session.trace = entries.slice(-MAX_TRACE_ENTRIES);
}

// One message for the next page view, shown inside the block it belongs to
// ('login', 'session' or 'probe').
function flash(req, scope, message) {
  req.session.flash = { scope, message };
}

function shorten(value, keep = 8) {
  if (!value) return value;
  return value.length <= keep ? value : `${value.slice(0, keep)}… (${value.length} chars)`;
}

function storeTokens(req, tokenResponse) {
  const now = Date.now();
  const previous = req.session.auth?.tokens ?? {};
  req.session.auth = {
    ...req.session.auth,
    tokens: {
      access_token: tokenResponse.access_token,
      // Refresh responses may omit tokens that did not rotate; keep the old ones then.
      refresh_token: tokenResponse.refresh_token ?? previous.refresh_token,
      id_token: tokenResponse.id_token ?? previous.id_token,
      token_type: tokenResponse.token_type,
      scope: tokenResponse.scope,
      expires_at: tokenResponse.expires_in ? now + tokenResponse.expires_in * 1000 : undefined,
      expires_in: tokenResponse.expires_in,
      refresh_expires_at: tokenResponse.refresh_expires_in
        ? now + tokenResponse.refresh_expires_in * 1000
        : previous.refresh_expires_at,
      refresh_expires_in: tokenResponse.refresh_expires_in ?? previous.refresh_expires_in,
    },
  };
}

function tokenSummary(tokenResponse) {
  return {
    token_type: tokenResponse.token_type,
    expires_in: tokenResponse.expires_in,
    refresh_expires_in: tokenResponse.refresh_expires_in,
    scope: tokenResponse.scope,
    received: ['access_token', 'refresh_token', 'id_token'].filter((k) => tokenResponse[k]).join(', '),
  };
}

app.get('/', async (req, res, next) => {
  // Back from the IAM logout of a user switch: start the new login straight away.
  const pendingSwitch = req.session.switchUser;
  if (pendingSwitch && req.query.state === pendingSwitch.state) {
    delete req.session.switchUser;
    trace(req, 'IAM session ended', { previous_user: pendingSwitch.previousUser });
    return startLogin(req, res, next, { loginHint: pendingSwitch.loginHint });
  }

  let discovery;
  let discoveryError;
  const flashed = req.session.flash;
  delete req.session.flash;
  try {
    discovery = await discover();
  } catch (err) {
    discoveryError = err.message;
  }

  let accessToken;
  if (discovery && req.session.auth?.tokens?.access_token) {
    accessToken = await inspectAccessToken(discovery.metadata, req.session.auth.tokens.access_token);
  }

  res.type('html').send(
    renderHome({
      config,
      discovery,
      auth: req.session.auth,
      accessToken,
      trace: req.session.trace ?? [],
      probe: req.session.probe,
      history: req.session.history ?? [],
      flash: flashed,
      discoveryError,
    }),
  );
});

// Step 1: create verifier/challenge/state/nonce and send the browser to IFS IAM.
async function startLogin(req, res, next, { loginHint }) {
  try {
    const { metadata, url: discoveryUrl } = await discover();
    const codeVerifier = createCodeVerifier();
    const codeChallenge = createCodeChallenge(codeVerifier);
    const state = randomToken();
    const nonce = randomToken();

    req.session.pending = { state, nonce, codeVerifier, createdAt: Date.now() };
    const authorizeUrl = buildAuthorizeUrl(metadata, { state, nonce, codeChallenge, loginHint });

    trace(req, 'Discovery', {
      discovery_url: discoveryUrl,
      issuer: metadata.issuer,
      authorization_endpoint: metadata.authorization_endpoint,
      token_endpoint: metadata.token_endpoint,
      code_challenge_methods_supported: (metadata.code_challenge_methods_supported ?? []).join(', ') || '(not advertised)',
    });
    trace(req, 'PKCE values generated', {
      code_verifier: `${codeVerifier} (${codeVerifier.length} chars, kept server-side until the token exchange)`,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    trace(req, 'Redirect to authorization endpoint', { url: authorizeUrl.toString() });

    req.session.save((err) => (err ? next(err) : res.redirect(authorizeUrl.toString())));
  } catch (err) {
    next(err);
  }
}

app.post('/login', (req, res, next) => startLogin(req, res, next, { loginHint: req.body.login_hint?.trim() || undefined }));

// Switching user needs the IAM SSO session gone first: with an SSO session alive,
// IAM treats a new login as re-authentication of the *current* user and checks the
// typed password against that user, so a different user's password is "invalid".
// Log out at IAM, come back to / with our state, then start a fresh login.
app.post('/switch-user', async (req, res, next) => {
  try {
    const { metadata } = await discover();
    const idToken = req.session.auth?.tokens?.id_token;
    const state = randomToken();
    req.session.switchUser = {
      state,
      loginHint: req.body.login_hint?.trim() || undefined,
      previousUser: req.session.auth?.idClaims?.preferred_username,
    };
    delete req.session.auth;
    delete req.session.probe;
    const logoutUrl = buildLogoutUrl(metadata, idToken, state);
    if (!logoutUrl) throw new Error('IAM does not advertise an end_session_endpoint, so the SSO session cannot be ended.');
    trace(req, 'Switch user: redirect to IAM logout', { url: logoutUrl.toString().replace(/id_token_hint=[^&]+/, 'id_token_hint=…') });
    req.session.save((err) => (err ? next(err) : res.redirect(logoutUrl.toString())));
  } catch (err) {
    next(err);
  }
});

// Step 2: IFS IAM redirects back with ?code&state. Exchange the code + verifier for tokens.
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription, session_state: sessionState } = req.query;
  const pending = req.session.pending;
  delete req.session.pending;

  trace(req, 'Callback received', {
    code: shorten(code),
    state,
    session_state: sessionState,
    error,
    error_description: errorDescription,
  });

  try {
    if (error) throw new Error(`IAM returned an error: ${error}${errorDescription ? ` (${errorDescription})` : ''}`);
    if (!pending) throw new Error('No login in progress for this browser session (expired, or callback replayed).');
    if (Date.now() - pending.createdAt > PENDING_LOGIN_TTL_MS) throw new Error('Login transaction expired; start again.');
    if (!state || state !== pending.state) throw new Error('State mismatch: the callback does not belong to the login this session started.');
    if (!code) throw new Error('Callback did not include an authorization code.');

    const { metadata } = await discover();
    const tokenResponse = await exchangeCode(metadata, { code, codeVerifier: pending.codeVerifier });
    trace(req, 'Token exchange (code + code_verifier)', {
      token_endpoint: metadata.token_endpoint,
      grant_type: 'authorization_code',
      client_authentication: config.clientSecret ? 'client_secret_post (confidential client)' : 'none (public client, PKCE only)',
      ...tokenSummary(tokenResponse),
    });

    if (!tokenResponse.id_token) throw new Error('Token response has no id_token; make sure the scope includes "openid".');
    const { payload: idClaims, protectedHeader } = await validateIdToken(metadata, tokenResponse.id_token, pending.nonce);
    trace(req, 'ID token validated', {
      alg: protectedHeader.alg,
      kid: protectedHeader.kid,
      iss: idClaims.iss,
      aud: Array.isArray(idClaims.aud) ? idClaims.aud.join(', ') : idClaims.aud,
      sub: idClaims.sub,
      preferred_username: idClaims.preferred_username,
      nonce: 'matches',
    });

    // New identity: rotate the session id (avoids fixation) but keep the trace
    // and the call history, so calls made as different users can be compared.
    const { trace: keptTrace, history: keptHistory } = req.session;
    req.session.regenerate((err) => {
      if (err) return res.status(500).send(`Could not start session: ${err.message}`);
      req.session.trace = keptTrace;
      req.session.history = keptHistory;
      storeTokens(req, tokenResponse);
      req.session.auth.idClaims = idClaims;
      req.session.auth.signedInAt = new Date().toISOString();
      req.session.save(() => res.redirect('/'));
    });
  } catch (err) {
    trace(req, 'Login failed', { error: err.message });
    flash(req, 'login', err.message);
    req.session.save(() => res.redirect('/'));
  }
});

app.post('/refresh', async (req, res) => {
  const refreshToken = req.session.auth?.tokens?.refresh_token;
  try {
    if (!refreshToken) throw new Error('No refresh token in this session.');
    const { metadata } = await discover();
    const previousSub = req.session.auth.idClaims?.sub;
    const tokenResponse = await refreshTokens(metadata, refreshToken);
    if (tokenResponse.id_token) {
      const { payload } = await validateIdToken(metadata, tokenResponse.id_token);
      // Renewal may change the token, never the identity.
      if (payload.sub !== previousSub) throw new Error(`Refresh returned a different subject (${payload.sub}); discarding.`);
      req.session.auth.idClaims = payload;
    }
    storeTokens(req, tokenResponse);
    trace(req, 'Token refreshed', {
      refresh_token_rotated: Boolean(tokenResponse.refresh_token && tokenResponse.refresh_token !== refreshToken),
      ...tokenSummary(tokenResponse),
    });
  } catch (err) {
    trace(req, 'Refresh failed', { error: err.message });
    flash(req, 'session', err.message);
  }
  req.session.save(() => res.redirect('/'));
});

// Call an IFS API with the access token to see what this user is actually allowed to do.
app.post('/probe', async (req, res) => {
  const accessToken = req.session.auth?.tokens?.access_token;
  const path = (req.body.path ?? '').trim();
  try {
    if (!accessToken) throw new Error('Sign in first.');
    if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Enter a path relative to IFS_URL, starting with "/".');
    const target = new URL(path, `${config.ifsUrl}/`);
    // Never send the bearer token anywhere but the configured IFS origin.
    if (target.origin !== new URL(config.ifsUrl).origin) throw new Error('Path resolves outside IFS_URL.');

    const started = Date.now();
    const apiRes = await fetch(target, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      redirect: 'manual',
    });
    const body = await apiRes.text();
    req.session.probe = {
      path,
      url: target.toString(),
      status: apiRes.status,
      statusText: apiRes.statusText,
      ms: Date.now() - started,
      user: req.session.auth.idClaims?.preferred_username,
      contentType: apiRes.headers.get('content-type'),
      body: body.length > 6000 ? `${body.slice(0, 6000)}\n… (${body.length} chars total, truncated)` : body,
    };
    req.session.history = [
      ...(req.session.history ?? []),
      { at: new Date().toISOString(), user: req.session.probe.user, path, status: apiRes.status, statusText: apiRes.statusText, ms: req.session.probe.ms },
    ].slice(-MAX_HISTORY_ENTRIES);
    trace(req, 'IFS API call', { url: target.toString(), status: `${apiRes.status} ${apiRes.statusText}` });
  } catch (err) {
    req.session.probe = { path, error: err.message };
  }
  req.session.save(() => res.redirect('/#probe'));
});

// RP-initiated logout: end the IFS IAM SSO session too, not just ours.
app.post('/logout', async (req, res, next) => {
  try {
    const idToken = req.session.auth?.tokens?.id_token;
    const { metadata } = await discover();
    const logoutUrl = buildLogoutUrl(metadata, idToken);
    req.session.destroy(() => res.redirect(logoutUrl ? logoutUrl.toString() : '/'));
  } catch (err) {
    next(err);
  }
});

app.post('/logout-local', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.post('/clear-history', (req, res) => {
  req.session.history = [];
  req.session.save(() => res.redirect('/'));
});

app.post('/clear-trace', (req, res) => {
  req.session.trace = [];
  req.session.save(() => res.redirect('/#trace'));
});

app.use((err, req, res, _next) => {
  console.error(err);
  if (req.session) {
    flash(req, req.session.auth ? 'session' : 'login', err.message);
    return req.session.save(() => res.redirect('/'));
  }
  res.status(500).send('Internal error');
});

