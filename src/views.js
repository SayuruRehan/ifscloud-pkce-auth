const esc = (value) =>
  String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const CLAIM_TIMES = new Set(['exp', 'iat', 'nbf', 'auth_time']);

function formatClaim(key, value) {
  if (CLAIM_TIMES.has(key) && typeof value === 'number') {
    return `${value}  (${new Date(value * 1000).toISOString()})`;
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function kvTable(obj) {
  const rows = Object.entries(obj ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!rows.length) return '<p class="muted">None</p>';
  return `<table class="kv">${rows
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td><code>${esc(formatClaim(k, v))}</code></td></tr>`)
    .join('')}</table>`;
}

function remaining(expiresAt) {
  if (!expiresAt) return 'unknown';
  const seconds = Math.round((expiresAt - Date.now()) / 1000);
  if (seconds <= 0) return 'expired';
  return seconds >= 120 ? `${Math.floor(seconds / 60)} min` : `${seconds} s`;
}

function renderConfig(config, discovery) {
  const m = discovery?.metadata;
  return `
  <section>
    <h2>Configuration</h2>
    ${kvTable({
      IFS_URL: config.ifsUrl,
      Realm: config.realm,
      Issuer: m?.issuer ?? config.issuer,
      'Client ID': config.clientId,
      'Client type': config.clientSecret ? 'confidential (secret + PKCE)' : 'public (PKCE only)',
      Scope: config.scope,
      'Redirect URI': config.redirectUri,
      'Authorization endpoint': m?.authorization_endpoint,
      'Token endpoint': m?.token_endpoint,
      'End-session endpoint': m?.end_session_endpoint,
      'PKCE methods advertised': m?.code_challenge_methods_supported?.join(', '),
    })}
    ${m && m.issuer !== config.issuer ? `<p class="warn">Discovered issuer differs from the configured one. Tokens are validated against the discovered issuer.</p>` : ''}
  </section>`;
}

function renderSignIn() {
  return `
  <section>
    <h2>Sign in to IFS Cloud</h2>
    <form method="post" action="/login" class="stack">
      <label>Login hint (optional IFS user id)
        <input name="login_hint" placeholder="e.g. ALAIN" autocomplete="off">
      </label>
      <button type="submit">Sign in with PKCE</button>
    </form>
    <p class="muted">If IFS signs you straight back in as the wrong user, it still has an IAM session from earlier.</p>
    <form method="post" action="/switch-user" class="row">
      <button type="submit" class="secondary small">End the IFS session and sign in again</button>
    </form>
  </section>`;
}

function renderSession(auth, accessToken, config, probe) {
  const t = auth.tokens;
  const id = auth.idClaims ?? {};
  const at = accessToken?.claims ?? {};
  return `
  <section>
    <h2>Signed in as <span class="user">${esc(id.preferred_username ?? id.sub)}</span></h2>
    ${kvTable({
      'Signed in at': auth.signedInAt,
      'Access token expires in': remaining(t.expires_at),
      'Refresh token expires in': t.refresh_token ? remaining(t.refresh_expires_at) : 'no refresh token',
      'Granted scope': t.scope,
      'Access token signature': accessToken?.signature,
    })}
    <div class="row">
      <form method="post" action="/refresh"><button ${t.refresh_token ? '' : 'disabled'}>Refresh tokens</button></form>
      <form method="post" action="/switch-user" class="row">
        <input name="login_hint" placeholder="IFS user id (optional)" autocomplete="off" aria-label="IFS user id for the new login">
        <button class="secondary">Sign in as a different user</button>
      </form>
      <form method="post" action="/logout"><button class="secondary">Log out (IAM + local)</button></form>
      <form method="post" action="/logout-local"><button class="secondary">Forget tokens locally</button></form>
    </div>
  </section>

  <section class="grid">
    <div>
      <h3>ID token claims <span class="badge ok">validated</span></h3>
      <p class="muted">Who authenticated. Used by this app only, never sent to IFS APIs.</p>
      ${kvTable(id)}
    </div>
    <div>
      <h3>Access token claims</h3>
      <p class="muted">What IFS APIs receive as <code>Authorization: Bearer …</code>.</p>
      ${accessToken?.isJwt ? kvTable(at) : `<p>${esc(accessToken?.signature ?? '')}</p>`}
      <details><summary>Raw access token (for Postman etc. — treat as a password)</summary>
        <textarea readonly rows="6">${esc(t.access_token)}</textarea>
      </details>
    </div>
  </section>

  ${renderProbe(config, probe)}`;
}

function renderProbe(config, probe) {
  return `
  <section id="probe">
    <h2>Call an IFS API as this user</h2>
    <p class="muted">IFS enforces this user's permission sets. Sign in as different users and repeat the same call to compare 200 vs 403.</p>
    <form method="post" action="/probe" class="row">
      <span class="prefix">${esc(config.ifsUrl)}</span>
      <input name="path" class="grow" value="${esc(probe?.path || config.apiProbePath)}"
        placeholder="/main/ifsapplications/projection/v1/&lt;Projection&gt;.svc/&lt;EntitySet&gt;?$top=1">
      <button type="submit">Send GET</button>
    </form>
  </section>`;
}

function renderProbeResult(probe) {
  if (!probe) return '';
  if (probe.error) return `<section><p class="error">${esc(probe.error)}</p></section>`;
  const cls = probe.status < 300 ? 'ok' : probe.status === 401 || probe.status === 403 ? 'deny' : 'warn';
  return `
  <section>
    <h3>Last API call <span class="badge ${cls}">${esc(probe.status)} ${esc(probe.statusText)}</span></h3>
    ${kvTable({ 'Called as': probe.user, URL: probe.url, 'Content-Type': probe.contentType, Duration: `${probe.ms} ms` })}
    <pre>${esc(prettyJson(probe.body))}</pre>
  </section>`;
}

function prettyJson(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function renderTrace(trace) {
  return `
  <section>
    <div class="row between">
      <h2>Flow trace</h2>
      <form method="post" action="/clear-trace"><button class="secondary small">Clear</button></form>
    </div>
    ${
      trace.length
        ? `<ol class="trace">${trace
            .map(
              (e) => `<li><div class="row between"><strong>${esc(e.step)}</strong><span class="muted">${esc(e.at)}</span></div>
              ${kvTable(e.details)}</li>`,
            )
            .join('')}</ol>`
        : '<p class="muted">Each step of the PKCE flow appears here once you sign in.</p>'
    }
  </section>`;
}

export function renderHome({ config, discovery, auth, accessToken, trace, probe, error }) {
  const signedIn = Boolean(auth?.tokens?.access_token);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IFS Cloud PKCE Demo</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --fg:#1c2330; --muted:#677184; --line:#e1e4ea; --accent:#5b3cc4;
          --ok:#1f7a4d; --deny:#b3261e; --warn:#9a6700; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151b; --card:#1b1f27; --fg:#e6e9ef; --muted:#9aa3b2; --line:#2c323d; --accent:#a48cff;
            --ok:#5ccf95; --deny:#ff8a80; --warn:#e3b341; }
  }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
  header h1 { margin:0 0 4px; font-size:22px; }
  section { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 20px; margin-top:16px; }
  h2 { font-size:17px; margin:0 0 12px; } h3 { font-size:15px; margin:0 0 6px; }
  .muted { color:var(--muted); margin-top:0; }
  .user { color:var(--accent); }
  table.kv { border-collapse:collapse; width:100%; font-size:13px; }
  table.kv th { text-align:left; vertical-align:top; padding:4px 12px 4px 0; width:220px; color:var(--muted); font-weight:500; white-space:nowrap; }
  table.kv td { padding:4px 0; word-break:break-all; }
  code, pre, textarea { font:12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; max-height:420px; }
  textarea { width:100%; background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:8px; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .row.between { justify-content:space-between; }
  .stack { display:grid; gap:12px; max-width:560px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:24px; }
  .grow { flex:1; min-width:240px; }
  .prefix { color:var(--muted); font-size:13px; }
  label { display:grid; gap:4px; font-size:14px; }
  input:not([type=checkbox]) { padding:8px 10px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); font:inherit; }
  button { padding:8px 14px; border-radius:6px; border:1px solid var(--accent); background:var(--accent); color:#fff; font:inherit; cursor:pointer; }
  button.secondary { background:transparent; color:var(--accent); }
  button.small { padding:4px 10px; font-size:13px; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .badge { font-size:12px; padding:2px 8px; border-radius:999px; border:1px solid currentColor; font-weight:500; }
  .ok { color:var(--ok); } .deny { color:var(--deny); } .warn { color:var(--warn); }
  .error { color:var(--deny); font-weight:500; margin:0; }
  ol.trace { padding-left:20px; margin:0; } ol.trace li { padding:8px 0; border-top:1px solid var(--line); }
  details { margin-top:8px; } summary { cursor:pointer; color:var(--muted); font-size:13px; }
  @media (max-width:600px) { table.kv th { width:auto; white-space:normal; } }
</style>
</head>
<body>
<main>
  <header>
    <h1>IFS Cloud · Authorization Code + PKCE</h1>
    <p class="muted">Proof of concept for running Mahara tests as a real IFS user.</p>
  </header>
  ${error ? `<section><p class="error">${esc(error)}</p></section>` : ''}
  ${signedIn ? renderSession(auth, accessToken, config, probe) + renderProbeResult(probe) : renderSignIn()}
  ${renderTrace(trace)}
  ${renderConfig(config, discovery)}
</main>
</body>
</html>`;
}
