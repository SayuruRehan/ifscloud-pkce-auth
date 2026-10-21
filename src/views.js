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
    return `${value} (${new Date(value * 1000).toISOString().replace('.000Z', 'Z')})`;
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

const clock = (iso) => new Date(iso).toLocaleTimeString('en-GB', { hour12: false });

function duration(seconds) {
  if (seconds === undefined || seconds === null) return '—';
  if (seconds <= 0) return 'expired';
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m ? `${m} min ${s} s` : `${s} s`;
}

// A stable pale hue per IFS user, in 60° steps so neighbours read apart.
function hueFor(name = '') {
  let h = 0;
  for (const ch of name.toLowerCase()) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return (h % 6) * 60 + 20;
}

function avatar(name) {
  const label = name || '?';
  return `<span class="avatar" style="--h:${hueFor(label)}" aria-hidden="true">${esc(label.slice(0, 1).toUpperCase())}</span>`;
}

function statusPill(status, statusText) {
  const kind = status < 300 ? 'ok' : status === 401 || status === 403 ? 'deny' : 'warn';
  return `<span class="pill ${kind}" data-status="${esc(status)}">${esc(status)} ${esc(statusText)}</span>`;
}

// The part of an IFS projection path people recognise: Projection.svc/EntitySet.
function shortPath(path) {
  const match = path.match(/projection\/v\d+\/([^?]+)/);
  return match ? match[1] : path;
}

function kvRows(obj, { mono = true } = {}) {
  const rows = Object.entries(obj ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!rows.length) return '<p class="empty">Nothing recorded.</p>';
  return `<dl class="kv">${rows
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="${mono ? 'mono' : ''}">${esc(formatClaim(k, v))}</dd></div>`)
    .join('')}</dl>`;
}

function notice(message) {
  if (!message) return '';
  return `<p class="notice" role="alert"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M8 4.5v4.2M8 11v.5"/></svg><span>${esc(message)}</span></p>`;
}

const MARK = `<svg class="mark" viewBox="0 0 24 24" aria-hidden="true"><circle cx="8.5" cy="12" r="5"/><path d="M13.5 12H22M18.5 12v3.5M21.5 12v2.5"/><circle cx="8.5" cy="12" r="1.6" class="dot"/></svg>`;

function topBar(config, user) {
  const host = new URL(config.ifsUrl).host;
  return `
  <header class="bar">
    <div class="bar-inner">
      <div class="brand">${MARK}<span class="name">Mahara sign-in lab</span>
        <span class="scope"><span class="sep">/</span>${esc(host)}<span class="sep">/</span>${esc(config.realm)}</span>
      </div>
      <div class="who">
        ${
          user
            ? `${avatar(user)}<span class="who-name">${esc(user)}</span>
               <form method="post" action="/logout"><button class="btn ghost" title="Ends the IFS IAM session as well">Log out</button></form>`
            : '<span class="muted">Not signed in</span>'
        }
      </div>
    </div>
  </header>`;
}

// Endpoints all live under the issuer; show only the part that differs.
function underIssuer(url, issuer) {
  return url && issuer && url.startsWith(issuer) ? `…${url.slice(issuer.length)}` : url;
}

function environmentCard(config, discovery, discoveryError) {
  const m = discovery?.metadata;
  const issuer = m?.issuer ?? config.issuer;
  return `
  <section class="card" aria-labelledby="env-h">
    <div class="card-head"><h2 id="env-h">Environment</h2><span class="meta">from .env and IAM discovery</span></div>
    ${discoveryError ? notice(`Couldn't read the IAM discovery document. ${discoveryError}`) : ''}
    ${kvRows({
      'IFS URL': config.ifsUrl,
      Issuer: issuer,
      'Client ID': config.clientId,
      'Client type': config.clientSecret ? 'confidential, secret + PKCE' : 'public, PKCE only',
      Scope: config.scope,
      'Redirect URI': config.redirectUri,
      'Authorize endpoint': underIssuer(m?.authorization_endpoint, issuer),
      'Token endpoint': underIssuer(m?.token_endpoint, issuer),
      'Logout endpoint': underIssuer(m?.end_session_endpoint, issuer),
      'PKCE methods': m?.code_challenge_methods_supported?.join(', '),
    })}
    ${m && m.issuer !== config.issuer ? `<p class="hint">The discovered issuer differs from the configured one; tokens are checked against the discovered issuer.</p>` : ''}
  </section>`;
}

function signInCard(flash) {
  return `
  <section class="card main" aria-labelledby="signin-h">
    <div class="card-head"><h2 id="signin-h">Sign in with IFS IAM</h2><span class="meta">Authorization code + PKCE</span></div>
    ${flash?.scope === 'login' ? notice(flash.message) : ''}
    <form method="post" action="/login" class="field-stack">
      <label for="login_hint">IFS user id <span class="muted">(optional)</span></label>
      <input id="login_hint" name="login_hint" autocomplete="off" spellcheck="false">
      <p class="hint">Fills in the username on the IFS login page.</p>
      <div><button class="btn primary" type="submit">Sign in with IFS</button></div>
    </form>
    <div class="next">
      <h3>What happens when you sign in</h3>
      <ol>
        <li>This app creates a one-time code verifier and sends only its SHA-256 hash (the code challenge) to IFS IAM.</li>
        <li>You sign in on the IFS login page. The app never sees the password.</li>
        <li>IFS sends back a one-time code. The app exchanges it, with the verifier, for that user's tokens.</li>
        <li>Every API call you send from here carries that user's access token, so IFS applies their permission sets.</li>
      </ol>
    </div>
    <div class="aside-row">
      <div>
        <h3>Signed straight back in as the wrong user?</h3>
        <p class="hint">IFS IAM still has a session from earlier. End it, then sign in again.</p>
      </div>
      <form method="post" action="/switch-user"><button class="btn" type="submit">End the IFS session</button></form>
    </div>
  </section>`;
}

function probeCard(config, probe, user) {
  let result;
  if (probe?.error) {
    result = notice(`Couldn't send the request. ${probe.error}`);
  } else if (probe) {
    result = `
    <div class="result">
      <div class="result-head">
        ${statusPill(probe.status, probe.statusText)}
        <span class="num">${esc(probe.ms)}<span class="unit"> ms</span></span>
        <span class="muted">${esc(probe.contentType ?? 'no content type')}</span>
      </div>
      <p class="mono small url">${esc(probe.url)}</p>
      <pre>${esc(prettyJson(probe.body) || '(empty body)')}</pre>
    </div>`;
  } else {
    result = `<p class="empty-frame">No call yet. Send a GET to see whether IFS lets ${esc(user)} read it.</p>`;
  }
  return `
  <section class="card main" id="probe" aria-labelledby="probe-h">
    <div class="card-head"><h2 id="probe-h">Call IFS as ${esc(user)}</h2><span class="meta">GET with the access token</span></div>
    <form method="post" action="/probe" class="field-stack">
      <label for="path">Projection path</label>
      <div class="joined">
        <span class="addon">${esc(new URL(config.ifsUrl).host)}</span>
        <input id="path" name="path" spellcheck="false" autocomplete="off" class="mono"
          value="${esc(probe?.path || config.apiProbePath)}"
          placeholder="/main/ifsapplications/projection/v1/Projection.svc/EntitySet?$top=1">
        <button class="btn primary" type="submit">Send GET</button>
      </div>
    </form>
    ${result}
  </section>`;
}

function lifetime(label, expiresAt, lifetimeS, { main } = {}) {
  if (!expiresAt) {
    return `<div class="life"><div class="life-head"><span class="label">${esc(label)}</span><span class="value muted">—</span></div><p class="hint">Not issued</p></div>`;
  }
  const left = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  const ratio = lifetimeS ? Math.min(1, left / lifetimeS) : 0;
  return `
  <div class="life" data-expires="${expiresAt}" data-lifetime="${lifetimeS ?? ''}">
    <div class="life-head"><span class="label">${esc(label)}</span><span class="value num" data-left>${esc(duration(left))}</span></div>
    <div class="track${main ? ' main' : ''}"><span style="width:${(ratio * 100).toFixed(1)}%"></span></div>
    <div class="ends num"><span>0</span><span>${esc(duration(lifetimeS))} lifetime</span></div>
  </div>`;
}

function sessionCard(auth, accessToken, flash) {
  const t = auth.tokens;
  const id = auth.idClaims ?? {};
  const sig = accessToken?.signature ?? 'not checked';
  const sigPill = sig.startsWith('valid')
    ? '<span class="pill ok" data-signature="valid">Valid</span>'
    : `<span class="pill deny" data-signature="invalid">${esc(sig)}</span>`;
  return `
  <section class="card" aria-labelledby="session-h">
    <div class="card-head"><h2 id="session-h">Session</h2><span class="meta num">signed in ${esc(clock(auth.signedInAt))}</span></div>
    ${flash?.scope === 'session' ? notice(flash.message) : ''}
    <div class="lives">
      ${lifetime('Access token', t.expires_at, t.expires_in, { main: true })}
      ${lifetime('Refresh token', t.refresh_token ? t.refresh_expires_at : undefined, t.refresh_expires_in)}
    </div>
    <dl class="kv">
      <div><dt>Subject</dt><dd class="mono" title="${esc(id.sub)}">${esc(id.sub)}</dd></div>
      <div><dt>Issuer</dt><dd class="mono">${esc(id.iss)}</dd></div>
      <div><dt>Scope</dt><dd class="mono">${esc(t.scope)}</dd></div>
      <div><dt>Access token signature</dt><dd>${sigPill}</dd></div>
    </dl>
    <div class="actions">
      <form method="post" action="/refresh"><button class="btn" ${t.refresh_token ? '' : 'disabled title="IAM issued no refresh token"'}>Refresh tokens</button></form>
      <form method="post" action="/logout-local"><button class="btn text">Forget tokens locally</button></form>
    </div>
  </section>`;
}

function historyCard(history) {
  const shown = history.slice(-8).reverse();
  const byUser = new Map();
  for (const h of history) {
    const u = byUser.get(h.user) ?? { allowed: 0, denied: 0 };
    if (h.status < 300) u.allowed += 1;
    else u.denied += 1;
    byUser.set(h.user, u);
  }
  const summary = [...byUser]
    .map(([user, c]) => `<span class="nowrap">${esc(user)} ${c.allowed} allowed · ${c.denied} refused</span>`)
    .join('');
  return `
  <section class="card calls" aria-labelledby="calls-h">
    <div class="card-head">
      <h2 id="calls-h">Calls by user</h2>
      ${history.length ? '<form method="post" action="/clear-history"><button class="btn text small">Clear</button></form>' : ''}
    </div>
    ${
      history.length
        ? `<p class="summary">${summary}</p>
      <div class="table-wrap"><table>
        <thead><tr><th>User</th><th class="path">Request</th><th>Result</th><th class="num">Time</th><th class="num">At</th></tr></thead>
        <tbody>${shown
          .map(
            (h) => `<tr>
              <td><span class="person">${avatar(h.user)}<span>${esc(h.user)}<span class="mono small path-sub">${esc(shortPath(h.path))}</span></span></span></td>
              <td class="mono small path" title="${esc(h.path)}">${esc(shortPath(h.path))}</td>
              <td>${statusPill(h.status, h.statusText)}</td>
              <td class="num">${esc(h.ms)}<span class="unit"> ms</span></td>
              <td class="num muted">${esc(clock(h.at))}</td>
            </tr>`,
          )
          .join('')}</tbody>
      </table></div>
      <p class="hint">${history.length > shown.length ? `Latest ${shown.length} of ${history.length} calls.` : `${history.length} ${history.length === 1 ? 'call' : 'calls'}.`} Kept when you switch user.</p>`
        : '<p class="empty-frame">No calls yet. Every GET is listed here with the user who sent it, so you can compare what each user is allowed to read.</p>'
    }
  </section>`;
}

function claimsCard(auth, accessToken) {
  const at = accessToken?.claims;
  return `
  <section class="card" aria-labelledby="claims-h">
    <div class="card-head"><h2 id="claims-h">ID token claims</h2><span class="pill ok">Validated</span></div>
    <p class="hint">Who signed in. Used by this app only; never sent to IFS APIs.</p>
    ${kvRows(auth.idClaims)}
    <details>
      <summary>Access token claims${at ? ` (${Object.keys(at).length})` : ''}</summary>
      ${at ? kvRows(at) : `<p class="hint">${esc(accessToken?.signature ?? 'Not a JWT')}</p>`}
    </details>
    <details>
      <summary>Raw access token</summary>
      <p class="hint">Treat it like a password. Useful for trying the same call in Postman.</p>
      <textarea readonly rows="5" class="mono" aria-label="Raw access token">${esc(auth.tokens.access_token)}</textarea>
    </details>
  </section>`;
}

function gist(details) {
  return details.error ?? details.status ?? (details.preferred_username ? `user ${details.preferred_username}` : undefined) ?? details.previous_user ?? details.url ?? details.issuer ?? '';
}

function traceStep(e, open) {
  return `<li${e.step.includes('failed') ? ' class="failed"' : ''}><details${open ? ' open' : ''}>
    <summary><span class="num muted">${esc(clock(e.at))}</span><span class="step">${esc(e.step)}</span><span class="gist mono small">${esc(gist(e.details))}</span></summary>
    ${kvRows(e.details)}
  </details></li>`;
}

function traceCard(trace) {
  // Each sign-in starts with Discovery; older sign-ins fold into one row.
  const lastStart = trace.findLastIndex((e) => e.step === 'Discovery');
  const split = lastStart > 0 ? lastStart : 0;
  const earlier = trace.slice(0, split);
  const latest = trace.slice(split);
  return `
  <section class="card" id="trace" aria-labelledby="trace-h">
    <div class="card-head">
      <h2 id="trace-h">Flow trace</h2>
      ${trace.length ? '<form method="post" action="/clear-trace"><button class="btn text small">Clear</button></form>' : ''}
    </div>
    ${
      trace.length
        ? `<p class="hint">Each step of the sign-in, oldest first. Open a step to see exactly what was sent and received.</p>
      <ol class="trace">
        ${earlier.length ? `<li class="earlier"><details><summary><span class="num muted">${esc(clock(earlier[0].at))}</span><span class="step">Earlier steps</span><span class="gist small">${earlier.length} steps before the latest sign-in</span></summary><ol class="trace">${earlier.map((e) => traceStep(e, false)).join('')}</ol></details></li>` : ''}
        ${latest.map((e, i) => traceStep(e, i === latest.length - 1)).join('')}
      </ol>`
        : '<p class="empty-frame">Nothing yet. Each step of the PKCE flow is recorded here once you sign in.</p>'
    }
  </section>`;
}

function prettyJson(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function findingLine(probe, user, auth) {
  if (probe && !probe.error) {
    return `Last call as ${esc(user)}: ${esc(shortPath(probe.path))} returned ${esc(probe.status)} ${esc(probe.statusText)}.`;
  }
  const left = Math.max(0, Math.round((auth.tokens.expires_at - Date.now()) / 1000));
  return `Access token valid for ${esc(duration(left))}. Call an IFS API below to see what this user can do.`;
}

export function renderHome({ config, discovery, auth, accessToken, trace, probe, history, flash, discoveryError }) {
  const signedIn = Boolean(auth?.tokens?.access_token);
  const user = signedIn ? auth.idClaims?.preferred_username ?? auth.idClaims?.sub : undefined;

  const body = signedIn
    ? `
    <div class="title-row">
      <div><h1>Signed in as <span class="user">${esc(user)}</span></h1>
        <p class="sub">${findingLine(probe, user, auth)}</p></div>
      <form method="post" action="/switch-user" class="switch">
        <label for="switch_hint" class="sr-only">IFS user id for the next sign-in</label>
        <input id="switch_hint" name="login_hint" placeholder="IFS user id" autocomplete="off" spellcheck="false">
        <button class="btn" type="submit">Switch user</button>
      </form>
    </div>
    <div class="grid">
      <div class="col">${probeCard(config, probe, user)}${historyCard(history)}</div>
      <div class="col">${sessionCard(auth, accessToken, flash)}${claimsCard(auth, accessToken)}</div>
    </div>
    ${traceCard(trace)}
    ${environmentCard(config, discovery, discoveryError)}`
    : `
    <div class="title-row">
      <div><h1>Sign in to IFS Cloud</h1>
        <p class="sub">Sign in as a real IFS user, then call IFS APIs with that user's own permissions.</p></div>
    </div>
    <div class="grid">
      ${signInCard(flash?.scope === 'login' || flash?.scope === 'session' ? { ...flash, scope: 'login' } : flash)}
      ${environmentCard(config, discovery, discoveryError)}
    </div>
    ${history.length ? historyCard(history) : ''}
    ${traceCard(trace)}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mahara sign-in lab</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Public+Sans:wght@400;500;600&display=swap">
<style>${CSS}</style>
</head>
<body>
${topBar(config, user)}
<main>${body}</main>
<script>${COUNTDOWN}</script>
</body>
</html>`;
}

// Ticks the token countdowns; the server-rendered values stand if scripts are off.
const COUNTDOWN = `
(function () {
  var lives = document.querySelectorAll('[data-expires]');
  if (!lives.length) return;
  function fmt(s) { if (s <= 0) return 'expired'; var m = Math.floor(s / 60); return m ? m + ' min ' + (s % 60) + ' s' : s + ' s'; }
  function tick() {
    lives.forEach(function (el) {
      var left = Math.max(0, Math.round((Number(el.dataset.expires) - Date.now()) / 1000));
      var total = Number(el.dataset.lifetime);
      el.querySelector('[data-left]').textContent = fmt(left);
      var bar = el.querySelector('.track span');
      if (bar && total) bar.style.width = Math.min(100, (left / total) * 100).toFixed(1) + '%';
      el.classList.toggle('expired', left === 0);
    });
  }
  setInterval(tick, 1000);
})();`;

/* Layout: no-sidebar shell. A 52px top bar over one centred 1200px column; a 12-column
   grid with one 16px gap. Cards pair 7 + 5 columns: 7/12 and 5/12 of (1200 - 2*24 padding
   - 16 gap) = 664 + 472 + 16 = 1152, so every row lands on both canvas edges. */
const CSS = `
:root {
  --ground: #f3f5f4; --surface: #ffffff; --raised: #f7f8f8; --active: #eceeed;
  --border: #e1e6e4; --rule: #edf0ef; --control: #cbd2cf;
  --text: #131817; --muted: #58615e; --faint: #67706d;
  --primary: #17201e; --on-primary: #ffffff;
  --accent: #0b7d76;
  --pill-ok-bg: #dcf7e8; --pill-ok-ink: #0b3b24;
  --pill-deny-bg: #ffe9e6; --pill-deny-ink: #861d1d;
  --pill-warn-bg: #fff6dd; --pill-warn-ink: #7a4a05;
  --negative: #b42323;
  --av-s: 62%; --av-l: 90%; --av-ink-l: 26%;
  --radius-card: 8px; --radius-control: 6px; --radius-chip: 4px;
  --gap: 16px; --pad: 20px;
  --font: "Public Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0d100f; --surface: #141817; --raised: #1a1f1e; --active: #222826;
    --border: #252c2a; --rule: #1d2321; --control: #414a47;
    --text: #edf1f0; --muted: #b2bbb8; --faint: #949d9a;
    --primary: #eef2f1; --on-primary: #0d100f;
    --accent: #3cc4b8;
    --pill-ok-bg: #15291e; --pill-ok-ink: #5fd496;
    --pill-deny-bg: #2e1919; --pill-deny-ink: #ff8f86;
    --pill-warn-bg: #2b2210; --pill-warn-ink: #eebc5c;
    --negative: #ff8f86;
    --av-s: 30%; --av-l: 24%; --av-ink-l: 82%;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--ground); color: var(--text); font: 14px/20px var(--font); }
h1, h2, h3 { margin: 0; text-wrap: balance; }
h1 { font-size: 24px; line-height: 32px; font-weight: 600; letter-spacing: -0.01em; }
h2 { font-size: 16px; line-height: 24px; font-weight: 600; }
h3 { font-size: 14px; font-weight: 600; }
p { margin: 0; }
.mono { font-family: var(--mono); font-size: 13px; }
.small { font-size: 12px; }
.num { font-variant-numeric: tabular-nums; }
.unit { color: var(--muted); font-size: 12px; }
.muted { color: var(--muted); }
.hint { color: var(--muted); font-size: 13px; }
.nowrap { white-space: nowrap; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* shell */
.bar { background: var(--surface); border-bottom: 1px solid var(--border); }
.bar-inner, main { max-width: 1200px; margin: 0 auto; padding-left: 24px; padding-right: 24px; }
.bar-inner { height: 52px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.mark { width: 22px; height: 22px; flex: none; fill: none; stroke: var(--accent); stroke-width: 2; stroke-linecap: round; }
.mark .dot { fill: var(--accent); stroke: none; }
.name { font-weight: 600; white-space: nowrap; }
.scope { color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sep { color: var(--control); margin: 0 8px; }
.who { display: flex; align-items: center; gap: 10px; flex: none; }
.who form { margin: 0; }
.avatar { --h: 160; width: 24px; height: 24px; flex: none; border-radius: 50%; display: inline-grid; place-items: center;
  font-size: 12px; font-weight: 600; background: hsl(var(--h) var(--av-s) var(--av-l)); color: hsl(var(--h) 45% var(--av-ink-l)); }

/* canvas */
main { padding-block: 28px 64px; display: grid; gap: var(--gap); }
.title-row { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding-bottom: 8px; }
.title-row > div { display: grid; gap: 4px; min-width: 0; }
.user { color: var(--accent); }
.sub { color: var(--muted); font-size: 15px; line-height: 22px; max-width: 72ch; }
.switch { display: flex; gap: 8px; }
.switch input { width: 160px; }
.grid { display: grid; grid-template-columns: minmax(0, 7fr) minmax(0, 5fr); gap: var(--gap); align-items: stretch; }
/* Two stacked cards per column. On the left the API call grows (its response pane takes the
   extra height) and the calls table keeps its own height; on the right the claims card grows. */
.col { display: flex; flex-direction: column; gap: var(--gap); min-width: 0; }
.col > .card.main, .col > .card:last-child:not(.calls) { flex: 1; }
.col > .card.main pre { max-height: none; }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-card); padding: var(--pad);
  display: flex; flex-direction: column; gap: 14px; min-width: 0; }
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 28px; }
.card-head form { margin: 0; }
.meta { color: var(--muted); font-size: 12px; white-space: nowrap; }

/* controls */
input, textarea { font: inherit; color: var(--text); background: var(--surface); border: 1px solid var(--control);
  border-radius: var(--radius-control); height: 36px; padding: 0 12px; min-width: 0; }
input::placeholder { color: var(--faint); }
textarea { height: auto; padding: 10px 12px; width: 100%; resize: vertical; line-height: 18px; }
.btn { font: 500 14px/1 var(--font); height: 36px; padding: 0 14px; border-radius: var(--radius-control); cursor: pointer;
  border: 1px solid var(--control); background: var(--surface); color: var(--text); white-space: nowrap;
  transition: background-color .12s, border-color .12s, transform .06s; }
.btn:hover { background: var(--raised); border-color: var(--muted); }
.btn:active { transform: translateY(1px); }
.btn.primary { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
.btn.primary:hover { opacity: .9; }
.btn.ghost { border-color: transparent; background: transparent; height: 32px; padding: 0 10px; }
.btn.ghost:hover { background: var(--active); }
.btn.text { border: 0; background: transparent; padding: 0 4px; color: var(--muted); }
.btn.text:hover { color: var(--text); background: transparent; text-decoration: underline; }
.btn.small { height: 28px; font-size: 13px; }
.btn:disabled { cursor: not-allowed; color: var(--muted); background: var(--raised); border-color: var(--border); transform: none; }
.field-stack { display: grid; gap: 8px; margin: 0; }
.field-stack label { font-weight: 500; }
.joined { display: flex; min-width: 0; }
.joined .addon { display: flex; align-items: center; padding: 0 12px; border: 1px solid var(--control); border-right: 0;
  border-radius: var(--radius-control) 0 0 var(--radius-control); background: var(--raised); color: var(--muted); white-space: nowrap;
  max-width: 40%; overflow: hidden; text-overflow: ellipsis; }
.joined input { flex: 1; border-radius: 0; }
.joined .btn { border-radius: 0 var(--radius-control) var(--radius-control) 0; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: auto; }
.actions form { margin: 0; }
.aside-row { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap;
  border-top: 1px solid var(--rule); padding-top: 14px; margin-top: auto; }
.aside-row > div { display: grid; gap: 2px; }
.next { display: grid; gap: 8px; border-top: 1px solid var(--rule); padding-top: 14px; }
.next ol { margin: 0; padding-left: 20px; display: grid; gap: 6px; max-width: 64ch; }
.next li::marker { color: var(--muted); font-variant-numeric: tabular-nums; }

/* pills, notices, empty states */
.pill { flex: none; display: inline-flex; align-items: center; height: 22px; padding: 0 8px; border-radius: 999px;
  font-size: 12px; font-weight: 500; white-space: nowrap; font-variant-numeric: tabular-nums; }
.pill.ok { background: var(--pill-ok-bg); color: var(--pill-ok-ink); }
.pill.deny { background: var(--pill-deny-bg); color: var(--pill-deny-ink); }
.pill.warn { background: var(--pill-warn-bg); color: var(--pill-warn-ink); }
.notice { display: flex; gap: 8px; align-items: flex-start; color: var(--text); }
.notice svg { width: 16px; height: 16px; flex: none; margin-top: 2px; fill: none; stroke: var(--negative); stroke-width: 1.6; stroke-linecap: round; }
.empty-frame { border: 1px dashed var(--control); border-radius: var(--radius-card); padding: 14px 16px; color: var(--muted); }
.empty { color: var(--muted); }

/* probe result */
.result { display: flex; flex-direction: column; gap: 10px; flex: 1; min-height: 0; }
.result-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.url { color: var(--muted); overflow-wrap: anywhere; }
pre { margin: 0; flex: 1; min-height: 120px; max-height: 360px; overflow: auto; background: var(--raised); border: 1px solid var(--rule);
  border-radius: var(--radius-control); padding: 12px 14px; font: 12.5px/18px var(--mono); color: var(--text); }

/* token lifetimes: the screen's one hue sits on the access token */
.lives { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.life { display: grid; gap: 6px; }
.life-head { display: grid; gap: 2px; }
.label { color: var(--muted); font-size: 13px; }
.value { font-size: 20px; line-height: 28px; }
.track { height: 6px; border-radius: 999px; background: var(--active); overflow: hidden; }
.track span { display: block; height: 100%; border-radius: inherit; background: var(--muted); transition: width .9s linear; }
.track.main span { background: var(--accent); }
.life.expired .value { color: var(--negative); }
.ends { display: flex; justify-content: space-between; color: var(--muted); font-size: 12px; }

/* key-value rows */
.kv { margin: 0; display: grid; }
.kv > div { display: grid; grid-template-columns: minmax(110px, 34%) minmax(0, 1fr); gap: 12px; padding: 6px 0; border-top: 1px solid var(--rule); }
.kv > div:first-child { border-top: 0; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
details { border-top: 1px solid var(--rule); padding-top: 10px; }
details > summary { cursor: pointer; color: var(--text); font-weight: 500; list-style-position: inside; }
details > summary:hover { color: var(--accent); }
details[open] > summary { margin-bottom: 10px; }

/* calls table */
.summary { display: flex; flex-wrap: wrap; gap: 4px 16px; color: var(--muted); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th { text-align: left; font-weight: 400; color: var(--muted); font-size: 12px; padding: 0 10px 8px 0; white-space: nowrap; }
td { padding: 8px 10px 8px 0; border-top: 1px solid var(--rule); vertical-align: middle; height: 44px; }
th.num, td.num { text-align: right; padding-right: 0; padding-left: 10px; white-space: nowrap; }
tbody tr:hover td { background: var(--raised); }
.person { display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }
.path { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.path-sub { display: none; }

/* trace */
.trace { list-style: none; margin: 0; padding: 0; display: grid; }
.trace li { border-top: 1px solid var(--rule); }
.trace li:first-child { border-top: 0; }
.trace details { border: 0; padding: 0; }
.trace summary { display: grid; grid-template-columns: 72px minmax(160px, 260px) minmax(0, 1fr); gap: 12px; align-items: baseline;
  padding: 10px 0; list-style: none; font-weight: 400; }
.trace summary::-webkit-details-marker { display: none; }
.trace .step { font-weight: 500; }
.trace .gist { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trace details[open] > summary { margin-bottom: 0; }
.trace details > .kv, .trace details > .empty { margin: 0 0 12px 84px; }
.trace li.failed .step { color: var(--negative); }
.trace .earlier > details > .trace { margin-left: 84px; border-left: 1px solid var(--rule); padding-left: 12px; margin-bottom: 8px; }

/* tablet and phone */
@media (max-width: 1000px) {
  .grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 640px) {
  .bar-inner, main { padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); }
  main { padding-block: 20px 48px; }
  .scope, .who-name { display: none; }
  h1 { font-size: 22px; line-height: 28px; }
  .title-row { align-items: stretch; }
  .switch { width: 100%; }
  .switch input { flex: 1; width: auto; }
  .btn, input { height: 44px; }
  .joined { flex-wrap: wrap; gap: 8px; }
  .joined .addon { display: none; }
  .joined input, .joined .btn { border-radius: var(--radius-control); }
  .joined input { flex-basis: 100%; }
  .joined .btn { flex: 1; }
  .lives { grid-template-columns: 1fr; gap: 14px; }
  .kv > div { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .trace summary { grid-template-columns: 64px minmax(0, 1fr); }
  .trace .gist { grid-column: 2; }
  .trace details > .kv, .trace details > .empty { margin-left: 0; }
  .trace .earlier > details > .trace { margin-left: 0; }
  /* Phone: the request moves under the user, so the result never runs off the card. */
  .path { display: none; }
  .person { align-items: flex-start; }
  .path-sub { display: block; color: var(--muted); max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  td { height: auto; padding-block: 10px; }
  .calls th.num, .calls td.num { display: none; }
}
@media (prefers-reduced-motion: reduce) { .btn, .track span { transition: none; } }
`;
