# IFS Cloud PKCE auth (proof of concept)

A small Node.js web app that signs a user in to **IFS Cloud IAM** with the
**Authorization Code flow + PKCE** (RFC 7636), validates the result, and lets you
call an IFS API as that user.

It exists to test the approach recommended in the *Mahara IFS User Execution*
investigation before building it into the Mahara desktop app. In that approach,
a tester picks an IFS user, signs in as that user through the IAM login page,
and runs the tests with that user's own access token. IFS then applies that
user's permission sets. Testers no longer need one Mahara environment per
service account to fake different permissions.

## What it does

1. **Discovery**: reads `${IFS_URL}/auth/realms/${IFS_REALM}/.well-known/openid-configuration`
   and checks that the IAM advertises `S256`.
2. **Authorize**: generates a fresh `code_verifier` (43 chars), its S256 `code_challenge`,
   `state` and `nonce`. It then redirects the browser to the IAM authorization endpoint.
   You can also pass a `login_hint` to pre-fill the IFS user id.
3. **Callback**: checks `state` and how old the login transaction is, then exchanges
   `code` + `code_verifier` at the token endpoint. No client secret is sent for a public client.
4. **Validate**: verifies the ID token's signature against the realm JWKS, plus `iss`,
   `aud`, `exp` and `nonce`. It also inspects the access token (claims, signature, issuer).
5. **Use**: sends a `GET` to any IFS API path with `Authorization: Bearer <access token>`.
   Sign in as different users and repeat the same call to compare `200` against `403`.
6. **Refresh / logout**: refreshes tokens and rejects the result if the subject changes.
   Logout is RP-initiated through the IAM `end_session_endpoint`.
7. **Switch user**: ends the IAM SSO session (logout with `id_token_hint` and a `state`),
   comes back to `/` and starts a fresh login. See *Why switching user logs out first*.

The page has four working blocks: **Call IFS as <user>**, **Session** (live token
countdowns, subject, signature), **Calls by user** and **ID token claims**. **Calls by user**
keeps every call with the user who made it, across user switches, so you can compare 200
against 403 side by side. A **Flow trace** records each step of the sign-in, so you can see
exactly what was sent and what came back. Earlier sign-ins fold into one row.

Tokens stay in the server-side in-memory session. The browser only gets an
`httpOnly` session cookie.

## Setup in IFS Cloud

Create an IAM client for this app. In IFS Cloud you manage IAM clients on the
**IAM Client** page under Solution Manager → Users and Permissions. Field names
can differ slightly between releases.

| Setting | Value |
|---|---|
| Client ID | e.g. `MAHARA_PKCE_POC`, which goes in `IFS_CLIENT_ID` |
| Client type | **Public** (no secret). If your release only allows confidential clients, put the secret in `IFS_CLIENT_SECRET`. PKCE is still used. |
| Redirect URI | `http://localhost:3000/callback` (must match `REDIRECT_URI` exactly) |
| Post-logout redirect | `http://localhost:3000/` (if the page has a separate field) |
| Flow | Authorization Code (standard flow) enabled |

The IFS users you want to test with must be active and able to log in to IFS
Cloud. Their permission sets decide what the API probe returns.

Reference: [IFS docs: Authorization Code Flow with PKCE](https://docs.ifs.com/techdocs/25r2/030_administration/010_security/040_iam_settings/035_iam_clients/020_authenticate_external_integration/200_authorization_code_flow_pkce/)

## Run

Requires Node.js 22+.

```bash
npm install
cp .env.example .env   # then fill in IFS_URL, IFS_REALM, IFS_CLIENT_ID
npm start              # http://localhost:3000
```

If IFS uses a certificate from a private CA, trust that CA. Do not turn off TLS
validation:

```bash
NODE_EXTRA_CA_CERTS=/path/to/company-ca.pem npm start
```

## Suggested trial (permission testing)

1. Sign in as a user who has the permission set needed for, say, `CustomerHandling`.
   Call the probe path and expect `200`.
2. Click **Sign in as a different user**, optionally entering the IFS user id, and log in as a user without that permission set.
   Repeat the call and expect `403`, or an empty result if row-level security applies.
3. Click **Refresh tokens** and confirm that the identity stays the same and whether
   the refresh token rotates. The investigation needs this answer before it allows
   refresh-token continuation for public clients.
4. Note what the trace shows for `sub`, `preferred_username` and the access token's
   claims (for example `upn`). These are the candidates for the "expected subject" check
   that Mahara needs to run before each test run.

## Why switching user logs out first

IFS IAM is built on Keycloak. While an IAM SSO session exists, a login request with
`prompt=login` is treated as **re-authentication of the user who is already signed in**.
The password you type is checked against that user, whatever you enter as the username,
so another user's correct password fails with *Invalid password*.

**Sign in as a different user** therefore ends the IAM session first. The app sends the
browser to the end-session endpoint with `id_token_hint`, `post_logout_redirect_uri`
and a random `state`. IAM returns to `/` with that `state`, and the app starts a fresh
PKCE login. This uses the `http://localhost:3000/` redirect URI already registered for logout.

The Mahara desktop will need the same rule: selecting a different IFS user for a run
must end the IAM browser session, or use a separate browser profile, before logging in.

## Tests

```bash
npm test
```

The tests run the whole flow against a mock Keycloak-style IAM and a fake IFS projection:
PKCE parameters, verifier check, ID token validation, permission differences between
users, switching user through IAM logout, state mismatch, and refusing to send the token
to another origin.

## Differences from the planned desktop implementation

- The desktop (WinUI/.NET) would use the **system browser + a loopback redirect**
  (`http://127.0.0.1:<port>/callback`), not a web server on a fixed port. Test whether
  your IAM client accepts loopback redirects on any port.
- The desktop would keep tokens in memory per run context and protect any stored
  refresh token (DPAPI). This PoC keeps them in an in-memory server session.
- This PoC validates the protocol by hand with `jose`, so every step is visible.
  For production, the investigation recommends a maintained OIDC client library.

## Layout

```
src/pkce.js     verifier / S256 challenge / state & nonce
src/oidc.js     discovery, authorize URL, token exchange & refresh, token validation, logout URL
src/app.js      Express routes (/login, /callback, /refresh, /probe, /switch-user, /logout)
src/views.js    server-rendered HTML and CSS (light and dark, phone layout)
src/server.js   starts the server
test/           unit + end-to-end tests
test/support/   mock IFS IAM (Keycloak-style) and fake IFS projection used by the tests
```
