import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { config } from './config.js';

let discoveryCache;
let jwks;

// Fetch the realm's OpenID Provider metadata once and reuse it.
export async function discover() {
  if (discoveryCache) return discoveryCache;
  const url = `${config.issuer}/.well-known/openid-configuration`;
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`Discovery failed: GET ${url} returned ${res.status} ${res.statusText}`);
  }
  const metadata = await res.json();
  const methods = metadata.code_challenge_methods_supported ?? [];
  if (methods.length && !methods.includes('S256')) {
    throw new Error(`IAM does not advertise S256 PKCE (supports: ${methods.join(', ')})`);
  }
  discoveryCache = { url, metadata };
  jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
  return discoveryCache;
}

export function buildAuthorizeUrl(metadata, { state, nonce, codeChallenge, loginHint, forceLogin }) {
  const url = new URL(metadata.authorization_endpoint);
  const params = {
    client_id: config.clientId,
    response_type: 'code',
    scope: config.scope,
    redirect_uri: config.redirectUri,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  };
  if (loginHint) params.login_hint = loginHint;
  // prompt=login makes IAM re-authenticate even when an SSO session already
  // exists in the browser, which is what lets you switch between IFS users.
  if (forceLogin) params.prompt = 'login';
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url;
}

async function tokenRequest(metadata, body) {
  const form = new URLSearchParams({ client_id: config.clientId, ...body });
  if (config.clientSecret) form.set('client_secret', config.clientSecret);
  const res = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: form,
    redirect: 'error',
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  if (!res.ok) {
    const detail = json.error ? `${json.error}: ${json.error_description ?? ''}` : text.slice(0, 500);
    throw new Error(`Token endpoint returned ${res.status}. ${detail}`);
  }
  return json;
}

export function exchangeCode(metadata, { code, codeVerifier }) {
  return tokenRequest(metadata, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier,
  });
}

export function refreshTokens(metadata, refreshToken) {
  return tokenRequest(metadata, { grant_type: 'refresh_token', refresh_token: refreshToken });
}

// Full validation of the ID token: signature (realm JWKS), iss, aud, exp and nonce.
export async function validateIdToken(metadata, idToken, expectedNonce) {
  const { payload, protectedHeader } = await jwtVerify(idToken, jwks, {
    issuer: metadata.issuer,
    audience: config.clientId,
  });
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new Error('ID token nonce does not match the nonce sent in the authorization request');
  }
  return { payload, protectedHeader };
}

// The access token is meant for IFS, not for us, so we only inspect it. If it is a
// JWT signed by the realm we also check the signature and issuer for evidence.
export async function inspectAccessToken(metadata, accessToken) {
  const result = { isJwt: false, claims: null, header: null, signature: 'not checked' };
  try {
    result.header = decodeProtectedHeader(accessToken);
    result.claims = decodeJwt(accessToken);
    result.isJwt = true;
  } catch {
    result.signature = 'opaque token (not a JWT)';
    return result;
  }
  try {
    await jwtVerify(accessToken, jwks, { issuer: metadata.issuer });
    result.signature = 'valid (realm JWKS, issuer matches)';
  } catch (err) {
    result.signature = `NOT valid: ${err.message}`;
  }
  return result;
}

export function buildLogoutUrl(metadata, idToken) {
  if (!metadata.end_session_endpoint) return null;
  const url = new URL(metadata.end_session_endpoint);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
  if (idToken) url.searchParams.set('id_token_hint', idToken);
  return url;
}
