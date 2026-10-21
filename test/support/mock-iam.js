// A tiny mock of IFS IAM (a Keycloak-style realm) plus a fake IFS projection
// that only ALAIN may read. The login page is skipped: login_hint picks the user.
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

export async function startMockIam({ clientId, realm, port = 0 }) {
  let idpUrl;
  const codes = new Map();
  const issued = { tokenRequests: [], logouts: [] };
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

  const idp = createServer(async (req, res) => {
    const url = new URL(req.url, idpUrl);
    const issuer = `${idpUrl}/auth/realms/${realm}`;
    const base = `/auth/realms/${realm}`;
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
        access_token: await sign({ azp: clientId, upn: entry.user, aud: 'account' }),
        id_token: await sign({ aud: clientId, nonce: entry.nonce, preferred_username: entry.user.toLowerCase() }),
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
  await new Promise((r) => idp.listen(port, '127.0.0.1', r));
  idpUrl = `http://127.0.0.1:${idp.address().port}`;
  return { url: idpUrl, issued, close: () => idp.close() };
}
