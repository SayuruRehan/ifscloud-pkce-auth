import { randomBytes } from 'node:crypto';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable ${name}. Copy .env.example to .env and fill it in.`);
  }
  return value;
}

const port = Number(process.env.PORT ?? 3000);
const ifsUrl = required('IFS_URL').replace(/\/+$/, '');
const realm = required('IFS_REALM');

export const config = {
  port,
  ifsUrl,
  realm,
  // IFS IAM is Keycloak based; the realm issuer lives under /auth/realms/<realm>.
  issuer: process.env.IFS_ISSUER?.trim() || `${ifsUrl}/auth/realms/${encodeURIComponent(realm)}`,
  clientId: required('IFS_CLIENT_ID'),
  // Leave empty for a public client (the case PKCE exists for). Set it only if the
  // IAM client is confidential; PKCE is still sent in that case.
  clientSecret: process.env.IFS_CLIENT_SECRET?.trim() || undefined,
  scope: process.env.IFS_SCOPE?.trim() || 'openid microprofile-jwt',
  redirectUri: process.env.REDIRECT_URI?.trim() || `http://localhost:${port}/callback`,
  postLogoutRedirectUri: process.env.POST_LOGOUT_REDIRECT_URI?.trim() || `http://localhost:${port}/`,
  apiProbePath: process.env.API_PROBE_PATH?.trim() || '',
  sessionSecret: process.env.SESSION_SECRET?.trim() || randomBytes(32).toString('hex'),
};
