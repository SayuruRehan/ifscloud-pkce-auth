import { createHash, randomBytes } from 'node:crypto';

// RFC 7636: the verifier is 43-128 chars from [A-Z a-z 0-9 - . _ ~].
// 32 random bytes base64url-encode to exactly 43 chars; 96 bytes give 128.
export function createCodeVerifier(byteLength = 32) {
  if (byteLength < 32 || byteLength > 96) {
    throw new RangeError('byteLength must be between 32 and 96 (43-128 characters)');
  }
  return randomBytes(byteLength).toString('base64url');
}

// S256: BASE64URL(SHA256(ASCII(code_verifier)))
export function createCodeChallenge(verifier) {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

// Opaque random value for state / nonce.
export function randomToken(byteLength = 16) {
  return randomBytes(byteLength).toString('base64url');
}
