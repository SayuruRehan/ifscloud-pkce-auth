import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCodeChallenge, createCodeVerifier } from '../src/pkce.js';

test('code verifier length and alphabet follow RFC 7636', () => {
  assert.equal(createCodeVerifier().length, 43);
  assert.equal(createCodeVerifier(96).length, 128);
  assert.match(createCodeVerifier(), /^[A-Za-z0-9\-._~]{43,128}$/);
  assert.throws(() => createCodeVerifier(31), RangeError);
  assert.throws(() => createCodeVerifier(97), RangeError);
});

test('S256 challenge matches the RFC 7636 appendix B example', () => {
  assert.equal(
    createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
    'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  );
});
