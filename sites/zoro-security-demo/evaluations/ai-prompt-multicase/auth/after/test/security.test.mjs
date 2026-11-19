import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { authenticate, cookieOptions } from '../src/session.mjs';

const key = 'synthetic-only-test-key';
const issue = (secret, options = {}) => jwt.sign({ sub: 'demo' }, secret, {
  algorithm: 'HS256',
  issuer: 'trace-eval',
  ...options,
});

test('valid signed token is accepted', () => {
  assert.equal(authenticate(issue(key, { expiresIn: '1h' }), key)?.sub, 'demo');
});

test('wrong-signature token is rejected', () => {
  assert.equal(authenticate(issue('wrong-synthetic-key', { expiresIn: '1h' }), key), null);
});

test('expired token is rejected', () => {
  assert.equal(authenticate(issue(key, { expiresIn: -10 }), key), null);
});

test('token from an unexpected issuer is rejected', () => {
  const token = issue(key, { issuer: 'other-issuer', expiresIn: '1h' });
  assert.equal(authenticate(token, key), null);
});

test('token without an expiration is rejected', () => {
  assert.equal(authenticate(issue(key), key), null);
});

test('token signed with a different algorithm is rejected', () => {
  const token = issue(key, { algorithm: 'HS384', expiresIn: '1h' });
  assert.equal(authenticate(token, key), null);
});

test('session cookie options require Secure and HttpOnly', () => {
  assert.equal(cookieOptions.httpOnly, true);
  assert.equal(cookieOptions.secure, true);
  assert.equal(cookieOptions.sameSite, 'lax');
});
