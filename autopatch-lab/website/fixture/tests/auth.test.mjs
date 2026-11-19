import test from 'node:test';
import assert from 'node:assert/strict';
import { authenticate, issueSession, readSession } from '../lib/auth.js';

test('valid credentials authenticate, invalid do not', () => {
  assert.equal(authenticate('alice', 'alice-pass-1')?.id, 'alice');
  assert.equal(authenticate('alice', 'wrong'), null);
});

test('session token round trip', () => {
  const s = readSession(issueSession({ id: 'bob', role: 'customer' }));
  assert.deepEqual(s, { sub: 'bob', role: 'customer' });
});

test('garbage token is rejected', () => {
  assert.equal(readSession('not-a-token'), null);
});
