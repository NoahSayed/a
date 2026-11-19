import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { PRIVATE_KEY, PUBLIC_KEY } from './keys.js';
import { readJson } from './data.js';

export const COOKIE = 'bakery_session';

function checkPassword(user, password) {
  const [salt, hash] = user.pw.split(':');
  const got = crypto.scryptSync(password, salt, 32);
  return crypto.timingSafeEqual(got, Buffer.from(hash, 'hex'));
}

/** Returns the user record for valid credentials, otherwise null. */
export function authenticate(id, password) {
  if (typeof id !== 'string' || typeof password !== 'string') return null;
  const user = readJson('users.json').find((u) => u.id === id);
  return user && checkPassword(user, password) ? user : null;
}

/** Signs a one-hour session token for a user. */
export function issueSession(user) {
  return jwt.sign({ sub: user.id, role: user.role }, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h' });
}

/** Returns { sub, role } for a valid token, otherwise null. */
export function readSession(token) {
  if (!token) return null;
  try {
    const p = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    return { sub: p.sub, role: p.role };
  } catch {
    return null;
  }
}

export function sessionFromRequest(request) {
  const m = /(?:^|;\s*)bakery_session=([^;]+)/.exec(request.headers.get('cookie') || '');
  return m ? readSession(decodeURIComponent(m[1])) : null;
}
