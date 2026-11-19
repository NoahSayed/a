// The pipeline's own site checks: page smoke, key flows, per-item security regression probes, unit tests, server-error count.
// (The hidden grader uses different inputs. Agents only ever see this file's output.)
import fs from 'node:fs';
import path from 'node:path';
import { http, login, sh, readJson } from './site.mjs';

const ADMIN_MARK = 'Admin dashboard';
const SUBREQ = 'middleware:middleware:middleware:middleware:middleware';

async function noteOf(port, cookie, id) {
  const r = await http(port, `/api/orders/${id}/note`, { cookie });
  try { return JSON.parse(r.text).text; } catch { return undefined; }
}

export const PROBES = {
  // GHSA-f82v-jwr5-mffw: x-middleware-subrequest skips middleware, so /admin must not render for an anonymous caller.
  next: async (c) => {
    const r = await http(c.port, '/admin', { headers: { 'x-middleware-subrequest': SUBREQ } });
    return { name: 'exploit blocked: /admin with x-middleware-subrequest header and no session', pass: !r.text.includes(ADMIN_MARK), detail: `status ${r.status}` };
  },
  // jsonwebtoken advisories: forged tokens must never be accepted.
  jsonwebtoken: async (c) => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'baker', role: 'admin' })}.`;
    const r = await http(c.port, '/admin', { cookie: `bakery_session=${forged}` });
    const v = await http(c.port, '/api/auth/verify', { cookie: `bakery_session=${forged}` });
    return { name: 'forged alg=none session token rejected', pass: !r.text.includes(ADMIN_MARK) && v.status === 401, detail: `admin ${r.status}, verify ${v.status}` };
  },
  // FICTIONAL-BAKERY-2024-0001: anonymous caller must not change someone else's order note.
  '@bakery/order-notes': async (c) => {
    const bob = (await login(c.port, 'bob', 'bob-pass-1')).cookie;
    const before = await noteOf(c.port, bob, 2);
    await http(c.port, '/api/orders/2/note', { method: 'PUT', json: { text: 'PIPELINE-PROBE anonymous overwrite' } });
    const after = await noteOf(c.port, bob, 2);
    if (after !== before) await http(c.port, '/api/orders/2/note', { method: 'PUT', json: { text: before }, cookie: bob }); // put it back
    return { name: 'exploit blocked: anonymous request cannot overwrite order 2 note', pass: before !== undefined && after === before, detail: `before=${JSON.stringify(before)} after=${JSON.stringify(after)}` };
  },
  '@bakery/analytics': async (c) => {
    const s0 = JSON.parse((await http(c.port, '/api/stats')).text || '{}');
    await http(c.port, '/products/1');
    const s1 = JSON.parse((await http(c.port, '/api/stats')).text || '{}');
    return { name: 'analytics still counts product views', pass: (s1.events ?? -1) > (s0.events ?? 0), detail: `${s0.events} -> ${s1.events}` };
  },
};

/** Run the checks against a running server. `probes` are item names whose security probe should run. */
export async function runChecks({ dir, port, probes = [], known = [], logFile, unit = true }) {
  const logStart = logFile && fs.existsSync(logFile) ? fs.statSync(logFile).size : 0;
  const checks = [];
  const add = (group, name, pass, detail = '') => checks.push({ group, name, pass: Boolean(pass), detail: String(detail).slice(0, 220) });

  for (const [label, p, mark] of [['home', '/', 'Fresh bread'], ['products', '/products', 'Sourdough Loaf'], ['product detail', '/products/2', 'Butter Croissant'], ['login', '/login', 'Log in'], ['admin login redirect target', '/login?next=/admin', 'Log in']]) {
    const r = await http(port, p);
    add('page', `page ${label} renders`, r.status === 200 && r.text.includes(mark) && !/Application error|Internal Server Error/.test(r.text), `status ${r.status}`);
  }
  const prods = await http(port, '/api/products');
  add('page', 'products API lists 5 products', prods.status === 200 && (() => { try { return JSON.parse(prods.text).length === 5; } catch { return false; } })(), `status ${prods.status}`);

  const alice = await login(port, 'alice', 'alice-pass-1');
  add('flow', 'login with valid credentials works', alice.status === 200 && alice.cookie.includes('bakery_session='), `status ${alice.status} ${alice.status !== 200 ? alice.text.slice(0, 80) : ''}`);
  const bad = await login(port, 'alice', 'not-the-password');
  add('flow', 'login with wrong password fails', bad.status === 401 && !bad.cookie, `status ${bad.status}`);
  const baker = await login(port, 'baker', 'croissant-123');
  const a0 = await http(port, '/admin');
  add('flow', 'admin is blocked for anonymous', a0.status !== 200 && !a0.text.includes(ADMIN_MARK), `status ${a0.status}`);
  const a1 = await http(port, '/admin', { cookie: 'bakery_session=garbage' });
  add('flow', 'admin is blocked for a bogus session', a1.status !== 200 && !a1.text.includes(ADMIN_MARK), `status ${a1.status}`);
  const a2 = await http(port, '/admin', { cookie: alice.cookie });
  add('flow', 'admin is blocked for a customer session', a2.status !== 200 && !a2.text.includes(ADMIN_MARK), `status ${a2.status}`);
  const a3 = await http(port, '/admin', { cookie: baker.cookie });
  add('flow', 'admin works for the logged-in admin', a3.status === 200 && a3.text.includes(ADMIN_MARK), `status ${a3.status}`);
  const my = await http(port, '/orders', { cookie: alice.cookie });
  add('flow', 'customer sees own orders page', my.status === 200 && my.text.includes('Your orders'), `status ${my.status}`);
  const orig = await noteOf(port, alice.cookie, 1);
  const text = `pipeline edit ${Date.now() % 100000}`;
  const put = await http(port, '/api/orders/1/note', { method: 'PUT', json: { text }, cookie: alice.cookie });
  const now = await noteOf(port, alice.cookie, 1);
  add('flow', 'owner can edit own order note', put.status === 200 && now === text, `PUT ${put.status}, now ${JSON.stringify(now)}`);
  if (orig !== undefined) await http(port, '/api/orders/1/note', { method: 'PUT', json: { text: orig }, cookie: alice.cookie });

  for (const item of probes) if (PROBES[item]) { const r = await PROBES[item]({ port, dir }); add('probe', r.name, r.pass, r.detail); }

  if (unit) {
    const t = sh('npm', ['test', '--silent'], { cwd: dir, timeout: 120e3 });
    add('unit', 'unit tests (npm test) pass', t.code === 0, t.code === 0 ? '' : (t.out + t.err).split('\n').filter((l) => /error|fail|minimum/i.test(l)).slice(0, 2).join(' | '));
  }

  if (logFile && fs.existsSync(logFile)) {
    const fresh = fs.readFileSync(logFile, 'utf8').slice(logStart).split('\n').filter((l) => /⨯|\bError\b|error:|unhandled/i.test(l));
    add('log', 'no server errors logged during the checks', fresh.length === 0, fresh.slice(0, 2).join(' | '));
  }
  for (const c of checks) c.known = !c.pass && known.includes(c.name);
  return { checks, pass: checks.every((c) => c.pass || c.known), failing: checks.filter((c) => !c.pass && !c.known) };
}

export function formatChecks(res) {
  return res.checks.map((c) => `${c.pass ? 'PASS' : c.known ? 'KNOWN-FAIL' : 'FAIL'} [${c.group}] ${c.name}${c.detail ? ` (${c.detail})` : ''}`).join('\n');
}
