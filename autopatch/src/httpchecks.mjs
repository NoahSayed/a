// Declarative HTTP checks shared by website adapters (Next.js, WordPress, any server app).
//   pages:  [{ path, status = 200, notIncludes = [...] , includes = [...] }]
//   flows:  [{ name, method, path, form | json, headers, useCookie, saveCookie, phase,
//              expect: { status: [..], includes, notIncludes, minCount: { text, n } } }]
//           phase: "any" (default) | "before-restart" | "after-restart"
//           saveCookie/useCookie let a flow log in before a restart and prove the session survives it.
//   probes: [{ finding, script }]  script: node <script> <baseUrl>  -> exit 0 = STILL VULNERABLE, exit 1 = blocked
import path from 'node:path';
import { http, sh } from './util.mjs';

const ERROR_TEXT = [/critical error/i, /Fatal error/, /Parse error/, /Internal Server Error/, /Application error: a (server|client)-side exception/];

export async function runPages(base, pages) {
  const out = [];
  for (const p of pages) {
    const r = await http(base, p.path);
    const want = p.status ?? 200;
    const errs = ERROR_TEXT.filter((re) => re.test(r.text)).map(String);
    const missing = (p.includes || []).filter((s) => !r.text.includes(s));
    const bad = (p.notIncludes || []).filter((s) => r.text.includes(s));
    out.push({ name: `page ${p.path}`, pass: r.status === want && !errs.length && !missing.length && !bad.length,
      detail: `${r.status}${errs.length ? ' error text on page' : ''}${missing.length ? ` missing: ${missing.join(', ')}` : ''}${bad.length ? ` unexpected: ${bad.join(', ')}` : ''}` });
  }
  return out;
}

function cookiesFrom(headers) {
  const list = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  return list.map((c) => c.split(';')[0]).filter((c) => !/=deleted$|=$/.test(c));
}

export async function runFlows(base, flows, { phase = 'any', jar = {} } = {}) {
  const out = [];
  for (const f of flows.filter((f) => (f.phase || 'any') === phase || (phase === 'any' && !f.phase))) {
    const r = await http(base, f.path, { method: f.method || (f.form || f.json ? 'POST' : 'GET'), form: f.form, json: f.json, headers: f.headers, cookie: f.useCookie ? jar[f.useCookie] : undefined });
    if (f.saveCookie) { const c = cookiesFrom(r.headers || { getSetCookie: () => [] }); if (c.length) jar[f.saveCookie] = c.join('; '); }
    const e = f.expect || {};
    const statuses = e.status ? [].concat(e.status) : [200];
    const problems = [];
    if (!statuses.includes(r.status)) problems.push(`status ${r.status}, want ${statuses.join('/')}`);
    for (const s of [].concat(e.includes || [])) if (!r.text.includes(s)) problems.push(`missing "${s}"`);
    for (const s of [].concat(e.notIncludes || [])) if (r.text.includes(s)) problems.push(`unexpected "${s}"`);
    if (e.minCount && (r.text.split(e.minCount.text).length - 1) < e.minCount.n) problems.push(`fewer than ${e.minCount.n} × "${e.minCount.text}"`);
    out.push({ name: `flow ${f.name}`, pass: problems.length === 0, detail: problems.join('; ') || 'ok' });
  }
  return out;
}

export function runProbes(base, probes, projectDir, findingKeys) {
  const out = [];
  for (const p of probes.filter((p) => !findingKeys || findingKeys.includes(p.finding))) {
    const r = sh(process.execPath, [path.resolve(projectDir, p.script), base], { timeout: 60000 });
    const vulnerable = r.code === 0;
    out.push({ name: `exploit blocked: ${p.finding}`, pass: r.code === 1, detail: vulnerable ? 'probe still works' : r.code === 1 ? 'blocked' : `probe error (exit ${r.code}): ${(r.err || '').slice(-200)}` });
  }
  return out;
}
