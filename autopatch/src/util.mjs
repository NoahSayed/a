// Small shared helpers. No dependencies beyond Node built-ins.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function sh(cmd, args, opts = {}) {
  const t = Date.now();
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 128e6, ...opts });
  return { code: r.status, out: r.stdout || '', err: r.stderr || '', ms: Date.now() - t, error: r.error };
}

/** curl honours the environment's HTTPS proxy and CA settings; Node's fetch may not. */
export function fetchText(url, { cacheDir, cacheKey, timeoutS = 30 } = {}) {
  const p = cacheDir && cacheKey ? path.join(cacheDir, cacheKey) : null;
  if (p && fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  const r = sh('curl', ['-sfL', '-m', String(timeoutS), url]);
  if (r.code !== 0) return null;
  if (p) { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, r.out); }
  return r.out;
}

export async function http(base, pathAndQuery, { method = 'GET', form, json, headers = {}, cookie, timeoutMs = 20000 } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let body;
  if (form) { body = new URLSearchParams(form).toString(); h['content-type'] = 'application/x-www-form-urlencoded'; }
  if (json !== undefined) { body = JSON.stringify(json); h['content-type'] = 'application/json'; }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(new URL(pathAndQuery, base), { method: body && method === 'GET' ? 'POST' : method, headers: h, body, redirect: 'manual', signal: ctl.signal });
    return { status: r.status, text: await r.text(), headers: r.headers };
  } catch (e) {
    return { status: 0, text: '', error: String(e) };
  } finally { clearTimeout(timer); }
}

export function hashDir(dir, { ignore = [] } = {}) {
  const h = crypto.createHash('sha256');
  const walk = (d, rel = '') => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (ignore.includes(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p, rel + e.name + '/');
      else { h.update(rel + e.name); h.update(fs.readFileSync(p)); }
    }
  };
  walk(dir);
  return h.digest('hex');
}

export function listFiles(dir, { ignore = ['node_modules', '.git', '.next'] } = {}) {
  const out = [];
  const walk = (d, rel = '') => {
    if (!fs.existsSync(d)) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (ignore.includes(e.name)) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r); else out.push(r);
    }
  };
  walk(dir);
  return out.sort();
}

/** Copy a project directory, skipping heavy or machine-local folders. */
export function copyTree(from, to, { skip = ['node_modules', '.git', '.next'] } = {}) {
  fs.rmSync(to, { recursive: true, force: true });
  fs.cpSync(from, to, { recursive: true, filter: (src) => !skip.includes(path.basename(src)) || src === from });
}

/** Minimal glob: supports "dir/**", "dir/*.ext", exact paths. */
export function matchGlob(file, pattern) {
  const re = new RegExp('^' + pattern.split('**').map((s) => s.split('*').map(escapeRe).join('[^/]*')).join('.*') + '$');
  return re.test(file);
}
const escapeRe = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

export function changedFiles(a, b, opts) {
  const fa = new Set(listFiles(a, opts)), fb = new Set(listFiles(b, opts));
  const out = [];
  for (const f of new Set([...fa, ...fb])) {
    if (!fa.has(f)) out.push({ file: f, change: 'added' });
    else if (!fb.has(f)) out.push({ file: f, change: 'removed' });
    else if (!fs.readFileSync(path.join(a, f)).equals(fs.readFileSync(path.join(b, f)))) out.push({ file: f, change: 'modified' });
  }
  return out.sort((x, y) => x.file.localeCompare(y.file));
}

export function unifiedDiff(a, b, files) {
  return files.map((f) => sh('diff', ['-u', '--label', `a/${f}`, '--label', `b/${f}`, fs.existsSync(path.join(a, f)) ? path.join(a, f) : '/dev/null', fs.existsSync(path.join(b, f)) ? path.join(b, f) : '/dev/null']).out).join('');
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function vcmp(a, b) {
  const x = String(a).split(/[.-]/).map((n) => parseInt(n, 10) || 0), y = String(b).split(/[.-]/).map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return Math.sign(d); }
  return 0;
}

export function createLogger(verbose) {
  return { info: (m) => console.error(m), debug: (m) => verbose && console.error(`  · ${m}`) };
}
