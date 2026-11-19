// Helpers to copy, install, build, serve and query the lab Next.js site.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const LAB = path.dirname(new URL(import.meta.url).pathname);
export const ROOT = path.join(LAB, '..');
export const FIXTURE = path.join(ROOT, 'fixture');
export const REGISTRY = path.join(ROOT, 'registry');
export const SCRATCH = process.env.WEBLAB_SCRATCH || '/tmp/claude-0/-home-user-a/085e7a47-7d23-560e-b39e-f8f23f36655f/scratchpad/weblab2';
export const PORT_MIN = 3100, PORT_MAX = 3199;

/** Site-owned code: the only things an AI may edit and the only things replayed from staging to production. */
export const OWNED = ['app', 'lib', 'components', 'middleware.js', 'public'];

export function sh(cmd, args, opts = {}) {
  const t = Date.now();
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 256e6, ...opts });
  return { code: r.status, out: r.stdout || '', err: r.stderr || '', ms: Date.now() - t };
}

/** Guard so a bad variable can never make us delete something outside the lab scratch directory. */
export function safeRm(p) {
  const abs = path.resolve(p);
  if (!abs.startsWith(SCRATCH + path.sep) || abs.split(path.sep).length < SCRATCH.split(path.sep).length + 1) throw new Error(`refusing to delete ${abs}`);
  fs.rmSync(abs, { recursive: true, force: true });
}

/** Copy a site's source (not node_modules, not the build output, not logs). */
export function copySource(from, to) {
  safeRm(to);
  fs.cpSync(from, to, { recursive: true, filter: (p) => !/(^|\/)(node_modules|\.next)(\/|$)/.test(path.relative(from, p)) && !p.endsWith('.log') });
}

export function npmCi(dir) {
  return sh('npm', ['ci', '--no-audit', '--no-fund', '--ignore-scripts'], { cwd: dir, timeout: 300e3 });
}

export function build(dir) {
  const r = sh(process.execPath, [path.join(dir, 'node_modules/next/dist/bin/next'), 'build'], { cwd: dir, timeout: 600e3, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' } });
  return { ok: r.code === 0, out: (r.out + r.err).slice(-4000), ms: r.ms };
}

// ---------- servers ----------
const servers = new Map(); // port -> { pid, dir }

function assertPort(port) { if (port < PORT_MIN || port > PORT_MAX) throw new Error(`port ${port} outside ${PORT_MIN}-${PORT_MAX}`); }

export async function start(dir, port, logFile) {
  assertPort(port);
  await stop(port);
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  const fd = fs.openSync(logFile, 'a');
  const p = spawn(process.execPath, [path.join(dir, 'node_modules/next/dist/bin/next'), 'start', '-p', String(port), '-H', '127.0.0.1'], {
    cwd: dir, stdio: ['ignore', fd, fd], detached: true, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' },
  });
  p.unref();
  servers.set(port, { pid: p.pid, dir });
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/api/products`); if (r.status < 500 || i > 60) return true; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

export async function stop(port) {
  assertPort(port);
  const s = servers.get(port);
  if (s) { try { process.kill(-s.pid, 'SIGKILL'); } catch { /* already gone */ } servers.delete(port); }
  await new Promise((r) => setTimeout(r, 250));
}

/** Kill next servers whose cwd is under `prefix` (our scratch dirs only), or listening process by port tag. */
export function killUnder(prefix) {
  for (const pid of fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x))) {
    try {
      const cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      if (prefix && cwd.startsWith(prefix) && cwd.startsWith(SCRATCH) && /next/.test(fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'))) process.kill(Number(pid), 'SIGKILL');
    } catch { /* process vanished or not ours */ }
  }
}

// ---------- http ----------
export async function http(port, p, { method, json, headers = {}, cookie } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let body;
  if (json !== undefined) { body = JSON.stringify(json); h['content-type'] = 'application/json'; }
  try {
    const r = await fetch(`http://127.0.0.1:${port}${p}`, { method: method || (body ? 'POST' : 'GET'), headers: h, body, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    const text = await r.text();
    return { status: r.status, text, location: r.headers.get('location') || '', setCookie: r.headers.getSetCookie?.() || [] };
  } catch (e) {
    return { status: 0, text: String(e.message), location: '', setCookie: [] };
  }
}

export async function login(port, username, password) {
  const r = await http(port, '/api/auth/login', { json: { username, password } });
  const cookie = r.setCookie.map((c) => c.split(';')[0]).join('; ');
  return { status: r.status, cookie, text: r.text };
}

export function readJson(dir, rel) { return JSON.parse(fs.readFileSync(path.join(dir, rel), 'utf8')); }
