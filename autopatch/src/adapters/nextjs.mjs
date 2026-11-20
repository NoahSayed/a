// Next.js adapter: an npm project that also runs a server. Findings, releases, update actions and promotion are
// npm's; on top of that it builds and starts the app on a staging port, runs HTTP pages / flows / probes against
// it (before AND after a restart), and checks that the AI added no risky code to the site's own files.
//
// Lessons from the Next.js lab built in:
//  - `next start` renames itself `next-server`, so stop() kills the process group AND any next-server whose cwd
//    is under the staging dirs.
//  - rebuild after every change (restart() rebuilds whenever the sources changed since the last build).
//  - the gate re-checks after a restart (hasServer: true) and flows can carry a session cookie across it.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { sh, http, sleep, listFiles, matchGlob } from '../util.mjs';
import { runPages, runFlows, runProbes } from '../httpchecks.mjs';
import { RISKY } from '../release-check.mjs';
import npmAdapter from './npm.mjs';

const KEEP_OUT = ['.next', '.git', '.autopatch'];
const INTEGRITY = ['eval', 'new Function', 'child_process / shell', 'remote fetch'];
const tail = (s, n) => String(s || '').slice(-n);
const port = (ctx) => Number(ctx.cfg.server?.port) || 3200;
const base = (ctx) => `http://127.0.0.1:${port(ctx)}`;
const state = (ctx) => (ctx.next ||= { buildOk: null, buildOut: '', sig: null, sigDir: null, pgid: null, started: false, errFile: null });

/** Hash of everything that influences a build (sources, lockfile, config), not runtime data. */
function sourceSig(dir) {
  const h = crypto.createHash('sha256');
  for (const f of listFiles(dir, { ignore: ['node_modules', ...KEEP_OUT] })) {
    if (f.startsWith('data/')) continue;
    h.update(f); h.update(fs.readFileSync(path.join(dir, f)));
  }
  return h.digest('hex');
}

function procs() {
  const out = [];
  for (const pid of fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x))) {
    try {
      const cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
      out.push({ pid: Number(pid), cwd, cmd });
    } catch { /* process vanished or not ours */ }
  }
  return out;
}

function killGroup(pgid, sig) { try { process.kill(-pgid, sig); } catch { /* already gone */ } }

/** Stop the server we started, plus any next server whose working directory is under one of `roots`. */
async function stopServer(ctx, roots = []) {
  const st = state(ctx);
  const rs = [...new Set([ctx.workDir, ...roots].filter(Boolean).map((r) => path.resolve(r)))];
  const victims = () => procs().filter((p) => p.pid !== process.pid && /next|node/.test(p.cmd)
    && /next(-server| start)|next\/dist|\.bin\/next/.test(p.cmd) && rs.some((r) => p.cwd === r || p.cwd.startsWith(r + path.sep)));
  if (st.pgid) killGroup(st.pgid, 'SIGTERM');
  for (const v of victims()) { try { process.kill(v.pid, 'SIGTERM'); } catch { /* gone */ } }
  for (let i = 0; i < 30; i++) {
    if (!(await portBusy(ctx)) && !victims().length) break;
    if (i === 10) { if (st.pgid) killGroup(st.pgid, 'SIGKILL'); for (const v of victims()) { try { process.kill(v.pid, 'SIGKILL'); } catch { /* gone */ } } }
    await sleep(200);
  }
  st.pgid = null; st.started = false;
}

async function portBusy(ctx) {
  const r = await http(base(ctx), '/', { timeoutMs: 1500 });
  return r.status !== 0;
}

function readLog(file) { try { return fs.readFileSync(file, 'utf8'); } catch { return ''; } }

const owned = (cfg, file) => cfg.ownedPaths.some((g) => matchGlob(file, g)) && !cfg.protectedPaths.some((g) => matchGlob(file, g));

function integrityCheck(ctx, dir) {
  const bad = [];
  const risky = RISKY.filter(([k]) => INTEGRITY.includes(k));
  const count = (text) => Object.fromEntries(risky.map(([k, re]) => [k, (text.match(re) || []).length]));
  for (const f of listFiles(dir).filter((f) => owned(ctx.cfg, f) && /\.(m?[jt]sx?|cjs)$/.test(f))) {
    const now = count(fs.readFileSync(path.join(dir, f), 'utf8'));
    const origP = path.join(ctx.cfg.projectDir, f);
    const was = fs.existsSync(origP) ? count(fs.readFileSync(origP, 'utf8')) : Object.fromEntries(risky.map(([k]) => [k, 0]));
    for (const [k] of risky) if (now[k] > was[k]) bad.push(`${f}: ${k}`);
  }
  return { name: 'integrity: no eval/child_process/remote fetch added in owned code', pass: bad.length === 0, detail: bad.join('; ') || 'ok' };
}

function httpChecks(ctx, phase, jar, findingKeys) {
  const { pages = [], flows = [], probes = [] } = ctx.cfg.checks;
  const b = base(ctx);
  return (async () => {
    const out = [];
    if (phase === 'after-restart') {
      out.push(...await runPages(b, pages));
      out.push(...await runFlows(b, flows, { phase: 'after-restart', jar }));
    } else {
      out.push(...await runPages(b, pages));
      out.push(...await runFlows(b, flows, { phase: 'any', jar }));
      out.push(...await runFlows(b, flows, { phase: 'before-restart', jar }));
    }
    out.push(...runProbes(b, probes, ctx.cfg.projectDir, findingKeys));
    return out;
  })();
}

export const nextjsAdapter = {
  ...npmAdapter,
  name: 'nextjs',
  hasServer: true,

  async prepareStaging(ctx, from, to) {
    if (!to || !path.isAbsolute(to) || path.resolve(to) === path.resolve(from) || path.resolve(to) === path.resolve(ctx.cfg.projectDir)) throw new Error(`refusing to prepare staging in ${to}`);
    fs.rmSync(to, { recursive: true, force: true });
    fs.mkdirSync(path.dirname(to), { recursive: true });
    // cp -a keeps node_modules symlinks (.bin) relative; fs.cpSync would point them back at the source tree
    const r = sh('cp', ['-a', path.resolve(from), to]);
    if (r.code !== 0) throw new Error(`copy to staging failed: ${r.err.slice(-300)}`);
    for (const k of KEEP_OUT) fs.rmSync(path.join(to, k), { recursive: true, force: true });
    if (!fs.existsSync(path.join(to, 'node_modules')) && fs.existsSync(path.join(to, 'package-lock.json'))) {
      const n = sh('npm', ['ci', '--no-audit', '--no-fund'], { cwd: to, timeout: 15 * 60e3 });
      if (n.code !== 0) throw new Error(`npm ci failed in staging: ${n.err.slice(-500)}`);
    }
  },

  async restart(ctx, dir) {
    const st = state(ctx);
    const staging = path.dirname(path.resolve(dir));
    await stopServer(ctx, [staging, dir]);
    if (await portBusy(ctx)) throw new Error(`port ${port(ctx)} is in use by something that is not an autopatch staging server`);
    // build (only when sources changed since the last successful build of this directory)
    const sig = sourceSig(dir);
    if (!(st.sigDir === dir && st.sig === sig && st.buildOk && fs.existsSync(path.join(dir, '.next')))) {
      if (path.resolve(dir) !== path.resolve(ctx.cfg.projectDir)) fs.rmSync(path.join(dir, '.next'), { recursive: true, force: true });
      const b = sh('npx', ['--no-install', 'next', 'build'], { cwd: dir, timeout: 15 * 60e3, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1', CI: '1' } });
      st.buildOut = b.out + b.err;
      st.buildOk = b.code === 0;
      st.sig = st.buildOk ? sig : null; st.sigDir = dir;
    }
    st.dir = dir;
    if (!st.buildOk) { ctx.log.debug?.(`build failed:\n${tail(st.buildOut, 600)}`); return; }
    fs.mkdirSync(ctx.workDir, { recursive: true });
    st.errFile = path.join(ctx.workDir, `next-${port(ctx)}.stderr.log`);
    const outFd = fs.openSync(path.join(ctx.workDir, `next-${port(ctx)}.stdout.log`), 'w');
    const errFd = fs.openSync(st.errFile, 'w');
    const child = spawn('npx', ['--no-install', 'next', 'start', '-p', String(port(ctx)), '-H', '127.0.0.1'], {
      cwd: dir, detached: true, stdio: ['ignore', outFd, errFd], env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1', NODE_ENV: 'production' },
    });
    child.unref();
    fs.closeSync(outFd); fs.closeSync(errFd);
    st.pgid = child.pid;
    let exited = false;
    child.on('exit', () => { exited = true; });
    const ready = ctx.cfg.server?.readyPath || '/';
    const deadline = Date.now() + (ctx.cfg.server?.readyTimeoutS || 90) * 1000;
    st.started = false;
    while (Date.now() < deadline && !exited) {
      const r = await http(base(ctx), ready, { timeoutMs: 5000 });
      if (r.status !== 0) { st.started = true; break; }
      await sleep(400);
    }
  },

  async stop(ctx) { await stopServer(ctx, ctx.next?.dir ? [path.dirname(path.resolve(ctx.next.dir))] : []); },

  async checks(ctx, dir, { findingKeys = [], phase = 'any', jar = {} } = {}) {
    const st = state(ctx);
    const out = [{ name: 'build succeeds', pass: Boolean(st.buildOk), detail: st.buildOk ? 'ok' : tail(st.buildOut, 400) || 'next build did not run' }];
    if (!st.buildOk) return out;
    if (!st.started) { out.push({ name: 'server starts', pass: false, detail: tail(readLog(st.errFile), 400) || `no answer on ${base(ctx)}${ctx.cfg.server?.readyPath || '/'}` }); return out; }
    const logStart = readLog(st.errFile).length;
    if (phase !== 'after-restart') {
      out.push(...await npmAdapter.checks(ctx, dir, { findingKeys }));
    }
    out.push(...await httpChecks(ctx, phase, jar, findingKeys));
    if (phase !== 'after-restart') out.push(integrityCheck(ctx, dir));
    const fresh = readLog(st.errFile).slice(logStart).split('\n').filter((l) => /⨯|\bError\b|unhandled/i.test(l));
    out.push({ name: 'no server errors logged during checks', pass: fresh.length === 0, detail: fresh.slice(0, 2).join(' | ').slice(0, 300) || 'ok' });
    return out;
  },

  logTail(ctx) {
    const st = state(ctx);
    return [st.buildOut && `--- next build ---\n${tail(st.buildOut, 1500)}`, ctx.lastOutput && `--- npm test ---\n${tail(ctx.lastOutput, 1000)}`,
      st.errFile && `--- server stderr ---\n${tail(readLog(st.errFile), 1000)}`].filter(Boolean).join('\n');
  },

  hotfixHint() { return 'a guard in the route handler (app/**/route.js), a server component, or middleware.js that checks the caller before it reaches the vulnerable package; keep the package itself untouched'; },

  async promote(ctx, actions) {
    const dir = ctx.cfg.projectDir;
    const isGit = sh('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir }).out.trim() === 'true';
    const orig = isGit ? sh('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: dir }).out.trim() : null;
    const r = await npmAdapter.promote(ctx, actions);
    if (isGit && sh('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: dir }).out.trim() === orig && !r.ok) return r;
    let ok = r.ok, details = r.details;
    if (ok) {
      const b = sh('npx', ['--no-install', 'next', 'build'], { cwd: dir, timeout: 15 * 60e3, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1', CI: '1' } });
      if (b.code !== 0) { ok = false; details = `next build failed on the promotion branch: ${tail(b.out + b.err, 300)}`; }
      else details += '; next build passed';
    }
    if (!ok && isGit) {
      // roll back: leave the project on its original branch and drop the failed autopatch branch
      const cur = sh('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: dir }).out.trim();
      sh('git', ['checkout', '-f', orig], { cwd: dir });
      if (cur !== orig && cur.startsWith('autopatch/')) sh('git', ['branch', '-D', cur], { cwd: dir });
      if (fs.existsSync(path.join(dir, 'package-lock.json'))) sh('npm', ['ci', '--no-audit', '--no-fund'], { cwd: dir, timeout: 15 * 60e3 });
      details = `${details}; rolled back to ${orig}`;
    }
    return { ok, details };
  },
};

export default nextjsAdapter;
