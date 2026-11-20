// WordPress adapter. Ideas proven in the WordPress lab:
//  - findings: `wp plugin list` matched against a Wordfence-Intelligence-v3-shaped feed (affected_versions ranges)
//  - fix = the smallest patched version that clears ALL advisories for a plugin, from a plugin zip
//  - staging = a copy of the site on its own port; PHP restarted after every change
//  - only PHP fatals logged DURING a check run count; plugin files must match an official release byte-for-byte;
//    no new admins; wp-config.php unchanged; no dangerous code in site-owned paths
//  - no fix? the pipeline asks the AI for a must-use plugin hotfix (wp-content/mu-plugins/hotfix-<slug>.php)
//  - promote = back up production, replay the update with WP-CLI, write only the owned files, restart, smoke check,
//    roll back on failure. The staging database is never copied to production.
//
// cfg.server:
//   wpCli         path to wp-cli.phar (run with php) or to a `wp` executable                       (required)
//   port          staging port                                                                     (8300)
//   prodPort      production port; when set, promote restarts php-builtin there and smoke-checks    (optional)
//   serve         'php-builtin' (php -S) | 'none' (an external server serves the staging dir)       ('php-builtin')
//   restartCmd    shell command run to (re)start PHP when serve is 'none' (env AUTOPATCH_DIR/PORT)  (optional)
//   logFile       PHP error log, relative to the site dir                                           ('wp-content/debug.log')
//   wordfenceFeed path to a v3-shaped JSON file, or 'remote' (env WORDFENCE_API_KEY)
//   releases      directory of plugin zips named <slug>.<version>.zip (else downloads.wordpress.org)
//   staging.dbMode 'file-copy' (SQLite, default) | 'mysql-export' (TODO, throws)
//
// Probes are scripts (see src/httpchecks.mjs): `node <script> <baseUrl>`, exit 0 = still vulnerable. This adapter
// sets AUTOPATCH_SITE_DIR (the dir being probed), AUTOPATCH_WPCLI and AUTOPATCH_PORT in the environment so a probe
// can read or restore an option with WP-CLI on THAT dir.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { sh, listFiles, hashDir, matchGlob, vcmp, sleep } from '../util.mjs';
import { kevSet, cvssFromVector, cacheDir } from '../feeds.mjs';
import { runPages, runFlows, runProbes } from '../httpchecks.mjs';

const DOWNLOAD = (slug, v) => `https://downloads.wordpress.org/plugin/${slug}.${v}.zip`;
const WORDFENCE_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
const DANGEROUS = [
  ['eval', /\beval\s*\(/], ['base64_decode', /base64_decode\s*\(/], ['gzinflate', /gzinflate\s*\(/],
  ['user creation', /wp_(insert|create)_user\s*\(/], ['role changes', /\badd_role\s*\(|\bset_role\s*\(/],
  ['remote calls', /wp_remote_(get|post|request|head)\s*\(|curl_exec\s*\(|file_get_contents\s*\(\s*['"]https?:/],
  ['shell', /\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|\bexec\s*\(/],
];

// ---------------------------------------------------------------- helpers
const srv = (ctx) => {
  const s = ctx.cfg.server || {};
  return {
    wpCli: s.wpCli ? path.resolve(ctx.cfg.projectDir, s.wpCli) : null,
    port: s.port ?? 8300, prodPort: s.prodPort ?? null, serve: s.serve || 'php-builtin', restartCmd: s.restartCmd || null,
    logFile: s.logFile || 'wp-content/debug.log', feed: s.wordfenceFeed || null,
    releases: s.releases ? path.resolve(ctx.cfg.projectDir, s.releases) : null,
    dbMode: s.staging?.dbMode || 'file-copy',
  };
};

function wp(ctx, dir, args, port) {
  const s = srv(ctx);
  if (!s.wpCli) throw new Error('wordpress adapter: set server.wpCli to the path of wp-cli.phar');
  const isPhar = s.wpCli.endsWith('.phar');
  const pre = [...(isPhar ? [s.wpCli] : []), ...(process.getuid?.() === 0 ? ['--allow-root'] : []), `--path=${dir}`];
  return sh(isPhar ? 'php' : s.wpCli, [...pre, ...args], { env: { ...process.env, LAB_PORT: String(port ?? s.port), AUTOPATCH_PORT: String(port ?? s.port) }, timeout: 120000 });
}

function parseJson(text, fallback) {
  const i = text.search(/^[[{]/m); // tolerate PHP notices printed before the JSON
  try { return JSON.parse(i >= 0 ? text.slice(i) : text); } catch { return fallback; }
}
const portFor = (ctx, dir) => (path.resolve(dir) === ctx.cfg.projectDir && srv(ctx).prodPort ? srv(ctx).prodPort : srv(ctx).port);
const readText = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const logSize = (ctx, dir) => { try { return fs.statSync(path.join(dir, srv(ctx).logFile)).size; } catch { return 0; } };
const logSince = (ctx, dir, offset) => { try { return fs.readFileSync(path.join(dir, srv(ctx).logFile)).subarray(offset).toString('utf8'); } catch { return ''; } };
const inside = (child, parent) => child === parent || child.startsWith(parent + path.sep);

function inventory(ctx, dir, port) {
  const r = wp(ctx, dir, ['plugin', 'list', '--fields=name,status,version', '--format=json'], port);
  return parseJson(r.out, []).filter((p) => !['dropin'].includes(p.status));
}

// ---------------------------------------------------------------- feed
function wordfenceRecords(ctx) {
  const s = srv(ctx);
  const maps = [];
  const load = (text, label) => { try { maps.push(JSON.parse(text)); } catch { ctx.log.info(`wordpress: could not parse advisory feed ${label}`); } };
  for (const f of [].concat(s.feed && s.feed !== 'remote' ? s.feed : [])) {
    const p = path.resolve(ctx.cfg.projectDir, f);
    if (fs.existsSync(p)) load(fs.readFileSync(p, 'utf8'), p); else ctx.log.info(`wordpress: feed ${p} not found`);
  }
  if (s.feed === 'remote') {
    const key = process.env.WORDFENCE_API_KEY;
    if (!key) ctx.log.info('wordpress: wordfenceFeed is "remote" but WORDFENCE_API_KEY is not set');
    else {
      fs.mkdirSync(ctx.workDir, { recursive: true });
      const hdr = path.join(ctx.workDir, '.wf-header'); // keep the key out of argv / ps
      fs.writeFileSync(hdr, `Authorization: Bearer ${key}\n`, { mode: 0o600 });
      const r = sh('curl', ['-sfL', '-m', '120', '-H', `@${hdr}`, WORDFENCE_URL]);
      fs.rmSync(hdr, { force: true });
      if (r.code === 0) load(r.out, 'remote'); else ctx.log.info(`wordpress: Wordfence feed request failed (curl exit ${r.code})`);
    }
  }
  for (const f of ctx.cfg.feeds?.local || []) { // Wordfence-shaped local files only; OSV files are ignored here
    const p = path.resolve(ctx.cfg.projectDir, f);
    if (!fs.existsSync(p)) continue;
    try { const j = JSON.parse(fs.readFileSync(p, 'utf8')); if (j && !Array.isArray(j) && Object.values(j).some((r) => r?.software)) maps.push(j); } catch { /* not ours */ }
  }
  const byId = new Map();
  for (const m of maps) for (const r of Object.values(m)) if (r && typeof r === 'object' && Array.isArray(r.software) && r.informational !== true) byId.set(r.id || r.title, r);
  return [...byId.values()];
}

function affected(version, ranges = {}) {
  return Object.values(ranges).some((r) => (r.from_version === '*' || vcmp(version, r.from_version) >= (r.from_inclusive ? 0 : 1))
    && (r.to_version === '*' || vcmp(version, r.to_version) <= (r.to_inclusive ? 0 : -1)));
}

// ---------------------------------------------------------------- releases (zips)
function zipSource(ctx, slug, version) {
  const s = srv(ctx);
  if (s.releases) { const p = path.join(s.releases, `${slug}.${version}.zip`); return fs.existsSync(p) ? p : null; }
  return DOWNLOAD(slug, version);
}

/** A local zip path for slug@version (downloading and caching it when needed), or null. */
function localZip(ctx, slug, version, given) {
  let src = given || zipSource(ctx, slug, version);
  if (!src) return null;
  if (!/^https?:/.test(src)) return fs.existsSync(src) ? src : null;
  const dest = path.join(cacheDir(ctx), 'releases', `${slug}.${version}.zip`);
  if (fs.existsSync(dest)) return dest;
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const r = sh('curl', ['-sfL', '-m', '180', '-o', dest, src]);
  if (r.code !== 0 || !fs.existsSync(dest)) { fs.rmSync(dest, { force: true }); return null; }
  return dest;
}

function unzipTo(zip, dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return sh('unzip', ['-q', '-o', zip, '-d', dir]).code === 0;
}
const pluginRoot = (dir, slug) => (fs.existsSync(path.join(dir, slug)) ? path.join(dir, slug)
  : (fs.readdirSync(dir).length === 1 ? path.join(dir, fs.readdirSync(dir)[0]) : dir));

const hashCache = new Map();
/** Byte-for-byte hashes of every official release zip we know for this plugin. */
function officialHashes(ctx, slug, installedVersion) {
  const s = srv(ctx);
  const zips = new Set();
  const dirs = [s.releases, path.join(cacheDir(ctx), 'releases')].filter((d) => d && fs.existsSync(d));
  for (const d of dirs) for (const f of fs.readdirSync(d)) if (f.startsWith(`${slug}.`) && new RegExp(`^${slug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.\\d+(\\.\\d+)*\\.zip$`).test(f)) zips.add(path.join(d, f));
  if (!zips.size && !s.releases && installedVersion) { const z = localZip(ctx, slug, installedVersion); if (z) zips.add(z); }
  const out = new Set();
  for (const z of zips) {
    const key = `${z}:${fs.statSync(z).mtimeMs}`;
    if (!hashCache.has(key)) {
      const tmp = path.join(ctx.workDir, '_hash', slug);
      hashCache.set(key, unzipTo(z, tmp) ? hashDir(pluginRoot(tmp, slug)) : null);
    }
    if (hashCache.get(key)) out.add(hashCache.get(key));
  }
  return out;
}

// ---------------------------------------------------------------- server control
async function waitUp(port, ms = 15000) {
  for (let t = 0; t < ms; t += 100) {
    try { await fetch(`http://127.0.0.1:${port}/wp-login.php`, { redirect: 'manual', signal: AbortSignal.timeout(3000) }); return true; } catch { await sleep(100); }
  }
  return false;
}
async function waitDown(port, ms = 5000) {
  for (let t = 0; t < ms; t += 100) {
    try { await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(500) }); await sleep(100); } catch { return; }
  }
}
function killPhp(port) { sh('pkill', ['-f', `php -S 127.0.0.1:${port} `]); }

async function startPhp(ctx, dir, port) {
  const s = srv(ctx);
  killPhp(port);
  await waitDown(port);
  if (s.serve === 'php-builtin') {
    fs.mkdirSync(ctx.workDir, { recursive: true });
    const fd = fs.openSync(path.join(ctx.workDir, `php-${port}.log`), 'a');
    const p = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', dir], { stdio: ['ignore', fd, fd], detached: true, env: { ...process.env, LAB_PORT: String(port) } });
    p.unref();
  } else if (s.restartCmd) {
    const r = sh('bash', ['-c', s.restartCmd], { env: { ...process.env, AUTOPATCH_DIR: dir, AUTOPATCH_PORT: String(port) } });
    if (r.code !== 0) throw new Error(`restartCmd failed: ${(r.err || r.out).slice(-300)}`);
  }
  if (!(await waitUp(port))) throw new Error(`site did not answer on port ${port}`);
}

function withProbeEnv(ctx, dir, port, fn) {
  const keep = { d: process.env.AUTOPATCH_SITE_DIR, w: process.env.AUTOPATCH_WPCLI, p: process.env.AUTOPATCH_PORT };
  process.env.AUTOPATCH_SITE_DIR = dir; process.env.AUTOPATCH_WPCLI = srv(ctx).wpCli || ''; process.env.AUTOPATCH_PORT = String(port);
  try { return fn(); } finally {
    for (const [k, v] of [['AUTOPATCH_SITE_DIR', keep.d], ['AUTOPATCH_WPCLI', keep.w], ['AUTOPATCH_PORT', keep.p]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

// ---------------------------------------------------------------- owned code
function ownedFiles(cfg, dir) {
  const seen = new Set();
  for (const g of cfg.ownedPaths) {
    const segs = g.split('/');
    const base = segs.slice(0, Math.max(0, segs.findIndex((x) => x.includes('*')) === -1 ? segs.length - 1 : segs.findIndex((x) => x.includes('*')))).join('/');
    for (const f of listFiles(path.join(dir, base))) { const rel = base ? `${base}/${f}` : f; if (matchGlob(rel, g)) seen.add(rel); }
  }
  return [...seen].filter((f) => !cfg.protectedPaths.some((g) => matchGlob(f, g))).sort();
}

// ---------------------------------------------------------------- the adapter
const wordpressAdapter = {
  name: 'wordpress',
  hasServer: true,
  // files the checks write to (SQLite DB) must not count as "the AI changed files outside its allowed paths"
  diffIgnore: ['.ht.sqlite', '.ht.sqlite-wal', '.ht.sqlite-shm', '.ht.sqlite-journal', 'php-server.log'],

  async findings(ctx) {
    const { cfg } = ctx;
    const dir = cfg.projectDir;
    const inv = inventory(ctx, dir, srv(ctx).prodPort ?? srv(ctx).port);
    const recs = wordfenceRecords(ctx);
    const kev = kevSet(ctx);
    const bySlug = new Map();
    for (const rec of recs) {
      for (const sw of rec.software.filter((x) => x.type === 'plugin')) {
        const p = inv.find((x) => x.name === sw.slug);
        if (!p || !affected(p.version, sw.affected_versions)) continue;
        if (!bySlug.has(sw.slug)) bySlug.set(sw.slug, { p, hits: [] });
        bySlug.get(sw.slug).hits.push({ rec, sw });
      }
    }
    const out = [];
    for (const [slug, { p, hits }] of bySlug) {
      // smallest available patched version that clears ALL advisories for this plugin
      const cands = [...new Set(hits.flatMap((h) => h.sw.patched_versions || []))].filter((v) => vcmp(v, p.version) > 0).sort(vcmp);
      let fix = null;
      for (const v of cands) {
        if (hits.some((h) => affected(v, h.sw.affected_versions))) continue;
        const zip = zipSource(ctx, slug, v);
        if (!zip) continue; // patched upstream but no zip available to us
        // ageDays is unknown: WordPress.org does not expose per-version release dates, so no cooldown applies
        fix = { version: v, major: parseInt(v, 10) !== parseInt(p.version, 10), ageDays: null, zip, tarball: zip };
        break;
      }
      const cvss = (h) => ({ score: h.rec.cvss?.score ?? null, ...cvssFromVector(h.rec.cvss?.vector) });
      const worst = hits.reduce((m, h) => ((cvss(h).score ?? 0) > (cvss(m).score ?? 0) ? h : m), hits[0]);
      const cves = [...new Set(hits.map((h) => h.rec.cve).filter(Boolean))];
      const unauths = hits.map((h) => cvss(h).unauth);
      out.push({
        id: worst.rec.id, ids: hits.map((h) => h.rec.id), aliases: cves, pkg: slug, installed: p.version,
        title: hits.length > 1 ? `${hits.length} advisories, worst: ${worst.rec.title}` : worst.rec.title,
        description: hits.map((h) => `${h.rec.id}: ${h.rec.title}\n${(h.rec.description || '').slice(0, 1500)}`).join('\n\n'),
        severity: String(worst.rec.cvss?.rating || '').toLowerCase() || null, cvss: cvss(worst),
        unauth: unauths.some((u) => u === true) ? true : unauths.every((u) => u === false) ? false : null,
        exploited: cves.some((c) => kev.has(c)), active: /^active/.test(p.status) || p.status === 'must-use', fix,
      });
    }
    return out;
  },

  async fetchRelease(ctx, f) {
    const root = path.join(ctx.workDir, 'releases', f.pkg);
    fs.rmSync(root, { recursive: true, force: true });
    const installed = path.join(ctx.cfg.projectDir, 'wp-content/plugins', f.pkg);
    const zip = localZip(ctx, f.pkg, f.fix.version, f.fix.zip);
    if (!zip || !fs.existsSync(installed)) return { reason: `could not get the ${f.pkg} ${f.fix.version} zip or the installed copy` };
    const oldDir = path.join(root, 'old');
    fs.mkdirSync(path.join(oldDir, f.pkg), { recursive: true });
    fs.cpSync(installed, path.join(oldDir, f.pkg), { recursive: true }); // the installed copy IS the old release
    const newDir = path.join(root, 'new');
    if (!unzipTo(zip, newDir)) return { reason: 'could not unzip the fix release' };
    const readme = readText(path.join(pluginRoot(newDir, f.pkg), 'readme.txt'));
    const m = readme.match(/==\s*Changelog\s*==([\s\S]*?)(?:\n==[^=]|$)/i);
    return { oldDir, newDir, notes: [f.description, m ? m[1].trim().slice(0, 4000) : readme.slice(0, 2000)].join('\n\n') };
  },

  async prepareStaging(ctx, from, to) {
    const s = srv(ctx);
    if (s.dbMode === 'mysql-export') {
      // TODO(mysql-export): `wp db export` from production, create/import into `staging.dbName`, point the staging
      // wp-config at it, then `wp search-replace <prod url> http://127.0.0.1:<port> --all-tables`. Not implemented.
      throw new Error('wordpress adapter: staging.dbMode "mysql-export" is not implemented yet (TODO); use "file-copy" (SQLite)');
    }
    if (!to || !path.isAbsolute(to)) throw new Error(`refusing to prepare staging at "${to}"`);
    fs.rmSync(to, { recursive: true, force: true });
    const skipWork = !inside(path.resolve(from), ctx.workDir); // production must not copy the scratch dir into itself
    fs.cpSync(from, to, { recursive: true, filter: (src) => !['.git', '.autopatch'].includes(path.basename(src)) && !(skipWork && inside(path.resolve(src), ctx.workDir)) });
    fs.mkdirSync(path.dirname(path.join(to, s.logFile)), { recursive: true });
    fs.writeFileSync(path.join(to, s.logFile), '');
  },

  async applyAction(ctx, dir, a) {
    const port = portFor(ctx, dir);
    if (a.kind === 'update') {
      const zip = localZip(ctx, a.pkg, a.version, a.zip || a.tarball);
      if (!zip) return { ok: false, log: `no zip available for ${a.pkg} ${a.version}` };
      const r = wp(ctx, dir, ['plugin', 'install', zip, '--force'], port);
      return { ok: r.code === 0, log: r.out + r.err };
    }
    if (a.kind === 'deactivate') {
      const r = wp(ctx, dir, ['plugin', 'deactivate', a.pkg], port);
      return { ok: r.code === 0, log: r.out + r.err };
    }
    if (a.kind === 'files') {
      for (const [rel, content] of Object.entries(a.files)) {
        const p = path.resolve(dir, rel);
        if (!inside(p, path.resolve(dir))) return { ok: false, log: `path escapes the site: ${rel}` };
        if (content === null) fs.rmSync(p, { force: true });
        else { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content); }
      }
      return { ok: true };
    }
    return { ok: false, log: `unsupported action ${a.kind}` };
  },

  async restart(ctx, dir) { ctx._dir = dir; await startPhp(ctx, dir, srv(ctx).port); },
  async stop(ctx) {
    const s = srv(ctx);
    if (s.serve !== 'php-builtin') return; // an external server is not ours to stop
    killPhp(s.port);
    await waitDown(s.port);
  },

  async checks(ctx, dir, { findingKeys = [], phase = 'any', jar = {} } = {}) {
    const { cfg } = ctx;
    const s = srv(ctx);
    const base = `http://127.0.0.1:${s.port}`;
    const out = [];
    const add = (name, pass, detail = '') => out.push({ name, pass: Boolean(pass), detail: String(detail).slice(0, 300) });
    const offset = logSize(ctx, dir); // only PHP errors logged from here on count

    out.push(...await runPages(base, cfg.checks.pages || []));
    const flows = cfg.checks.flows || [];
    out.push(...await runFlows(base, flows, { phase: 'any', jar }));
    if (phase !== 'any') out.push(...await runFlows(base, flows, { phase, jar }));
    if (findingKeys.length && (cfg.checks.probes || []).length) {
      out.push(...withProbeEnv(ctx, dir, s.port, () => runProbes(base, cfg.checks.probes, cfg.projectDir, findingKeys)));
    }
    const fatals = logSince(ctx, dir, offset).split('\n').filter((l) => /PHP (Fatal|Parse) error/.test(l));
    add('no PHP fatal errors during checks', fatals.length === 0, fatals.slice(-2).join(' | '));
    ctx.lastLogTail = fatals.join('\n');

    // ---- integrity: third-party code untouched, no new admins, config unchanged, no dangerous owned code
    for (const p of inventory(ctx, dir, s.port)) {
      if (p.status === 'must-use') continue;
      const d = path.join(dir, 'wp-content/plugins', p.name);
      if (!fs.existsSync(d) || !fs.statSync(d).isDirectory()) continue;
      const official = officialHashes(ctx, p.name, p.version);
      if (!official.size) continue; // nothing to compare against
      add(`plugin files untouched: ${p.name}`, official.has(hashDir(d)), 'must match an official release byte-for-byte');
    }
    const admins = (a) => parseJson(wp(ctx, a, ['user', 'list', '--role=administrator', '--field=user_login', '--format=json'], portFor(ctx, a)).out, []).sort();
    ctx._admins ??= admins(cfg.projectDir); // snapshot of production, taken once
    const now = admins(dir);
    add('only the expected administrators', JSON.stringify(now) === JSON.stringify(ctx._admins), `now: ${now.join(',')}; expected: ${ctx._admins.join(',')}`);
    add('wp-config.php unchanged', readText(path.join(dir, 'wp-config.php')) === readText(path.join(cfg.projectDir, 'wp-config.php')));
    const bad = ownedFiles(cfg, dir).filter((f) => f.endsWith('.php')).map((f) => [f, DANGEROUS.filter(([, re]) => re.test(readText(path.join(dir, f)))).map(([k]) => k)]).filter(([, k]) => k.length);
    add('no dangerous code in owned paths', bad.length === 0, bad.map(([f, k]) => `${f} (${k.join(', ')})`).join('; '));
    return out;
  },

  logTail(ctx, dir) {
    const lines = readText(path.join(dir, srv(ctx).logFile)).split('\n').filter(Boolean).slice(-15).join('\n');
    return lines || ctx.lastLogTail || '';
  },

  hotfixHint(ctx, f) {
    return `a must-use plugin at wp-content/mu-plugins/hotfix-${f.pkg}.php (create wp-content/mu-plugins if needed). It loads on every request before ${f.pkg}; use add_action/add_filter hooks (e.g. an early 'admin_init'/'init' or a 'wp_ajax_nopriv_*' guard) to refuse the exploit request, and never edit the plugin's own files.`;
  },

  async promote(ctx, actions) {
    const { cfg } = ctx;
    const s = srv(ctx);
    const dir = cfg.projectDir;
    const port = s.prodPort;
    if (!path.isAbsolute(dir) || dir === path.parse(dir).root) return { ok: false, details: `refusing to promote into "${dir}"` };
    const backup = path.join(ctx.workDir, 'production-backup');
    fs.rmSync(backup, { recursive: true, force: true });
    const scratchInside = inside(ctx.workDir, dir); // never copy the scratch dir into its own backup
    fs.cpSync(dir, backup, { recursive: true, filter: (src) => !(scratchInside && inside(path.resolve(src), ctx.workDir)) });
    const rollback = async (why) => {
      if (port && s.serve === 'php-builtin') { killPhp(port); await waitDown(port); }
      for (const e of fs.readdirSync(dir)) if (!inside(ctx.workDir, path.join(dir, e))) fs.rmSync(path.join(dir, e), { recursive: true, force: true });
      for (const e of fs.readdirSync(backup)) fs.cpSync(path.join(backup, e), path.join(dir, e), { recursive: true });
      if (port) { try { await startPhp(ctx, dir, port); } catch { /* the site was restored; the web server needs a human */ } }
      return { ok: false, details: `${why}; rolled back to the backup (${backup})` };
    };

    // replay the accepted actions on production: WP-CLI for plugins, plain file writes for owned paths only
    for (const a of actions) {
      if (a.kind === 'files') for (const rel of Object.keys(a.files)) if (!cfg.ownedPaths.some((g) => matchGlob(rel, g)) || cfg.protectedPaths.some((g) => matchGlob(rel, g))) return rollback(`file ${rel} is outside owned paths`);
      const r = await wordpressAdapter.applyAction(ctx, dir, a);
      if (!r.ok) return rollback(`apply failed (${a.kind} ${a.pkg || ''}): ${(r.log || '').slice(-300)}`);
    }

    if (!port && s.serve === 'php-builtin') return { ok: true, details: `applied, no smoke check (set server.prodPort); backup at ${backup}` };
    const offset = logSize(ctx, dir);
    try { await startPhp(ctx, dir, port || s.port); } catch (e) { return rollback(`restart failed: ${e.message}`); }
    const base = `http://127.0.0.1:${port || s.port}`;
    const keys = [...new Set(actions.flatMap((a) => [a.finding, a.pkg]).filter(Boolean))];
    const results = [
      ...await runPages(base, cfg.checks.pages || []),
      ...await runFlows(base, (cfg.checks.flows || []).filter((f) => f.smoke), { phase: 'any', jar: {} }), // only flows marked "smoke": true; the rest write data
      ...(cfg.checks.probes?.length ? withProbeEnv(ctx, dir, port || s.port, () => runProbes(base, cfg.checks.probes, cfg.projectDir, keys)) : []),
    ];
    const fatals = logSince(ctx, dir, offset).split('\n').filter((l) => /PHP (Fatal|Parse) error/.test(l));
    const failed = results.filter((c) => !c.pass);
    if (failed.length || fatals.length) return rollback(`smoke check failed: ${[...failed.map((c) => `${c.name} (${c.detail})`), ...fatals.slice(-1)].join('; ')}`);
    return { ok: true, details: `smoke check passed on port ${port || s.port}; backup kept at ${backup}` };
  },
};

export default wordpressAdapter;
