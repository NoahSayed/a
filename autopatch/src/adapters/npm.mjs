// npm adapter: Node apps and libraries. Findings come from `npm audit` (GitHub advisory DB) plus local OSV
// files; checks are the project's own tests plus a re-audit; promotion lands on a new git branch.
import fs from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { sh, copyTree } from '../util.mjs';
import { osvRecord, kevSet, localOsv, cvssFromVector } from '../feeds.mjs';

function readJson(p, d = {}) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return d; } }

export function installedVersion(dir, pkg) {
  const lock = readJson(path.join(dir, 'package-lock.json'));
  return lock.packages?.[`node_modules/${pkg}`]?.version || readJson(path.join(dir, 'node_modules', pkg, 'package.json')).version || null;
}

function versionsOf(ctx, pkg) {
  const r = sh('npm', ['view', pkg, 'versions', '--json'], { cwd: ctx.cfg.projectDir });
  try { return [].concat(JSON.parse(r.out)); } catch { return []; }
}

function releaseAgeDays(ctx, pkg, version) {
  const r = sh('npm', ['view', `${pkg}@${version}`, 'time', '--json'], { cwd: ctx.cfg.projectDir });
  try { const t = JSON.parse(r.out)[version]; return t ? Math.floor((Date.now() - Date.parse(t)) / 864e5) : null; } catch { return null; }
}

/** OSV "affected" ranges -> list of semver range strings */
function osvRanges(aff) {
  const out = [];
  for (const r of aff.ranges || []) {
    let lo = null;
    for (const e of r.events || []) {
      if (e.introduced !== undefined) lo = e.introduced === '0' ? '0.0.0' : e.introduced;
      if (e.fixed !== undefined) { out.push(`>=${lo || '0.0.0'} <${e.fixed}`); lo = null; }
      if (e.last_affected !== undefined) { out.push(`>=${lo || '0.0.0'} <=${e.last_affected}`); lo = null; }
    }
    if (lo) out.push(`>=${lo}`);
  }
  for (const v of aff.versions || []) out.push(v);
  return out;
}

export const npmAdapter = {
  name: 'npm',
  hasServer: false,

  async findings(ctx) {
    const { cfg } = ctx;
    const dir = cfg.projectDir;
    const r = sh('npm', ['audit', '--json'], { cwd: dir });
    let a = {};
    try { a = JSON.parse(r.out); } catch { ctx.log.info('npm audit produced no JSON; is there a package-lock.json?'); }
    // group advisories by package
    const byPkg = new Map();
    for (const [pkg, v] of Object.entries(a.vulnerabilities || {})) {
      for (const x of v.via.filter((x) => typeof x === 'object')) {
        const id = x.url?.split('/').pop() || String(x.source);
        if (!byPkg.has(pkg)) byPkg.set(pkg, []);
        byPkg.get(pkg).push({ id, title: x.title, range: x.range, severity: x.severity, cvss: { score: x.cvss?.score ?? null, ...cvssFromVector(x.cvss?.vectorString) }, source: 'npm-audit' });
      }
    }
    // local OSV advisories (private / internal packages the public DB does not know)
    for (const rec of localOsv(cfg)) {
      for (const aff of (rec.affected || []).filter((x) => (x.package?.ecosystem || 'npm').toLowerCase() === 'npm')) {
        const pkg = aff.package.name;
        const inst = installedVersion(dir, pkg);
        const ranges = osvRanges(aff);
        if (!inst || !ranges.some((rg) => semver.satisfies(inst, rg, { includePrerelease: true }))) continue;
        const vec = (rec.severity || []).find((s) => /CVSS/.test(s.type))?.score;
        if (!byPkg.has(pkg)) byPkg.set(pkg, []);
        byPkg.get(pkg).push({ id: rec.id, title: rec.summary || rec.id, range: ranges.join(' || '), severity: rec.database_specific?.severity || null, cvss: { score: rec.database_specific?.cvss_score ?? null, ...cvssFromVector(vec) }, details: rec.details, aliases: rec.aliases || [], localFix: rec.database_specific?.fixed_release || null, source: 'local' });
      }
    }
    const kev = kevSet(ctx);
    const out = [];
    for (const [pkg, advs] of byPkg) {
      const installed = installedVersion(dir, pkg);
      if (!installed) continue;
      for (const adv of advs) {
        if (adv.source === 'npm-audit') {
          const osv = osvRecord(ctx, 'npm', adv.id);
          adv.aliases = (osv?.aliases || []).filter((x) => x.startsWith('CVE-'));
          adv.details = osv?.details || '';
        }
        adv.exploited = (adv.aliases || []).some((c) => kev.has(c));
      }
      // smallest version that clears ALL known advisories for this package (website lab lesson)
      let fix = null;
      const local = advs.find((x) => x.localFix);
      if (local) fix = { version: local.localFix.version, tarball: local.localFix.tarball ? path.resolve(dir, local.localFix.tarball) : null };
      else {
        // Prefer staying on the installed major: the smallest same-major version that clears the most advisories
        // (ideally all). Only if the same major line clears none, fall back to the smallest version that clears all.
        const vs = versionsOf(ctx, pkg).filter((v) => semver.valid(v) && !semver.prerelease(v) && semver.gt(v, installed)).sort(semver.compare);
        const cleared = (v) => advs.filter((x) => !x.range || !semver.satisfies(v, x.range)).length;
        const same = vs.filter((v) => semver.major(v) === semver.major(installed));
        let best = null;
        for (const v of same) if (cleared(v) > (best ? cleared(best) : 0)) best = v;
        const all = vs.find((v) => cleared(v) === advs.length);
        if (best && (cleared(best) === advs.length || !all || semver.major(all) !== semver.major(installed))) {
          fix = { version: best };
          const left = advs.filter((x) => x.range && semver.satisfies(best, x.range)).map((x) => x.id);
          if (left.length) { fix.residual = left; fix.majorOption = all || null; }
        } else if (all) fix = { version: all };
      }
      if (fix) { fix.major = semver.major(fix.version) !== semver.major(installed); fix.ageDays = fix.tarball ? null : releaseAgeDays(ctx, pkg, fix.version); }
      const worst = advs.reduce((m, x) => ((x.cvss.score ?? 0) > (m.cvss.score ?? 0) ? x : m), advs[0]);
      out.push({
        id: worst.id, ids: advs.map((x) => x.id), aliases: [...new Set(advs.flatMap((x) => x.aliases || []))], pkg, installed,
        title: advs.length > 1 ? `${advs.length} advisories, worst: ${worst.title}` : worst.title,
        description: advs.map((x) => `${x.id}: ${x.title}\n${(x.details || '').slice(0, 1500)}`).join('\n\n'),
        severity: worst.severity, cvss: worst.cvss, unauth: advs.some((x) => x.cvss.unauth === true) ? true : advs.every((x) => x.cvss.unauth === false) ? false : null,
        exploited: advs.some((x) => x.exploited), active: true, fix,
      });
    }
    return out;
  },

  async fetchRelease(ctx, f) {
    const rel = path.join(ctx.workDir, 'releases', `${f.pkg.replace(/[@/]/g, '_')}`);
    fs.rmSync(rel, { recursive: true, force: true });
    fs.mkdirSync(rel, { recursive: true });
    const unpack = (spec, name) => {
      const d = path.join(rel, name);
      fs.mkdirSync(d, { recursive: true });
      let tgz = spec;
      if (!fs.existsSync(spec)) {
        const p = sh('npm', ['pack', spec, '--silent', '--pack-destination', rel], { cwd: rel });
        if (p.code !== 0) return null;
        tgz = path.join(rel, p.out.trim().split('\n').pop());
      }
      sh('tar', ['xzf', tgz, '-C', d]);
      return d;
    };
    const oldSpec = installedTarball(ctx.cfg.projectDir, f.pkg) || `${f.pkg}@${f.installed}`;
    const oldDir = unpack(oldSpec, 'old');
    const newDir = unpack(f.fix.tarball || `${f.pkg}@${f.fix.version}`, 'new');
    if (!oldDir || !newDir) return { reason: 'could not download both versions' };
    const changelog = ['CHANGELOG.md', 'package/CHANGELOG.md', 'package/HISTORY.md'].map((p) => path.join(newDir, p)).find((p) => fs.existsSync(p));
    return { oldDir, newDir, notes: [f.description, changelog ? fs.readFileSync(changelog, 'utf8').slice(0, 4000) : ''].join('\n\n') };
  },

  async prepareStaging(ctx, from, to) {
    copyTree(from, to, { skip: ['.git', '.next', '.autopatch'] });
    if (!fs.existsSync(path.join(to, 'node_modules')) && fs.existsSync(path.join(to, 'package-lock.json'))) {
      const r = sh('npm', ['ci', '--no-audit', '--no-fund'], { cwd: to });
      if (r.code !== 0) throw new Error(`npm ci failed in staging: ${r.err.slice(-500)}`);
    }
  },

  async applyAction(ctx, dir, a) {
    if (a.kind === 'update') {
      const pj = readJson(path.join(dir, 'package.json'));
      const direct = ['dependencies', 'devDependencies', 'optionalDependencies'].some((k) => pj[k]?.[a.pkg]);
      if (!direct && !a.tarball) {
        // transitive package (e.g. next's postcss): pin it with an npm "overrides" entry instead of adding a direct dependency
        pj.overrides = { ...(pj.overrides || {}), [a.pkg]: a.version };
        fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pj, null, 2) + '\n');
        const r = sh('npm', ['install', '--no-audit', '--no-fund'], { cwd: dir });
        return { ok: r.code === 0, log: r.out + r.err };
      }
      const spec = a.tarball || `${a.pkg}@${a.version}`;
      const r = sh('npm', ['install', spec, '--save-exact', '--no-audit', '--no-fund'], { cwd: dir });
      return { ok: r.code === 0, log: r.out + r.err };
    }
    if (a.kind === 'files') {
      for (const [rel, content] of Object.entries(a.files)) {
        const p = path.join(dir, rel);
        if (content === null) fs.rmSync(p, { force: true });
        else { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content); }
      }
      return { ok: true };
    }
    return { ok: false, log: `unsupported action ${a.kind}` };
  },

  async restart() {}, async stop() {},

  async checks(ctx, dir, { findingKeys = [] } = {}) {
    const out = [];
    const pj = readJson(path.join(dir, 'package.json'));
    const testCmd = ctx.cfg.checks.test || (pj.scripts?.test && !/no test specified/.test(pj.scripts.test) ? 'npm test' : null);
    if (testCmd) {
      const r = sh('bash', ['-c', testCmd], { cwd: dir, timeout: 15 * 60e3 });
      ctx.lastOutput = (r.out + r.err).slice(-4000);
      out.push({ name: 'tests pass', pass: r.code === 0, detail: r.code === 0 ? 'ok' : ctx.lastOutput.slice(-400) });
    }
    if (findingKeys.length) {
      const a = JSON.parse(sh('npm', ['audit', '--json'], { cwd: dir }).out || '{}');
      const still = Object.entries(a.vulnerabilities || {}).flatMap(([, v]) => v.via.filter((x) => typeof x === 'object').map((x) => x.url?.split('/').pop()));
      const ids = findingKeys.filter((k) => /^GHSA-/.test(k));
      if (ids.length) out.push({ name: `advisory cleared: ${ids.join(',')}`, pass: !ids.some((i) => still.includes(i)), detail: ids.filter((i) => still.includes(i)).join(',') || 'cleared' });
    }
    const base = readJson(path.join(ctx.cfg.projectDir, 'package.json'));
    const sameDeps = (k) => JSON.stringify(Object.keys(pj[k] || {}).sort()) === JSON.stringify(Object.keys(base[k] || {}).sort());
    out.push({ name: 'dependency set unchanged', pass: sameDeps('dependencies') && sameDeps('devDependencies'), detail: 'only versions may change' });
    const scriptsChanged = [...new Set([...Object.keys(pj.scripts || {}), ...Object.keys(base.scripts || {})])].filter((k) => (pj.scripts || {})[k] !== (base.scripts || {})[k]);
    out.push({ name: 'package scripts unchanged', pass: scriptsChanged.length === 0, detail: scriptsChanged.join(',') || 'ok' });
    return out;
  },

  logTail(ctx) { return ctx.lastOutput || ''; },

  async promote(ctx, actions) {
    const dir = ctx.cfg.projectDir;
    const isGit = sh('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir }).out.trim() === 'true';
    if (isGit) {
      if (sh('git', ['status', '--porcelain'], { cwd: dir }).out.trim()) return { ok: false, details: 'working tree has uncommitted changes; commit or stash first' };
      const branch = `autopatch/${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}`;
      sh('git', ['checkout', '-b', branch], { cwd: dir });
      for (const a of actions) { const r = await npmAdapter.applyAction(ctx, dir, a); if (!r.ok) return { ok: false, details: `apply failed on ${branch}: ${r.log?.slice(-300)}` }; }
      const checks = await npmAdapter.checks(ctx, dir, {});
      if (!checks.every((c) => c.pass)) return { ok: false, details: `checks failed on ${branch}: ${checks.filter((c) => !c.pass).map((c) => c.name).join(', ')}` };
      sh('git', ['add', '-A'], { cwd: dir });
      sh('git', ['commit', '-qm', `autopatch: ${actions.map((a) => (a.kind === 'update' ? `${a.pkg}@${a.version}` : `fix for ${a.finding}`)).join(', ')}`], { cwd: dir });
      return { ok: true, details: `committed on new branch ${branch}; open a PR from it` };
    }
    const backup = path.join(ctx.workDir, 'project-backup');
    copyTree(dir, backup, { skip: ['.git'] });
    for (const a of actions) await npmAdapter.applyAction(ctx, dir, a);
    const checks = await npmAdapter.checks(ctx, dir, {});
    if (!checks.every((c) => c.pass)) { copyTree(backup, dir, { skip: [] }); return { ok: false, details: 'checks failed after promotion; restored backup' }; }
    return { ok: true, details: `applied in place (backup at ${backup})` };
  },
};

function installedTarball(dir, pkg) {
  const spec = readJson(path.join(dir, 'package.json')).dependencies?.[pkg] || '';
  return spec.startsWith('file:') ? path.resolve(dir, spec.slice(5)) : null;
}

export default npmAdapter;
