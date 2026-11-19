// Website auto-patch pipeline (round 3), staging-first like the WordPress lab:
//   scan (npm audit + local OSV records) -> scope -> smallest fixed version -> release-tarball check
//   -> staging copy (npm ci, build, start) -> baseline checks -> apply -> build/start -> gate
//   -> [AI repair of site code | AI app-level guard when no fix exists] -> gate
//   -> promote by replaying the change on production -> rebuild, restart, smoke -> rollback on failure.
// The AI only ever works on the staging copy and only on site-owned code. Everything that decides is plain code.
import fs from 'node:fs';
import path from 'node:path';
import semver from '../../lab/node_modules/semver/index.js';
import { scan as r1scan, chooseFix as r1chooseFix } from '../../lab/pipeline.mjs'; // round-1 functions: npm audit parsing, smallest fixed version
import { sh, safeRm, copySource, npmCi, build, start, stop, OWNED, REGISTRY, SCRATCH, LAB } from './site.mjs';
import { runChecks } from './checks.mjs';
import { unpack, releaseCheck, releaseNotes } from './release.mjs';

const BAD_ADDED = [/\beval\s*\(/, /\bnew\s+Function\s*\(/, /child_process|\bexecSync\b|\bspawnSync\b|\bexecFile\b/, /JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries)\(\s*process\.env/,
  /(?:fetch|https?\.get|https?\.request|axios\.\w+)\s*\(\s*['"`]https?:\/\/(?!127\.0\.0\.1|localhost)/];

// ---------- 1. scan + scope ----------
function curlCached(url, file) {
  const p = path.join(SCRATCH, 'cache', file);
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const r = sh('curl', ['-sfL', '-m', '30', url]);
  if (r.code !== 0) return null;
  fs.writeFileSync(p, r.out);
  return r.out;
}

function osvRange(affected) {
  const parts = [];
  for (const r of affected.ranges || []) {
    let lo = '>=0.0.0';
    for (const ev of r.events) {
      if ('introduced' in ev) lo = `>=${ev.introduced === '0' ? '0.0.0' : ev.introduced}`;
      if ('fixed' in ev) { parts.push(`${lo} <${ev.fixed}`); lo = null; }
    }
    if (lo) parts.push(lo);
  }
  return parts.join(' || ');
}

const installedVersion = (dir, pkg) => { try { return JSON.parse(fs.readFileSync(path.join(dir, 'node_modules', pkg, 'package.json'), 'utf8')).version; } catch { return null; } };

export function loadFeed() { return JSON.parse(fs.readFileSync(path.join(REGISTRY, 'feed.json'), 'utf8')); }
const registry = () => JSON.parse(fs.readFileSync(path.join(REGISTRY, 'registry.json'), 'utf8'));

/** Findings in scope for this run, each with the smallest fixed version (or null) and the supply-chain facts about it. */
export function findItems(prod, feed) {
  const items = [];
  // real advisories: npm audit, round-1 parser
  const npmFindings = r1scan(prod);
  for (const f of npmFindings) {
    const scoped = f.advisories.filter((a) => feed.inScope.includes(a.ghsa));
    if (!scoped.length) continue;
    const item = { pkg: f.pkg, installed: f.installed, source: 'npm', fictional: false, advisories: scoped, outOfScope: f.advisories.length - scoped.length };
    r1chooseFix(prod, item); // smallest version greater than installed outside every in-scope range; also npm metadata (install scripts, age, publisher)
    items.push(item);
  }
  // local OSV-format records (the fictional internal packages)
  const dir = path.join(REGISTRY, 'advisories');
  const reg = registry();
  for (const file of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const o = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    if (!feed.inScope.includes(o.id)) continue;
    for (const aff of o.affected) {
      const pkg = aff.package.name;
      const installed = installedVersion(prod, pkg);
      const range = osvRange(aff);
      if (!installed || !semver.satisfies(installed, range)) continue;
      let item = items.find((i) => i.pkg === pkg);
      if (!item) { item = { pkg, installed, source: 'local', fictional: true, status: reg[pkg]?.status, advisories: [], outOfScope: 0 }; items.push(item); }
      item.advisories.push({ ghsa: o.id, title: o.summary, range, severity: o.database_specific?.severity || 'moderate', details: o.details });
    }
  }
  for (const item of items.filter((i) => i.source === 'local')) {
    const versions = Object.keys(reg[item.pkg].versions).filter((v) => semver.gt(v, item.installed) && item.advisories.every((a) => !semver.satisfies(v, a.range))).sort(semver.compare);
    const v = versions[0];
    item.fix = v ? { version: v, major: semver.major(v) !== semver.major(item.installed), tarball: path.resolve(REGISTRY, reg[item.pkg].versions[v]) } : null;
  }
  // advisory text from OSV (untrusted; only ever shown to the AI as quoted data)
  for (const item of items) for (const a of item.advisories) {
    if (a.details) continue;
    const osv = curlCached(`https://storage.googleapis.com/osv-vulnerabilities/npm/${a.ghsa}.json`, `${a.ghsa}.json`);
    try { const o = JSON.parse(osv); a.details = (o.details || '').slice(0, 1500); a.cves = (o.aliases || []).filter((x) => x.startsWith('CVE-')); } catch { a.details = ''; a.cves = []; }
  }
  for (const item of items) {
    const rank = { low: 1, moderate: 2, high: 3, critical: 4 };
    const worst = Math.max(...item.advisories.map((a) => rank[a.severity] || 2));
    item.lane = worst >= 4 ? 'fast-track' : worst === 3 ? 'patch-now' : 'routine';
    item.order = !item.fix ? 3 : item.fix.major ? 1 : 0; // patch/minor bumps first, then majors, then "no fix"
  }
  return items.sort((a, b) => a.order - b.order || a.pkg.localeCompare(b.pkg));
}

/** Changelog text for the new release; npm tarballs often ship none, so fall back to the project's own file. */
const CHANGELOG_URLS = { jsonwebtoken: 'https://raw.githubusercontent.com/auth0/node-jsonwebtoken/master/CHANGELOG.md' };
function changelogFor(item, newRoot) {
  let t = releaseNotes(newRoot, item.installed, item.fix.version);
  if (CHANGELOG_URLS[item.pkg] && /^\(README|ships no changelog/.test(t)) {
    const full = curlCached(CHANGELOG_URLS[item.pkg], `changelog-${item.pkg}.md`);
    if (full) {
      const i = full.indexOf(`## ${item.fix.version}`);
      const j = full.indexOf(`## ${item.installed}`);
      t = full.slice(Math.max(i, 0), j > i ? j : i + 3000).slice(0, 3500);
    }
  }
  return t;
}

// ---------- 2. rescan: is the installed version still inside an in-scope advisory's range? ----------
export function rescan(dir, item) {
  const installed = installedVersion(dir, item.pkg);
  const still = item.advisories.filter((a) => installed && semver.satisfies(installed, a.range)).map((a) => a.ghsa);
  let auditStill = [];
  if (item.source === 'npm') {
    const r = sh('npm', ['audit', '--json'], { cwd: dir });
    try { const v = JSON.parse(r.out).vulnerabilities?.[item.pkg]; auditStill = (v?.via || []).filter((x) => typeof x === 'object').map((x) => x.url.split('/').pop()).filter((g) => item.advisories.some((a) => a.ghsa === g)); } catch { /* audit unavailable */ }
  }
  return { installed, stillAffectedBy: [...new Set([...still, ...auditStill])], fixed: still.length === 0 && auditStill.length === 0 };
}

// ---------- 3. integrity of a staging copy against production ----------
function diffFiles(a, b) {
  const r = sh('diff', ['-rq', '-x', 'node_modules', '-x', '.next', '-x', '*.log', '-x', 'check-site.sh', a, b]);
  const files = [];
  for (const line of r.out.split('\n').filter(Boolean)) {
    let m;
    if ((m = line.match(/^Files (.+) and (.+) differ$/))) files.push(path.relative(a, m[1]));
    else if ((m = line.match(/^Only in (.+): (.+)$/))) files.push(path.relative(m[1].startsWith(a) ? a : b, path.join(m[1], m[2])));
  }
  return files;
}

export function integrity(prod, staging, expected) {
  const violations = [];
  const changed = diffFiles(prod, staging);
  const isOwned = (f) => OWNED.some((o) => f === o || f.startsWith(o + '/'));
  for (const f of changed) {
    if (isOwned(f)) continue;
    if (f === 'data/notes.json') continue; // runtime state touched by the flow checks
    if (f === 'package.json' || f === 'package-lock.json') continue; // examined below
    if (f.startsWith('vendor/') && expected?.vendor === f) continue;
    violations.push(`changed outside site code: ${f}`);
  }
  const pj = (d) => JSON.parse(fs.readFileSync(path.join(d, 'package.json'), 'utf8'));
  const a = pj(prod), b = pj(staging);
  const depA = { ...a.dependencies }, depB = { ...b.dependencies };
  if (expected?.pkg) { delete depA[expected.pkg]; delete depB[expected.pkg]; }
  if (JSON.stringify(depA) !== JSON.stringify(depB)) violations.push('dependencies other than the target changed');
  if (JSON.stringify({ ...a, dependencies: 0 }) !== JSON.stringify({ ...b, dependencies: 0 })) violations.push('package.json changed beyond the target dependency (scripts/config)');
  if (expected?.pkg && b.dependencies[expected.pkg] !== expected.spec) violations.push(`${expected.pkg} is ${b.dependencies[expected.pkg]}, expected ${expected.spec}`);
  if (!expected?.pkg && a.dependencies && JSON.stringify(a.dependencies) !== JSON.stringify(b.dependencies)) violations.push('dependencies changed but no bump was intended');
  const hooks = (d) => Object.entries(JSON.parse(fs.readFileSync(path.join(d, 'package-lock.json'), 'utf8')).packages).filter(([, v]) => v.hasInstallScript).map(([k]) => k);
  const ha = new Set(hooks(prod));
  const newHooks = hooks(staging).filter((k) => !ha.has(k));
  if (newHooks.length) violations.push(`new packages with install scripts: ${newHooks.join(', ')}`);
  for (const o of OWNED) {
    if (!fs.existsSync(path.join(staging, o)) && !fs.existsSync(path.join(prod, o))) continue;
    const d = sh('diff', ['-ruN', path.join(prod, o), path.join(staging, o)]).out;
    for (const line of d.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++'))) {
      for (const re of BAD_ADDED) if (re.test(line)) violations.push(`added code matches ${re.source.slice(0, 40)}: ${line.trim().slice(0, 100)}`);
    }
  }
  return { pass: violations.length === 0, violations, changed };
}

// ---------- the pipeline ----------
export async function webAutopatch({ prod, prodPort, stagePort, scratch, ai = null, log = console.log, injectChangelog = null, sabotage = null, only = null }) {
  const feed = loadFeed();
  let items = findItems(prod, feed);
  if (only) items = items.filter((i) => only.includes(i.pkg));
  log(`in scope: ${items.map((i) => `${i.pkg}@${i.installed} -> ${i.fix?.version ?? 'no fix'}`).join(', ')}`);
  const staging = path.join(scratch, 'staging');
  const prodLog = path.join(scratch, 'production.log');
  const stageLog = path.join(scratch, 'staging.log');
  const results = [];

  for (const item of items) {
    const t0 = Date.now();
    const r = { pkg: item.pkg, from: item.installed, to: item.fix?.version ?? null, lane: item.lane, advisories: item.advisories.map((a) => a.ghsa), outOfScopeAdvisories: item.outOfScope, fictional: item.fictional };
    results.push(r);
    const done = (outcome, extra = {}) => { Object.assign(r, { outcome, minutes: +((Date.now() - t0) / 60e3).toFixed(1) }, extra); log(`${item.pkg}: ${outcome}`); };
    let newRoot = null, changelog = '';

    // ---- 1. release check of the proposed fix tarball, before anything is installed ----
    if (item.fix) {
      const oldSrc = item.source === 'local' ? path.resolve(REGISTRY, registry()[item.pkg].versions[item.installed]) : `${item.pkg}@${item.installed}`;
      const newSrc = item.source === 'local' ? item.fix.tarball : `${item.pkg}@${item.fix.version}`;
      const oldRoot = unpack(oldSrc, `${item.pkg}-${item.installed}`);
      newRoot = unpack(newSrc, `${item.pkg}-${item.fix.version}`);
      const rc = releaseCheck(oldRoot, newRoot);
      r.releaseCheck = rc.suspicious ? rc.problems.join(' | ') : 'clean: no new install scripts, no new eval/exec/remote-fetch patterns';
      r.npmMetadataFlags = item.source === 'npm' ? { installScripts: item.fix.installScripts, publisherChanged: item.fix.publisherChanged, ageDays: item.fix.ageDays } : null;
      if (rc.suspicious || item.fix.installScripts?.length || item.fix.publisherChanged) {
        r.releaseCheckDetail = rc;
        done(`REFUSED: the proposed fix ${item.fix.version} fails the release check; kept ${item.installed}, human alerted`, { action: 'refuse' });
        continue;
      }
      changelog = changelogFor(item, newRoot);
      if (injectChangelog && injectChangelog.pkg === item.pkg) changelog += injectChangelog.text;
    }

    // ---- 2. staging copy of the current production, baseline checks ----
    copySource(prod, staging);
    const ci = npmCi(staging);
    if (ci.code !== 0) { done('ERROR: npm ci failed on staging', { detail: ci.err.slice(-300) }); continue; }
    fs.writeFileSync(stageLog, '');
    const b0 = build(staging);
    await start(staging, stagePort, stageLog);
    const baseline = await runChecks({ dir: staging, port: stagePort, probes: [item.pkg], logFile: stageLog });
    const known = baseline.checks.filter((c) => !c.pass && c.group !== 'probe').map((c) => c.name);
    r.baseline = { build: b0.ok, knownFailures: known, probeBefore: baseline.checks.filter((c) => c.group === 'probe').map((c) => ({ name: c.name, pass: c.pass })) };
    const knownFile = path.join(scratch, 'known.json');
    fs.writeFileSync(knownFile, JSON.stringify(known));
    const checkScript = `#!/bin/bash\n# Rebuilds the staging copy, restarts it and runs the site checks.\nnode ${path.join(LAB, 'stage-check.mjs')} --dir "$(pwd)" --port ${stagePort} --item '${item.pkg}' --known ${knownFile} --log ${stageLog}\n`;
    fs.writeFileSync(path.join(staging, 'check-site.sh'), checkScript);
    await stop(stagePort);

    // ---- 3. apply the bump on staging ----
    let spec = null, vendorFile = null;
    if (item.fix) {
      if (item.source === 'npm') spec = `${item.pkg}@${item.fix.version}`;
      else { vendorFile = `vendor/${path.basename(item.fix.tarball)}`; fs.copyFileSync(item.fix.tarball, path.join(staging, vendorFile)); spec = `file:${vendorFile}`; }
      const ins = sh('npm', ['install', spec, '--save-exact', '--no-audit', '--no-fund', '--ignore-scripts'], { cwd: staging, timeout: 300e3 });
      if (ins.code !== 0) { done('ERROR: npm install failed on staging', { detail: ins.err.slice(-300) }); continue; }
    }
    const expected = item.fix ? { pkg: item.pkg, spec: item.source === 'npm' ? item.fix.version : spec, vendor: vendorFile } : { pkg: null };

    const runGate = async () => {
      const b = build(staging);
      if (!b.ok) return { pass: false, build: b, failing: [{ group: 'build', name: 'next build', detail: b.out.slice(-600) }], integrity: integrity(prod, staging, expected), rescan: rescan(staging, item), checks: [] };
      await start(staging, stagePort, stageLog);
      const res = await runChecks({ dir: staging, port: stagePort, probes: [item.pkg], known, logFile: stageLog });
      const ig = integrity(prod, staging, expected);
      const rs = rescan(staging, item);
      await stop(stagePort);
      const pass = res.pass && ig.pass && (item.fix ? rs.fixed : true);
      const failing = [...res.failing, ...ig.violations.map((v) => ({ group: 'integrity', name: v, detail: '' })), ...(item.fix && !rs.fixed ? [{ group: 'rescan', name: `still affected by ${rs.stillAffectedBy.join(', ')}`, detail: '' }] : [])];
      return { pass, build: b, checks: res.checks, failing, integrity: ig, rescan: rs };
    };
    const summarize = (g) => ({ pass: g.pass, failing: g.failing.map((c) => `[${c.group}] ${c.name}${c.detail ? ` (${c.detail})` : ''}`), rescan: g.rescan, integrity: g.integrity.violations });

    let g = await runGate();
    r.gateAfterApply = summarize(g);
    const tail = () => fs.readFileSync(stageLog, 'utf8').split('\n').filter(Boolean).slice(-15).join('\n');

    // ---- 4. AI on staging only: repair after a bump, or an app-level guard when no fix exists ----
    let aiKind = null;
    if (ai && !g.pass) {
      aiKind = item.fix ? 'repair' : 'guard';
      const rr = await ai[aiKind]({ staging, port: stagePort, item, failing: g.failing, logTail: tail(), changelog, knownFile });
      r.ai = { kind: aiKind, ...rr };
      log(`${item.pkg}: AI ${aiKind} by ${rr.by}: $${rr.costUsd ?? '?'} ${rr.turns ?? '?'} turns`);
      g = await runGate();
      r.gateAfterAI = summarize(g);
    }
    r.gate = summarize(g);
    if (!g.pass) {
      const why = item.fix ? 'staging gate failed; production left on the old version, still vulnerable, human alerted' : (ai ? 'AI guard did not pass the gate' : 'no fix exists and no AI configured; left vulnerable, human alerted');
      done(`NOT SHIPPED: ${why}`, { action: item.fix ? 'bump' : 'guard' });
      continue;
    }

    // ---- 5. promote: replay the same change on production (never copy staging data), rebuild, restart, smoke ----
    const backup = path.join(scratch, 'prod-backup');
    copySource(prod, backup);
    safeRm(path.join(scratch, 'prod-backup-next'));
    fs.cpSync(path.join(prod, '.next'), path.join(scratch, 'prod-backup-next'), { recursive: true });
    await stop(prodPort);
    if (item.fix) {
      if (vendorFile) fs.copyFileSync(item.fix.tarball, path.join(prod, vendorFile));
      const ins = sh('npm', ['install', spec, '--save-exact', '--no-audit', '--no-fund', '--ignore-scripts'], { cwd: prod, timeout: 300e3 });
      if (ins.code !== 0) r.promoteNote = `npm install on production failed: ${ins.err.slice(-200)}`;
    }
    const replayed = [];
    for (const o of OWNED) {
      const s = path.join(staging, o), p = path.join(prod, o);
      const exists = fs.existsSync(s);
      const differs = (exists !== fs.existsSync(p)) || (exists && sh('diff', ['-rq', s, p]).code !== 0);
      if (!differs) continue;
      safeRmProd(p, prod);
      if (exists) fs.cpSync(s, p, { recursive: true });
      replayed.push(o);
    }
    r.replayedSiteCode = replayed;
    if (sabotage === item.pkg) fs.writeFileSync(path.join(prod, 'app/page.js'), 'export default function Home() { throw new Error("sabotage"); }\n');
    const same = (f) => fs.readFileSync(path.join(staging, f), 'utf8') === fs.readFileSync(path.join(prod, f), 'utf8');
    r.replayMatchesStaging = same('package.json') && same('package-lock.json');
    const bp = build(prod);
    fs.writeFileSync(prodLog, '');
    if (bp.ok) await start(prod, prodPort, prodLog);
    const smoke = bp.ok ? await runChecks({ dir: prod, port: prodPort, probes: [item.pkg], known, logFile: prodLog, unit: false }) : { pass: false, failing: [{ name: 'production build failed', detail: bp.out.slice(-300) }] };
    r.smoke = { pass: smoke.pass && r.replayMatchesStaging, failing: smoke.failing.map((c) => c.name) };
    if (!r.smoke.pass) {
      await stop(prodPort);
      // roll back: restore code, manifests and the previous build output, reinstall the old lockfile
      for (const f of fs.readdirSync(prod).filter((x) => x !== 'node_modules')) safeRmProd(path.join(prod, f), prod);
      for (const f of fs.readdirSync(backup)) fs.cpSync(path.join(backup, f), path.join(prod, f), { recursive: true });
      fs.cpSync(path.join(scratch, 'prod-backup-next'), path.join(prod, '.next'), { recursive: true });
      npmCi(prod);
      await start(prod, prodPort, prodLog);
      const after = await runChecks({ dir: prod, port: prodPort, probes: [], known, logFile: prodLog, unit: false });
      done('ROLLED BACK: production smoke check failed after the change; previous version restored', { action: 'rollback', rollbackVerified: after.pass });
      continue;
    }
    done(`SHIPPED: ${item.fix ? `bump to ${item.fix.version}` : 'app-level guard'}${aiKind ? ` + AI ${aiKind}` : ''}`, { action: item.fix ? 'bump' : 'guard' });
  }
  await stop(stagePort);
  return { items: results, report: report(results) };
}

function safeRmProd(p, prod) {
  const abs = path.resolve(p);
  if (!abs.startsWith(path.resolve(prod) + path.sep) || abs.includes('node_modules')) throw new Error(`refusing to delete ${abs}`);
  fs.rmSync(abs, { recursive: true, force: true });
}

function report(results) {
  const L = ['## Site security run', ''];
  for (const r of results) {
    L.push(`### ${r.pkg} ${r.from} -> ${r.to ?? '(no fixed version)'}${r.fictional ? ' (fictional internal package)' : ''}`);
    L.push(`- Advisories in scope: ${r.advisories.join(', ')}${r.outOfScopeAdvisories ? ` (+${r.outOfScopeAdvisories} other advisories on this package left out of scope)` : ''}. Lane: ${r.lane}`);
    if (r.releaseCheck) L.push(`- Release check: ${r.releaseCheck}`);
    if (r.baseline) L.push(`- Baseline on staging: build ${r.baseline.build ? 'ok' : 'FAILED'}; probe before change: ${r.baseline.probeBefore.map((p) => `${p.pass ? 'blocked' : 'EXPLOITABLE'} (${p.name})`).join('; ')}; known failures: ${r.baseline.knownFailures.join(', ') || 'none'}`);
    if (r.gateAfterApply) L.push(`- Gate after apply: ${r.gateAfterApply.pass ? 'pass' : 'FAIL: ' + r.gateAfterApply.failing.join('; ')}`);
    if (r.ai) L.push(`- AI ${r.ai.kind}: ${r.ai.by}, $${r.ai.costUsd ?? '?'}, ${r.ai.turns ?? '?'} turns, ${Math.round((r.ai.ms || 0) / 1000)}s`);
    if (r.gateAfterAI) L.push(`- Gate after AI: ${r.gateAfterAI.pass ? 'pass' : 'FAIL: ' + r.gateAfterAI.failing.join('; ')}`);
    if (r.smoke) L.push(`- Production smoke: ${r.smoke.pass ? 'pass' : 'FAIL ' + r.smoke.failing.join(', ')}`);
    L.push(`- **Outcome:** ${r.outcome}`, '');
  }
  return L.join('\n');
}
