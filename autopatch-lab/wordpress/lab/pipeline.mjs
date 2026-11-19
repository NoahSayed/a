// WordPress auto-patch pipeline:
// feed -> inventory -> match -> lane -> (supply-chain check on the fix release) -> staging copy -> apply -> gate
//   -> [AI repair of site-owned code | AI hotfix mu-plugin when no fix exists] -> gate -> promote to production -> smoke -> rollback if needed.
// The AI only ever works on a staging copy and may only change site-owned code (theme, mu-plugins). Promotion is plain code.
import fs from 'node:fs';
import path from 'node:path';
import { wp, http, copySite, serve, stop, zipPath, sh, LAB } from './site.mjs';
import { runChecks, PROBES } from './checks.mjs';

const BAD = [/\beval\s*\(/, /base64_decode\s*\(/, /gzinflate\s*\(/, /wp_(insert|create)_user\s*\(/, /wp_remote_(get|post|request)\s*\(/, /\bshell_exec|passthru|proc_open/];
const vcmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return Math.sign(d); } return 0; };

function affected(ver, ranges) {
  return Object.values(ranges).some((r) => (r.from_version === '*' || vcmp(ver, r.from_version) >= (r.from_inclusive ? 0 : 1)) && (r.to_version === '*' || vcmp(ver, r.to_version) <= (r.to_inclusive ? 0 : -1)));
}

function unzipTo(zip, dir) { fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true }); sh('unzip', ['-q', zip, '-d', dir]); return dir; }
function phpFiles(d) { return fs.existsSync(d) ? fs.readdirSync(d, { recursive: true }).map((f) => path.join(d, f)).filter((f) => f.endsWith('.php')) : []; }

/** Compare old vs new release: does the "fix" introduce code patterns the old version did not have? */
export function releaseDiff(slug, oldV, newZip, scratch) {
  const a = unzipTo(zipPath(slug, oldV), path.join(scratch, '_diff-old'));
  const b = unzipTo(newZip, path.join(scratch, '_diff-new'));
  const count = (d) => { const t = phpFiles(d).map((f) => fs.readFileSync(f, 'utf8')).join('\n'); return BAD.map((re) => (t.match(new RegExp(re, 'g')) || []).length); };
  const ca = count(a), cb = count(b);
  const introduced = BAD.filter((_, i) => cb[i] > ca[i]).map((re) => re.source);
  const readme = fs.existsSync(path.join(b, slug, 'readme.txt')) ? fs.readFileSync(path.join(b, slug, 'readme.txt'), 'utf8') : '';
  return { introduced, readme };
}

export async function wpAutopatch({ prod, prodPort = 8081, stagePort = 8082, feed, scratch, ai = null, zipVariant = () => '', log = console.log }) {
  const inv = JSON.parse(wp(prod, ['plugin', 'list', '--format=json'], prodPort).out);
  const findings = [];
  for (const rec of Object.values(feed).filter((r) => r && r.id)) {
    for (const sw of rec.software.filter((s) => s.type === 'plugin')) {
      const p = inv.find((x) => x.name === sw.slug);
      if (!p || !affected(p.version, sw.affected_versions)) continue;
      const unauth = /PR:N/.test(rec.cvss?.vector || '');
      const lane = unauth && p.status === 'active' && rec.cvss.score >= 5 ? 'urgent' : 'routine';
      findings.push({ id: rec.id, cve: rec.cve, title: rec.title, slug: sw.slug, installed: p.version, active: p.status === 'active', patched: sw.patched, fixVersion: sw.patched_versions[0] || null, cvss: rec.cvss, lane, why: unauth ? 'no login needed to exploit' : 'needs a logged-in account to exploit', description: rec.description });
    }
  }
  findings.sort((a, b) => (a.lane === b.lane ? b.cvss.score - a.cvss.score : a.lane === 'urgent' ? -1 : 1));
  const staging = path.join(scratch, 'staging');
  let n = 0;
  for (const f of findings) {
    n++;
    const t0 = Date.now();
    const done = (outcome, extra = {}) => { Object.assign(f, { outcome, minutes: +((Date.now() - t0) / 60e3).toFixed(1) }, extra); log(`${f.slug}: ${outcome}`); };
    // ---- 1. supply-chain check of the fix release before it touches anything ----
    let zip = null, notes = '';
    if (f.patched) {
      zip = zipPath(f.slug, f.fixVersion, zipVariant(f.slug, f.fixVersion));
      const d = releaseDiff(f.slug, f.installed, zip, scratch);
      notes = d.readme;
      f.releaseCheck = d.introduced.length ? `fix release introduces: ${d.introduced.join(', ')}` : 'no suspicious code introduced';
      if (d.introduced.length) { done('HELD: fix release looks malicious; kept current version, human alerted', { action: 'hold' }); continue; }
      if (f.lane === 'routine') { /* routine fixes still go through staging; a real deployment would respect a cooldown here */ }
    }
    // ---- 2. staging copy of current production ----
    copySite(prod, staging);
    await serve(staging, stagePort);
    // Baseline: what already fails on (a copy of) production before this change.
    const baseline = await runChecks(staging, stagePort, { ref: prod });
    const known = baseline.checks.filter((c) => !c.pass).map((c) => c.name);
    const knownFile = path.join(scratch, `known-failures-${f.slug}.json`);
    fs.writeFileSync(knownFile, JSON.stringify(known));
    fs.writeFileSync(path.join(staging, 'check-site.sh'), `#!/bin/bash\n# Runs the site checks against this staging copy.\nnode ${path.join(LAB, 'checks.mjs')} --dir "$(pwd)" --port ${stagePort} --probes ${f.slug} --ref ${prod} --known ${knownFile}\n`);
    const probeBefore = PROBES[f.slug] ? await PROBES[f.slug](staging, stagePort) : null;
    f.probeFiredBefore = probeBefore;
    let action;
    if (f.patched) {
      action = 'update';
      const ins = wp(staging, ['plugin', 'install', zip, '--force'], stagePort); f.installLog = (ins.out + ins.err).slice(-400); if (process.env.WPLAB_DEBUG) console.log('INSTALL', zip, ins.code, f.installLog);
    } else if (ai) {
      action = 'ai-hotfix';
    } else {
      action = 'deactivate';
      wp(staging, ['plugin', 'deactivate', f.slug], stagePort);
    }
    await serve(staging, stagePort); // restart PHP after a code change, like a real deploy reloads PHP-FPM
    let gate = await runChecks(staging, stagePort, { probes: [f.slug], ref: prod, known });
    f.gateAfterApply = gate.checks.filter((c) => !c.pass && !c.known).map((c) => c.name);
    // ---- 3. AI step, only on staging ----
    if (ai && (action === 'ai-hotfix' || !gate.pass)) {
      const kind = action === 'ai-hotfix' ? 'hotfix' : 'repair';
      const logTail = fs.readFileSync(path.join(staging, 'wp-content/debug.log'), 'utf8').split('\n').slice(-15).join('\n');
      const r = await ai[kind]({ staging, port: stagePort, finding: f, failing: gate.checks.filter((c) => !c.pass && !c.known), logTail, notes });
      f.ai = { kind, ...r };
      log(`${f.slug}: AI ${kind} by ${r.by}: $${r.costUsd ?? '?'}`);
      await serve(staging, stagePort);
      gate = await runChecks(staging, stagePort, { probes: [f.slug], ref: prod, known });
    }
    f.gate = gate.checks.filter((c) => !c.pass && !c.known).map((c) => `${c.name} (${c.detail})`);
    f.knownBefore = known;
    const siteOk = gate.checks.filter((c) => /^page loads|fatal|untouched|administrator|dangerous|wp-config/.test(c.name)).every((c) => c.pass || c.known);
    const exploitBlocked = gate.checks.find((c) => c.name.startsWith('exploit blocked'))?.pass ?? true;
    await stop(stagePort);
    let promote = gate.pass;
    let note = '';
    if (!promote && action === 'deactivate' && f.lane === 'urgent' && siteOk && exploitBlocked) {
      promote = true; note = ' (feature loss accepted: critical, no fix exists; human alerted)';
    }
    if (!promote) { done(`NOT SHIPPED: staging gate failed${f.patched ? '; still vulnerable, human alerted' : ''}`, { action }); continue; }
    // ---- 4. promote: replay the same change on production (never copy the staging database) ----
    const backup = `${prod}.bak-${n}`;
    copySite(prod, backup);
    if (action === 'update') wp(prod, ['plugin', 'install', zip, '--force'], prodPort);
    if (action === 'deactivate') wp(prod, ['plugin', 'deactivate', f.slug], prodPort);
    for (const owned of ['wp-content/themes/bakery', 'wp-content/mu-plugins']) {
      fs.rmSync(path.join(prod, owned), { recursive: true, force: true });
      fs.cpSync(path.join(staging, owned), path.join(prod, owned), { recursive: true });
    }
    await serve(prod, prodPort);
    const smoke = await runChecks(prod, prodPort, { probes: [f.slug] });
    const smokeOk = smoke.checks.filter((c) => /^page loads|fatal|exploit/.test(c.name)).every((c) => c.pass);
    if (!smokeOk) {
      await stop(prodPort);
      fs.rmSync(prod, { recursive: true, force: true }); fs.renameSync(backup, prod);
      await serve(prod, prodPort);
      done('ROLLED BACK: production smoke check failed', { action });
      continue;
    }
    fs.rmSync(backup, { recursive: true, force: true });
    done(`SHIPPED: ${action}${f.ai ? ` + AI ${f.ai.kind}` : ''}${note}`, { action });
  }
  return { findings, report: report(findings) };
}

function report(findings) {
  const L = ['## Site security run', ''];
  for (const f of findings) {
    L.push(`### ${f.slug} ${f.installed} — ${f.cve} (${f.cvss.rating} ${f.cvss.score})`);
    L.push(`- ${f.title}`);
    L.push(`- Lane: **${f.lane}** (${f.why}${f.active ? ', plugin active' : ', plugin inactive'}). Fix available: ${f.patched ? f.fixVersion : 'no'}`);
    if (f.releaseCheck) L.push(`- Fix release check: ${f.releaseCheck}`);
    if (f.probeFiredBefore !== undefined) L.push(`- Exploit probe on unpatched staging: ${f.probeFiredBefore ? 'fired (confirmed exploitable)' : f.probeFiredBefore === null ? 'no probe' : 'did not fire'}`);
    if (f.ai) L.push(`- AI ${f.ai.kind}: ${f.ai.by}, $${f.ai.costUsd ?? '?'}`);
    if (f.gate?.length) L.push(`- Staging gate failures: ${f.gate.join('; ')}`);
    L.push(`- **Outcome:** ${f.outcome}`, '');
  }
  return L.join('\n');
}
