// Re-score one existing probe file (no model call) against the 3 copies, using the fixed host scanner.
// Usage: node rescore-one.mjs <label>
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { serve, stop, SCRATCH } from '/home/user/a/autopatch-lab/wordpress/lab/site.mjs';
import { runChecks } from '/home/user/a/autopatch-lab/wordpress/lab/checks.mjs';
const label = process.argv[2];
const OUTDIR = '/home/user/a/autopatch-lab/experiments/probe-writing/results';
const rec = JSON.parse(fs.readFileSync(path.join(OUTDIR, `${label}.json`), 'utf8'));
const script = path.join(OUTDIR, `${label}.probe.mjs`);
// scanner (same logic as fixed run-probe-exp.mjs)
const src0 = fs.readFileSync(script, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
const hosts = [...src0.matchAll(/https?:\/\/([^\/\s'"`)\]},;]+)/g)].map((m) => m[1].replace(/[.,;:!?)\]}>]+$/, ''));
const bad = hosts.filter((h) => !/^127\.0\.0\.1(:\d+)?$/.test(h) && !/^\$\{?\s*(base|url|argv)/i.test(h));
const ports = { vuln: 8182, fixed: 8183, decoy: 8184, chk: 8185 };
const against = {};
const dirOf = (v) => path.join(SCRATCH, 'vulnsites', `${rec.vuln}-${v}`);
for (const v of ['vuln', 'fixed', 'decoy']) {
  const port = ports[v];
  await serve(dirOf(v), port);
  const r = spawnSync('node', [script, `http://127.0.0.1:${port}`], { encoding: 'utf8', timeout: 15000 });
  await stop(port);
  against[v] = { exit: r.status, out: ((r.stdout || '') + (r.stderr || '')).slice(0, 1000), timedOut: r.status === null };
}
await serve(dirOf('vuln'), ports.chk);
const chk = await runChecks(dirOf('vuln'), ports.chk, { probes: [] });
await stop(ports.chk);
const valid = against.vuln.exit === 0 && against.fixed.exit === 1;
const discriminating = valid && against.decoy.exit === 0;
const safe = bad.length === 0 && chk.pass !== false;
const prev = { against: rec.against, otherHosts: rec.otherHosts, badHosts: rec.badHosts, valid: rec.valid, discriminating: rec.discriminating, safe: rec.safe };
Object.assign(rec, { against, otherHosts: hosts, badHosts: bad, safeFunctional: chk.pass, valid, discriminating, safe,
  rescored: { date: '2026-11-19', reason: 'host-scanner artifact: regex matched "127.0.0.1:8186)" in a usage comment; probe was never run. Scanner fixed (strip comments, trim trailing punctuation); probe re-run against the 3 copies, no model call.', previous: prev } });
fs.writeFileSync(path.join(OUTDIR, `${label}.json`), JSON.stringify(rec, null, 2));
const allP = path.join(OUTDIR, '_all.json');
const all = JSON.parse(fs.readFileSync(allP, 'utf8'));
const i = all.findIndex((x) => x.label === label);
all[i] = rec;
fs.writeFileSync(allP, JSON.stringify(all, null, 2));
console.log(JSON.stringify({ label, exits: Object.fromEntries(Object.entries(against).map(([k, v]) => [k, v.exit])), hosts, bad, safeFunctional: chk.pass, valid, discriminating, safe }));
