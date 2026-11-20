#!/usr/bin/env node
// autopatch: watch advisories for your project, stage verified fixes, ship them only when you say so.
//   autopatch scan    [--project <dir>]                         report what affects you (changes nothing)
//   autopatch fix     [--project <dir>] [--model haiku|sonnet] [--no-ai] [--approve <id,...>] [--promote]
//                                                               stage fixes on copies; --promote applies them
//   autopatch check   --project <dir> --dir <staging> [--finding <id>] [--known <file>]   (used by the AI step)
//   autopatch init    [--project <dir>] --adapter npm|nextjs|wordpress
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadConfig } from '../src/config.mjs';
import { loadAdapter } from '../src/adapters/index.mjs';
import { run, findingKeys } from '../src/pipeline.mjs';
import { runGate } from '../src/gate.mjs';
import { writeReports } from '../src/report.mjs';
import { createLogger } from '../src/util.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const args = {};
for (let i = 0; i < rest.length; i++) {
  if (!rest[i].startsWith('--')) continue;
  const k = rest[i].slice(2);
  if (rest[i + 1] === undefined || rest[i + 1].startsWith('--')) args[k] = true; else args[k] = rest[++i];
}
const project = path.resolve(args.project || '.');

function usage(code = 1) {
  console.error(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 8).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
  process.exit(code);
}

async function main() {
  if (!cmd || cmd === 'help' || args.help) usage(0);
  if (cmd === 'init') {
    const adapter = args.adapter || 'npm';
    const tpl = JSON.parse(fs.readFileSync(new URL(`../templates/${adapter}.config.json`, import.meta.url), 'utf8'));
    const out = path.join(project, 'autopatch.config.json');
    if (fs.existsSync(out)) { console.error(`${out} already exists`); process.exit(1); }
    fs.writeFileSync(out, JSON.stringify(tpl, null, 2) + '\n');
    console.error(`wrote ${out}; edit ownedPaths and checks for your project`);
    return;
  }
  const overrides = {};
  if (args.model) overrides.ai = { model: args.model };
  if (args['no-ai']) overrides.ai = { ...(overrides.ai || {}), enabled: false };
  const cfg = loadConfig(project, overrides);
  const adapter = await loadAdapter(cfg.adapter);
  const log = createLogger(args.verbose);

  if (cmd === 'check') {
    const dir = path.resolve(args.dir);
    const workDir = args.work || path.join(os.tmpdir(), 'autopatch-check');
    const ctx = { cfg, workDir, log };
    const known = args.known && fs.existsSync(path.resolve(dir, args.known)) ? JSON.parse(fs.readFileSync(path.resolve(dir, args.known), 'utf8')) : [];
    const keys = args.finding ? [args.finding, ...(await adapter.findings?.({ ...ctx, quiet: true }).then((fs_) => fs_.filter((f) => f.id === args.finding).flatMap(findingKeys)).catch(() => []))] : [];
    const g = await runGate(adapter, ctx, dir, { findingKeys: keys, known, restartCheck: cfg.checks.restartCheck });
    await adapter.stop(ctx);
    for (const c of g.checks) console.log(`${c.pass ? 'PASS' : c.known ? 'KNOWN (already failing before this change)' : 'FAIL'}  ${c.name}${c.pass ? '' : `  -> ${c.detail}`}`);
    console.log(g.pass ? '\nALL CHECKS PASS' : '\nSOME CHECKS FAIL');
    process.exit(g.pass ? 0 : 1);
  }
  if (cmd !== 'scan' && cmd !== 'fix') usage();
  const id = crypto.createHash('sha1').update(project).digest('hex').slice(0, 8);
  const workDir = path.resolve(args.work || path.join(os.tmpdir(), `autopatch-${id}`), new Date().toISOString().replace(/[:.]/g, '-'));
  const mode = cmd === 'scan' ? 'scan' : args.promote ? 'promote' : 'stage';
  const approve = args.approve ? String(args.approve).split(',') : [];
  const result = await run({ cfg, adapter, mode, approve, workDir, log });
  const report = writeReports(result, workDir);
  console.log(fs.readFileSync(report, 'utf8'));
  console.error(`\nreport: ${report}`);
  const bad = result.findings.some((f) => f.policy.lane === 'urgent' && f.status !== 'ready');
  process.exit(mode === 'scan' ? (result.findings.length ? 2 : 0) : bad ? 3 : 0);
}

main().catch((e) => { console.error(e.stack || e); process.exit(1); });
