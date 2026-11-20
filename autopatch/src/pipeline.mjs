// The loop: findings -> lane -> release check -> staging -> baseline -> apply -> gate (+restart re-check)
//   -> [AI repair | AI hotfix, on staging, owned files only] -> gate -> sensitive-change review -> staged result
//   -> (only with --promote) replay accepted actions on the real project.
import fs from 'node:fs';
import path from 'node:path';
import { decideLane, sevRank } from './policy.mjs';
import { releaseCheck } from './release-check.mjs';
import { assessChanges } from './sensitive.mjs';
import { runGate, baseline } from './gate.mjs';
import { runAgent, repairPrompt, hotfixPrompt } from './ai.mjs';
import { changedFiles, unifiedDiff, matchGlob, copyTree } from './util.mjs';

const DIFF_IGNORE = ['node_modules', '.git', '.next', '.autopatch', 'debug.log'];

export function findingKeys(f) { return [...new Set([f.id, ...(f.ids || []), f.pkg, ...(f.aliases || [])].filter(Boolean))]; }

function allowed(cfg, file) {
  return cfg.ownedPaths.some((g) => matchGlob(file, g)) && !cfg.protectedPaths.some((g) => matchGlob(file, g));
}

function writeCheckScript(ctx, dir, f, known) {
  fs.mkdirSync(path.join(dir, '.autopatch'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.autopatch/known.json'), JSON.stringify(known));
  const bin = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'bin', 'autopatch.mjs');
  fs.writeFileSync(path.join(dir, '.autopatch/check.sh'),
    `#!/bin/bash\n# Runs this staging copy's checks (pages, flows, tests, exploit probes, integrity).\nexec node ${bin} check --project ${ctx.cfg.projectDir} --dir "$(pwd)" --finding ${JSON.stringify(f.id)} --known .autopatch/known.json\n`);
  return 'bash .autopatch/check.sh';
}

export async function run({ cfg, adapter, mode = 'scan', approve = [], workDir, log }) {
  const ctx = { cfg, workDir, log };
  fs.mkdirSync(workDir, { recursive: true });
  log.info(`autopatch: ${adapter.name} adapter, project ${cfg.projectDir}`);
  const findings = await adapter.findings(ctx);
  for (const f of findings) f.policy = decideLane(f, cfg);
  findings.sort((a, b) => (a.policy.lane === b.policy.lane ? sevRank(b) - sevRank(a) : a.policy.lane === 'urgent' ? -1 : 1));
  log.info(`found ${findings.length} applicable advisories (${findings.filter((f) => f.policy.lane === 'urgent').length} urgent)`);
  if (mode === 'scan' || !findings.length) return { mode, findings, accepted: [] };

  let cur = path.join(workDir, 'staging-0');
  await adapter.prepareStaging(ctx, cfg.projectDir, cur);
  const accepted = [];
  let k = 0;
  try {
    for (const f of findings) {
      const t0 = Date.now();
      const done = (outcome, extra = {}) => { Object.assign(f, { outcome, seconds: Math.round((Date.now() - t0) / 1000) }, extra); log.info(`  ${f.pkg} ${f.id}: ${outcome}`); };
      log.info(`- ${f.pkg} ${f.installed} ${f.id} [${f.policy.lane}]`);
      let notes = '';
      if (f.fix) {
        const rel = await adapter.fetchRelease(ctx, f);
        notes = rel.notes || '';
        f.releaseCheck = rel.oldDir && rel.newDir ? releaseCheck(rel.oldDir, rel.newDir) : { suspicious: false, findings: [], skipped: rel.reason || 'release not available for inspection' };
        if (f.releaseCheck.suspicious) { done('HELD: fix release looks malicious; human alerted', { status: 'held' }); continue; }
        if (f.policy.cooldown) { done(`HELD: ${f.policy.flags.join('; ')}`, { status: 'held' }); continue; }
      } else if (!cfg.ai.enabled) {
        done('NEEDS HUMAN: no fixed version and AI is disabled (consider a WAF/virtual patch or removing the component)', { status: 'needs-human' });
        continue;
      }
      const next = path.join(workDir, `staging-${++k}`);
      await adapter.prepareStaging(ctx, cur, next);
      const known = await baseline(adapter, ctx, next);
      const actions = [];
      if (f.fix) {
        const a = { kind: 'update', pkg: f.pkg, version: f.fix.version, tarball: f.fix.tarball || undefined, finding: f.id };
        const r = await adapter.applyAction(ctx, next, a);
        if (!r.ok) { done(`FAILED: could not apply update (${r.log?.slice(-200)})`, { status: 'failed' }); await adapter.stop(ctx); continue; }
        actions.push(a);
      }
      let gate = await runGate(adapter, ctx, next, { findingKeys: findingKeys(f), known, restartCheck: cfg.checks.restartCheck });
      f.gateAfterApply = gate.newFailures.map((c) => c.name);
      const preAi = `${next}.pre-ai`;
      if ((!f.fix || !gate.pass) && cfg.ai.enabled) {
        const ignore = [...DIFF_IGNORE, ...(adapter.diffIgnore || [])]; // e.g. WordPress: the SQLite DB the checks write to
        copyTree(next, preAi, { skip: ignore });
        const checkCmd = writeCheckScript(ctx, next, f, known);
        const kind = f.fix ? 'repair' : 'hotfix';
        const prompt = kind === 'repair'
          ? repairPrompt({ cfg, finding: f, failing: gate.newFailures, logTail: adapter.logTail?.(ctx, next), notes, checkCmd })
          : hotfixPrompt({ cfg, finding: f, checkCmd, hint: adapter.hotfixHint?.(ctx, f) });
        log.info(`  AI ${kind} (${cfg.ai.model}) on staging...`);
        f.ai = { kind, ...runAgent({ cfg, cwd: next, prompt }) };
        log.info(`  AI ${kind}: $${f.ai.costUsd ?? '?'}, ${f.ai.turns ?? '?'} turns`);
        fs.rmSync(path.join(next, '.autopatch'), { recursive: true, force: true });
        const changed = changedFiles(preAi, next, { ignore });
        const forbidden = changed.filter((c) => !allowed(cfg, c.file));
        f.aiChanges = changed;
        f.aiDiff = unifiedDiff(preAi, next, changed.map((c) => c.file));
        if (forbidden.length) { done(`FAILED: AI touched files outside its allowed paths: ${forbidden.map((c) => c.file).join(', ')}`, { status: 'failed' }); await adapter.stop(ctx); continue; }
        if (changed.length) actions.push({ kind: 'files', finding: f.id, files: Object.fromEntries(changed.map((c) => [c.file, c.change === 'removed' ? null : fs.readFileSync(path.join(next, c.file), 'utf8')])) });
        gate = await runGate(adapter, ctx, next, { findingKeys: findingKeys(f), known, restartCheck: cfg.checks.restartCheck });
        f.sensitive = assessChanges(f.aiDiff, cfg.sensitive.extraPatterns);
      }
      await adapter.stop(ctx);
      f.gate = gate.checks.map(({ name, pass, known: kn, detail }) => ({ name, pass, known: kn, detail }));
      if (!gate.pass) { done(`NOT STAGED: gate failed (${gate.newFailures.map((c) => c.name).join('; ')}); still vulnerable, human alerted`, { status: 'failed' }); continue; }
      if (!actions.length) { done('NOT STAGED: nothing changed', { status: 'failed' }); continue; }
      // Major upgrades always wait for a human, even when every check passes (the Next.js run once jumped 14 -> 15).
      const needsHuman = f.sensitive?.humanApprovalRequired || f.fix?.major;
      const approved = approve.includes(f.id) || approve.includes(f.pkg);
      if (needsHuman && !approved) {
        done(`STAGED, NEEDS HUMAN APPROVAL: ${[...(f.sensitive?.reasons || []), f.fix?.major ? `major upgrade ${f.installed} -> ${f.fix.version}${f.ai ? ' with AI code changes' : ''}` : null].filter(Boolean).join('; ')} (rerun with --approve ${f.id})`, { status: 'needs-approval', actions });
        continue; // not carried forward until approved
      }
      accepted.push(...actions);
      cur = next;
      done(`STAGED: ${actions.map((a) => (a.kind === 'update' ? `update to ${a.version}` : `AI ${f.ai.kind}: ${Object.keys(a.files).join(', ')}`)).join(' + ')}`, { status: 'ready', actions });
    }
  } finally { await adapter.stop(ctx); }

  let promotion = null;
  if (mode === 'promote' && accepted.length) {
    log.info(`promoting ${accepted.length} action(s) to the project...`);
    promotion = await adapter.promote(ctx, accepted);
    log.info(`promotion: ${promotion.ok ? 'done' : 'FAILED (rolled back)'} ${promotion.details || ''}`);
  }
  return { mode, findings, accepted, promotion, finalStaging: cur };
}
