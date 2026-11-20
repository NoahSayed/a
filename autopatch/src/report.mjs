// Human-readable report (markdown) plus machine-readable JSON.
import fs from 'node:fs';
import path from 'node:path';

export function writeReports(result, dir) {
  const L = [`# autopatch report (${new Date().toISOString()})`, '', `Mode: **${result.mode}**`, ''];
  if (!result.findings.length) L.push('No applicable advisories found.');
  for (const f of result.findings) {
    L.push(`## ${f.pkg} ${f.installed} — ${f.id}${f.aliases?.length ? ` (${f.aliases.join(', ')})` : ''}`);
    L.push(`- ${f.title}`);
    L.push(`- Severity: ${f.cvss?.score ?? f.severity ?? '?'}${f.unauth ? ', no login needed' : ''}${f.exploited ? ', **known exploited (KEV)**' : ''}`);
    L.push(`- Lane: **${f.policy.lane}** (${f.policy.reasons.join('; ')})`);
    L.push(`- Fix: ${f.fix ? `${f.fix.version}${f.fix.major ? ' (major)' : ''}${f.fix.ageDays != null ? `, released ${f.fix.ageDays}d ago` : ''}${f.fix.residual?.length ? `; still open on this major: ${f.fix.residual.join(', ')}${f.fix.majorOption ? ` (all cleared by ${f.fix.majorOption}, a major upgrade: plan it separately)` : ''}` : ''}` : 'none published'}`);
    if (f.releaseCheck) L.push(`- Release check: ${f.releaseCheck.suspicious ? `**SUSPICIOUS**: ${f.releaseCheck.findings.join('; ')}` : f.releaseCheck.skipped ? `skipped (${f.releaseCheck.skipped})` : 'nothing suspicious introduced'}${f.releaseCheck.warnings?.length ? ` (warnings: ${f.releaseCheck.warnings.join('; ')})` : ''}`);
    if (f.ai) L.push(`- AI ${f.ai.kind}: ${f.ai.model}, $${f.ai.costUsd ?? '?'}, ${f.ai.turns ?? '?'} turns; files: ${(f.aiChanges || []).map((c) => `${c.file} (${c.change})`).join(', ') || 'none'}`);
    if (f.sensitive?.reasons?.length) L.push(`- Needs human because: ${f.sensitive.reasons.join('; ')}`);
    if (f.sensitive?.reviewNotes?.length) L.push(`- Review notes: touches ${f.sensitive.reviewNotes.join(', ')}`);
    const failed = (f.gate || []).filter((c) => !c.pass && !c.known);
    if (failed.length) L.push(`- Gate failures: ${failed.map((c) => `${c.name} (${c.detail})`).join('; ')}`);
    if (f.outcome) L.push(`- **Outcome:** ${f.outcome}`);
    if (f.aiDiff) L.push('', '<details><summary>AI change</summary>', '', '```diff', f.aiDiff.slice(0, 20000), '```', '</details>');
    L.push('');
  }
  if (result.promotion) L.push('## Promotion', '', `${result.promotion.ok ? 'Applied' : 'FAILED and rolled back'}: ${result.promotion.details || ''}`);
  L.push('', '_Advisory, changelog and release text is treated as untrusted data. Nothing reaches the project without `--promote`._');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'report.md'), L.join('\n'));
  const slim = { ...result, findings: result.findings.map(({ aiDiff, ...f }) => f) };
  fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(slim, null, 2));
  return path.join(dir, 'report.md');
}
