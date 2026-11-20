// Decides how urgent a finding is and whether it may skip the release cooldown.
// Lanes:
//   urgent  - known exploited (CISA KEV), or exploitable without login and severity high/critical
//   routine - everything else; goes through the cooldown so a freshly poisoned release has time to be caught
const SEV = { none: 0, low: 1, moderate: 2, medium: 2, high: 3, critical: 4 };

export function sevRank(f) {
  if (f.cvss?.score != null) return f.cvss.score >= 9 ? 4 : f.cvss.score >= 7 ? 3 : f.cvss.score >= 4 ? 2 : f.cvss.score > 0 ? 1 : 0;
  return SEV[String(f.severity || '').toLowerCase()] ?? 0;
}

export function decideLane(f, cfg) {
  const reasons = [];
  let lane = 'routine';
  if (f.exploited) { lane = 'urgent'; reasons.push('listed as known exploited (CISA KEV)'); }
  else if (f.unauth && sevRank(f) >= 3 && f.active !== false) { lane = 'urgent'; reasons.push('no login needed and severity high/critical'); }
  else if (sevRank(f) >= 4 && f.active !== false) { lane = 'urgent'; reasons.push('critical severity'); }
  else reasons.push(f.unauth === false ? 'needs a logged-in account to exploit' : 'not marked exploited, severity below high');
  if (f.active === false) reasons.push('component is installed but not active');
  const flags = [];
  if (f.fix && lane !== 'urgent' && f.fix.ageDays != null && f.fix.ageDays < cfg.policy.cooldownDays) {
    flags.push(`fix released ${f.fix.ageDays}d ago, inside the ${cfg.policy.cooldownDays}d cooldown`);
  }
  return { lane, reasons, flags, cooldown: flags.length > 0 };
}
