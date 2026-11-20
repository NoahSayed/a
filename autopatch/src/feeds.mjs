// Advisory intel: OSV records (GCS bucket mirror of osv.dev), CISA KEV (GitHub mirror), local advisory files.
import fs from 'node:fs';
import path from 'node:path';
import { fetchText } from './util.mjs';

export function cacheDir(ctx) { return path.join(ctx.workDir, '..', 'cache'); }

export function osvRecord(ctx, ecosystem, id) {
  const t = fetchText(`https://storage.googleapis.com/osv-vulnerabilities/${encodeURIComponent(ecosystem)}/${id}.json`, { cacheDir: cacheDir(ctx), cacheKey: `osv-${ecosystem}-${id}.json` });
  try { return t ? JSON.parse(t) : null; } catch { return null; }
}

let kev;
export function kevSet(ctx) {
  if (kev) return kev;
  const t = fetchText('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json', { cacheDir: cacheDir(ctx), cacheKey: 'kev.json' });
  try { kev = new Set(JSON.parse(t).vulnerabilities.map((v) => v.cveID)); } catch { kev = new Set(); }
  return kev;
}

/** Local advisory files in OSV format (a single record, an array, or {vulns:[...]}) for private/internal packages. */
export function localOsv(cfg) {
  const out = [];
  for (const f of cfg.feeds.local || []) {
    const p = path.resolve(cfg.projectDir, f);
    if (!fs.existsSync(p)) continue;
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    const list = Array.isArray(j) ? j : j.vulns || (j.id && j.affected ? [j] : []);
    out.push(...list);
  }
  return out;
}

export function cvssFromVector(vector) {
  return { vector, unauth: /PR:N/.test(vector || '') ? true : /PR:[LH]/.test(vector || '') ? false : null };
}
