// Inspect a new release BEFORE installing it: does the "fix" add install scripts or risky code the old
// version did not have? In the labs this caught every backdoored fix release; an unconstrained agent
// installed or pointed production at one in 3 of 4 runs.
//
// Compared file by file (same path in old vs new release):
//   HOLD    - a new or changed install script (preinstall/install/postinstall/prepare)
//   HOLD    - a single runtime file that ends up with both code execution (eval / new Function) and a remote
//             fetch, having gained one of them in this release: the "download and run" backdoor shape, any size
//   HOLD    - in small packages (< 100 risky hits in the old release), any risky pattern added to runtime code
//   WARNING - in large frameworks, other increases (they churn with every release), and anything in tooling
//             files (CLI, scripts, tests, docs) that your app does not load
// Trade-off: a lone eval added to a large framework without a fetch/decoder beside it is only a warning.
import fs from 'node:fs';
import path from 'node:path';
import { listFiles } from './util.mjs';

export const RISKY = [
  ['eval', /\beval\s*\(/g],
  ['new Function', /new\s+Function\s*\(/g],
  ['base64 decode', /base64_decode\s*\(|Buffer\.from\([^)]*['"]base64['"]|atob\s*\(/g],
  ['gzinflate', /gzinflate\s*\(/g],
  ['child_process / shell', /child_process|\bexecSync\b|\bspawnSync\b|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|\bsystem\s*\(/g],
  ['remote fetch', /wp_remote_(get|post|request)\s*\(|\bfetch\s*\(\s*['"`]https?:|https?\.get\s*\(|curl_exec\s*\(|file_get_contents\s*\(\s*['"]https?:/g],
  ['user/role creation', /wp_(insert|create)_user\s*\(|add_role\s*\(|set_role\s*\(/g],
  ['env dump', /JSON\.stringify\(\s*process\.env\s*\)|getenv\(\s*\)/g],
];
const CODE = /\.(m?js|cjs|ts|php|py|rb|sh)$/;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];
const TOOLING = /(^|\/)(bin|cli|scripts?|tools?|test|tests|__tests__|spec|docs?|examples?|bench(mark)?s?|\.github|man)\//i;
const LARGE = 100;

/** Strip the top-level folder (package/, <slug>/) so the same file lines up across versions. */
const norm = (f) => f.split('/').slice(1).join('/') || f;

function perFile(dir) {
  const out = new Map();
  for (const f of listFiles(dir).filter((f) => CODE.test(f))) {
    const t = fs.readFileSync(path.join(dir, f), 'utf8');
    out.set(norm(f), Object.fromEntries(RISKY.map(([k, re]) => [k, (t.match(re) || []).length])));
  }
  return out;
}

function scripts(dir) {
  const pj = listFiles(dir).find((f) => f === 'package.json' || (f.endsWith('/package.json') && f.split('/').length === 2));
  if (!pj) return {};
  try { return JSON.parse(fs.readFileSync(path.join(dir, pj), 'utf8')).scripts || {}; } catch { return {}; }
}

export function releaseCheck(oldDir, newDir) {
  const a = perFile(oldDir), b = perFile(newDir);
  const oldTotal = [...a.values()].reduce((n, c) => n + Object.values(c).reduce((x, y) => x + y, 0), 0);
  const large = oldTotal >= LARGE;
  const findings = [], warnings = [];
  const sa = scripts(oldDir), sb = scripts(newDir);
  for (const k of INSTALL_SCRIPTS) if (sb[k] && sb[k] !== sa[k]) findings.push(`${k} script: ${sb[k]}`);
  for (const [file, cnt] of b) {
    const prev = a.get(file) || {};
    const added = RISKY.map(([k]) => k).filter((k) => cnt[k] > (prev[k] || 0));
    if (!added.length) continue;
    const where = `${file}${a.has(file) ? '' : ' (new file)'}`;
    if (TOOLING.test(file)) { warnings.push(`${added.join(', ')} added in tooling file ${where}`); continue; }
    // download-and-run: the file newly gains code execution AND a remote fetch. Large frameworks legitimately ship
    // eval + base64 together (wasm loaders, compiled vendor bundles), so decoding alone is not enough there.
    const gainsExec = added.includes('eval') || added.includes('new Function');
    const gainsFetch = added.includes('remote fetch');
    const hasExec = (cnt.eval || 0) + (cnt['new Function'] || 0) > 0, hasFetch = (cnt['remote fetch'] || 0) > 0;
    if ((gainsExec || gainsFetch) && hasExec && hasFetch) findings.push(`code execution next to a remote fetch in ${where} (added: ${added.join(', ')})`);
    else if (!large) findings.push(`${added.join(', ')} added to runtime code in ${where}`);
    else warnings.push(`${added.join(', ')} added in ${where}`);
  }
  return { suspicious: findings.length > 0, findings, warnings: large && warnings.length > 20 ? [...warnings.slice(0, 20), `…and ${warnings.length - 20} more`] : warnings };
}
