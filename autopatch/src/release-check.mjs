// Inspect a new release BEFORE installing it: does the "fix" add install scripts or risky code the old
// version did not have? In the labs this caught every backdoored fix release; an unconstrained agent
// installed or pointed production at one in 3 of 4 runs.
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

// Files a package ships for its own tooling (CLI, build scripts, tests, docs) are not loaded by your app.
// A risky pattern appearing there is a warning; appearing in runtime code it is a hold.
const TOOLING = /(^|\/)(bin|cli|scripts?|tools?|test|tests|__tests__|spec|docs?|examples?|bench(mark)?s?|\.github|man|build)\//i;

function scan(dir) {
  const runtime = Object.fromEntries(RISKY.map(([k]) => [k, 0]));
  const tooling = Object.fromEntries(RISKY.map(([k]) => [k, 0]));
  for (const f of listFiles(dir).filter((f) => CODE.test(f))) {
    const t = fs.readFileSync(path.join(dir, f), 'utf8');
    const bucket = TOOLING.test(f) ? tooling : runtime;
    for (const [k, re] of RISKY) bucket[k] += (t.match(re) || []).length;
  }
  return { runtime, tooling };
}

function scripts(dir) {
  const pj = listFiles(dir).find((f) => f === 'package.json' || f.endsWith('/package.json') && f.split('/').length === 2);
  if (!pj) return {};
  try { return JSON.parse(fs.readFileSync(path.join(dir, pj), 'utf8')).scripts || {}; } catch { return {}; }
}

/** Compare old vs new unpacked release directories. */
export function releaseCheck(oldDir, newDir) {
  const a = scan(oldDir), b = scan(newDir);
  const intro = (bucket) => Object.keys(b[bucket]).filter((k) => b[bucket][k] > a[bucket][k]);
  const rt = intro('runtime'), tl = intro('tooling');
  const sa = scripts(oldDir), sb = scripts(newDir);
  const newInstall = INSTALL_SCRIPTS.filter((k) => sb[k] && sb[k] !== sa[k]).map((k) => `${k} script: ${sb[k]}`);
  const all = new Set([...rt, ...tl]);
  const combo = (all.has('eval') || all.has('new Function')) && all.has('remote fetch') ? ['eval/new Function together with remote fetch'] : [];
  const findings = [...newInstall, ...combo, ...rt.map((k) => `${k} in runtime code (${a.runtime[k]} → ${b.runtime[k]})`)];
  const warnings = tl.map((k) => `${k} in tooling files (${a.tooling[k]} → ${b.tooling[k]})`);
  return { suspicious: findings.length > 0, findings, warnings };
}
