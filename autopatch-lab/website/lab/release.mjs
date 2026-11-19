// Release check: inspect the tarball of a proposed "fix" before it is installed anywhere.
// Compares the new release with the one in use: new install scripts, and risky code patterns that did not exist in the same file before.
import fs from 'node:fs';
import path from 'node:path';
import { sh, SCRATCH, safeRm } from './site.mjs';

export const CACHE = path.join(SCRATCH, 'cache');

const PATTERNS = {
  eval: /\beval\s*\(/,
  newFunction: /\bnew\s+Function\s*\(/,
  childProcess: /child_process|\bexecSync\s*\(|\bspawnSync\s*\(/,
  remoteFetch: /(?:https?\.(?:get|request)|\bfetch|axios\.get)\s*\(\s*['"`]https?:\/\//,
  remoteUrlLiteral: /require\(['"]https?['"]\)/,
  envDump: /JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries)\(\s*process\.env/,
};
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

/** Unpack a tarball (a local .tgz path, or an npm spec such as next@14.2.25) into a cached directory. Returns the package root. */
export function unpack(source, tag) {
  const dir = path.join(CACHE, 'unpacked', tag.replace(/[^\w.@-]/g, '_'));
  const root = path.join(dir, 'package');
  if (fs.existsSync(root)) return root;
  fs.mkdirSync(dir, { recursive: true });
  let tgz = source;
  if (!source.endsWith('.tgz')) {
    const r = sh('npm', ['pack', source, '--pack-destination', dir, '--silent'], { cwd: dir, timeout: 300e3 });
    if (r.code !== 0) throw new Error(`npm pack ${source} failed: ${r.err.slice(-300)}`);
    tgz = path.join(dir, r.out.trim().split('\n').pop());
  }
  const t = sh('tar', ['xzf', tgz, '-C', dir]);
  if (t.code !== 0) throw new Error(`tar failed: ${t.err}`);
  return root;
}

const TEXT = /\.(c|m)?js$|\.json$|\.sh$/;
function walk(d, base = d, out = []) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, base, out);
    else if (TEXT.test(e.name) && fs.statSync(p).size < 6e6) out.push(path.relative(base, p));
  }
  return out;
}

function patternsPerFile(root) {
  const out = new Map();
  for (const rel of walk(root)) {
    const t = fs.readFileSync(path.join(root, rel), 'utf8');
    const hit = Object.entries(PATTERNS).filter(([, re]) => re.test(t)).map(([k]) => k);
    if (hit.length) out.set(rel, new Set(hit));
  }
  return out;
}

export function releaseCheck(oldRoot, newRoot) {
  const pj = (r) => JSON.parse(fs.readFileSync(path.join(r, 'package.json'), 'utf8'));
  const a = pj(oldRoot), b = pj(newRoot);
  const hooks = (p) => INSTALL_HOOKS.filter((k) => p.scripts?.[k]).map((k) => `${k}: ${p.scripts[k]}`);
  const newHooks = hooks(b).filter((h) => !hooks(a).includes(h));
  const before = patternsPerFile(oldRoot), after = patternsPerFile(newRoot);
  const introduced = [];
  for (const [file, set] of after) {
    const prev = before.get(file) || new Set();
    for (const k of set) if (!prev.has(k)) introduced.push(`${file}: ${k}`);
  }
  const problems = [];
  if (newHooks.length) problems.push(`new install script(s): ${newHooks.join('; ')}`);
  if (introduced.length) problems.push(`risky code patterns not present before: ${introduced.slice(0, 6).join('; ')}${introduced.length > 6 ? ` (+${introduced.length - 6} more)` : ''}`);
  return { suspicious: problems.length > 0, problems, newInstallScripts: newHooks, introduced, filesBefore: before.size, filesAfter: after.size };
}

/** Changelog / release text of the new version, as untrusted text for the AI: whatever the tarball ships. */
export function releaseNotes(newRoot, fromVersion, toVersion) {
  for (const n of ['CHANGELOG.md', 'CHANGELOG', 'HISTORY.md', 'README.md']) {
    const p = path.join(newRoot, n);
    if (!fs.existsSync(p)) continue;
    const t = fs.readFileSync(p, 'utf8');
    if (n.startsWith('README')) return `(README.md of ${toVersion})\n` + t.slice(0, 1500);
    const i = t.indexOf(toVersion);
    const j = t.indexOf(fromVersion, i + 1);
    return t.slice(Math.max(i, 0), j > i ? j : (i < 0 ? 3000 : i + 3000)).slice(0, 3500);
  }
  return '(this release ships no changelog)';
}
