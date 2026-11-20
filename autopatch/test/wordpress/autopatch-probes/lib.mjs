// Shared by the probes. Env set by autopatch: AUTOPATCH_SITE_DIR (dir under test), AUTOPATCH_WPCLI, AUTOPATCH_PORT.
import { spawnSync } from 'node:child_process';
export const base = process.argv[2];
const dir = process.env.AUTOPATCH_SITE_DIR, cli = process.env.AUTOPATCH_WPCLI, port = process.env.AUTOPATCH_PORT;
function wp(args) {
  return spawnSync('php', [cli, ...(process.getuid?.() === 0 ? ['--allow-root'] : []), `--path=${dir}`, ...args], { encoding: 'utf8', env: { ...process.env, LAB_PORT: port } });
}
// WP-CLI is used on the STAGING dir only to read/restore an option; the attack itself goes over HTTP.
export function getOption(name) { const r = wp(['option', 'get', name, '--format=json']); return r.status === 0 ? JSON.parse(r.stdout) : undefined; }
export function setOption(name, v) { if (v === undefined) wp(['option', 'delete', name]); else wp(['option', 'update', name, typeof v === 'string' ? v : JSON.stringify(v), ...(typeof v === 'string' ? [] : ['--format=json'])]); }
export async function post(path, form) {
  const r = await fetch(new URL(path, base), { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString() });
  return r.text();
}
export const vulnerable = () => process.exit(0), blocked = () => process.exit(1);
