// Helpers to build, copy, serve and query the lab WordPress site.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const LAB = path.dirname(new URL(import.meta.url).pathname);
export const ROOT = path.join(LAB, '..');
export const FIX = path.join(ROOT, 'fixtures');
export const SCRATCH = process.env.WPLAB_SCRATCH || '/tmp/wplab';
export const WPCLI = path.join(SCRATCH, 'wp-cli.phar');

export function sh(cmd, args, opts = {}) {
  const t = Date.now();
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64e6, ...opts });
  return { code: r.status, out: r.stdout || '', err: r.stderr || '', ms: Date.now() - t };
}

export function wp(dir, args, port = 8081) {
  return sh('php', [WPCLI, '--allow-root', `--path=${dir}`, ...args], { env: { ...process.env, LAB_PORT: String(port) } });
}

export function zipPath(slug, version, variant = '') {
  return path.join(SCRATCH, 'repo', `${slug}.${version}${variant}.zip`);
}

/** Build the plugin "repository" (zips) and the base site once. */
export function buildBase() {
  const base = path.join(SCRATCH, '_base-site');
  if (fs.existsSync(path.join(base, 'wp-content/database/.ht.sqlite'))) return base;
  if (!fs.existsSync(WPCLI)) throw new Error(`put wp-cli.phar at ${WPCLI}`);
  const core = process.env.WP_CORE_DIR; // checkout of github.com/WordPress/WordPress
  const sqlitePkg = process.env.WP_SQLITE_DIR; // checkout of github.com/WordPress/sqlite-database-integration
  // repo of plugin zips
  const repo = path.join(SCRATCH, 'repo');
  fs.mkdirSync(repo, { recursive: true });
  for (const slug of fs.readdirSync(path.join(FIX, 'plugins'))) {
    for (const v of fs.readdirSync(path.join(FIX, 'plugins', slug)).filter((d) => /^\d/.test(d))) {
      const tmp = path.join(SCRATCH, '_zip', slug);
      fs.rmSync(path.join(SCRATCH, '_zip'), { recursive: true, force: true });
      fs.mkdirSync(tmp, { recursive: true });
      fs.cpSync(path.join(FIX, 'plugins', slug, v), tmp, { recursive: true });
      sh('zip', ['-qr', zipPath(slug, v), slug], { cwd: path.join(SCRATCH, '_zip') });
      if (slug === 'simple-gallery' && v === '3.0.0') { // poisoned-changelog variant of the same release
        fs.copyFileSync(path.join(FIX, 'plugins', slug, 'readme.injected.txt'), path.join(tmp, 'readme.txt'));
        sh('zip', ['-qr', zipPath(slug, v, '-injected'), slug], { cwd: path.join(SCRATCH, '_zip') });
      }
    }
  }
  // WordPress core + SQLite drop-in
  fs.rmSync(base, { recursive: true, force: true });
  fs.cpSync(core, base, { recursive: true, filter: (p) => !p.includes('/.git') });
  const sq = path.join(base, 'wp-content/plugins/sqlite-database-integration');
  fs.cpSync(path.join(sqlitePkg, 'packages/plugin-sqlite-database-integration'), sq, { recursive: true, dereference: false });
  fs.rmSync(path.join(sq, 'wp-includes/database'), { force: true, recursive: true });
  fs.cpSync(path.join(sqlitePkg, 'packages/mysql-on-sqlite/src'), path.join(sq, 'wp-includes/database'), { recursive: true });
  fs.writeFileSync(path.join(base, 'wp-content/db.php'), fs.readFileSync(path.join(sq, 'db.copy'), 'utf8')
    .replace('{SQLITE_IMPLEMENTATION_FOLDER_PATH}', '/nonexistent-use-relative').replace('{SQLITE_PLUGIN}', 'sqlite-database-integration/load.php'));
  fs.writeFileSync(path.join(base, 'wp-config.php'), `<?php
define('DB_NAME','wp'); define('DB_USER','x'); define('DB_PASSWORD','x'); define('DB_HOST','localhost');
define('DB_CHARSET','utf8'); define('DB_COLLATE','');
define('DB_DIR', __DIR__ . '/wp-content/database/'); define('DB_FILE','.ht.sqlite');
define('AUTH_KEY','lab-auth-key-7f3a'); define('SECURE_AUTH_KEY','lab2'); define('LOGGED_IN_KEY','lab3'); define('NONCE_KEY','lab4');
define('AUTH_SALT','lab5'); define('SECURE_AUTH_SALT','lab6'); define('LOGGED_IN_SALT','lab7'); define('NONCE_SALT','lab8');
// Each copy (production / staging) is served on its own port; no search-replace needed in the lab.
$lab_port = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : (getenv('LAB_PORT') ?: '8081');
define('WP_HOME', 'http://127.0.0.1:' . $lab_port); define('WP_SITEURL', 'http://127.0.0.1:' . $lab_port);
define('WP_DEBUG', true); define('WP_DEBUG_LOG', __DIR__ . '/wp-content/debug.log'); define('WP_DEBUG_DISPLAY', false);
define('AUTOMATIC_UPDATER_DISABLED', true); define('WP_HTTP_BLOCK_EXTERNAL', true); define('DISALLOW_FILE_EDIT', true);
$table_prefix = 'wp_';
if ( ! defined('ABSPATH') ) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`);
  must(wp(base, ['core', 'install', '--url=http://127.0.0.1:8081', '--title=Lab Bakery', '--admin_user=owner', '--admin_password=owner-pass-123', '--admin_email=owner@example.invalid', '--skip-email']));
  fs.cpSync(path.join(FIX, 'theme/bakery'), path.join(base, 'wp-content/themes/bakery'), { recursive: true });
  must(wp(base, ['theme', 'activate', 'bakery']));
  fs.cpSync(path.join(FIX, 'uploads'), path.join(base, 'wp-content/uploads'), { recursive: true });
  for (const [slug, v] of [['quick-contact', '1.0.0'], ['simple-gallery', '2.0.0'], ['old-forms', '1.4.2'], ['seo-helper', '1.1.0']]) {
    must(wp(base, ['plugin', 'install', zipPath(slug, v), '--activate']));
  }
  for (const [title, body] of [['Contact', '[quick_contact]'], ['Gallery', '[simple_gallery]'], ['Newsletter', '[old_form]'], ['About', 'Fresh bread daily. [seo_note text="bakery"]']]) {
    must(wp(base, ['post', 'create', '--post_type=page', '--post_status=publish', `--post_title=${title}`, `--post_content=${body}`]));
  }
  fs.mkdirSync(path.join(base, 'wp-content/mu-plugins'), { recursive: true });
  fs.writeFileSync(path.join(base, 'wp-content/debug.log'), '');
  return base;
}

function must(r) { if (r.code !== 0) throw new Error(r.out + r.err); return r; }

export function copySite(from, to) {
  fs.rmSync(to, { recursive: true, force: true });
  fs.cpSync(from, to, { recursive: true });
  fs.writeFileSync(path.join(to, 'wp-content/debug.log'), '');
}

const servers = new Map();
export async function serve(dir, port) {
  await stop(port);
  const p = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', dir], { stdio: 'ignore', detached: true });
  servers.set(port, p);
  for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${port}/wp-login.php`); return; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  throw new Error(`server on ${port} did not start`);
}
export async function stop(port) {
  const p = servers.get(port);
  if (p) { try { process.kill(-p.pid); } catch {} servers.delete(port); }
  sh('bash', ['-c', `pkill -f "php -S 127.0.0.1:${port}" || true`]);
  await new Promise((r) => setTimeout(r, 200));
}

export async function http(port, pathAndQuery, { method = 'GET', form, cookie } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  let body;
  if (form) { body = new URLSearchParams(form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
  const r = await fetch(`http://127.0.0.1:${port}${pathAndQuery}`, { method: form ? 'POST' : method, headers, body, redirect: 'manual' });
  return { status: r.status, text: await r.text(), headers: r.headers };
}

export function hashDir(dir) {
  const h = crypto.createHash('sha256');
  const walk = (d, rel = '') => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p, rel + e.name + '/');
      else { h.update(rel + e.name); h.update(fs.readFileSync(p)); }
    }
  };
  walk(dir);
  return h.digest('hex');
}

export function officialPluginHashes() {
  const out = {};
  for (const slug of fs.readdirSync(path.join(FIX, 'plugins'))) {
    out[slug] = {};
    for (const v of fs.readdirSync(path.join(FIX, 'plugins', slug)).filter((d) => /^\d/.test(d))) out[slug][v] = hashDir(path.join(FIX, 'plugins', slug, v));
    if (slug === 'simple-gallery') { // the poisoned-readme build of 3.0.0 is also an "official" artifact
      const tmp = path.join(SCRATCH, '_hash-inj');
      fs.rmSync(tmp, { recursive: true, force: true });
      fs.cpSync(path.join(FIX, 'plugins', slug, '3.0.0'), tmp, { recursive: true });
      fs.copyFileSync(path.join(FIX, 'plugins', slug, 'readme.injected.txt'), path.join(tmp, 'readme.txt'));
      out[slug]['3.0.0-injected'] = hashDir(tmp);
    }
  }
  return out;
}
