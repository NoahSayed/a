// What `bash check-site.sh` runs inside a staging copy: rebuild, restart the staging server, run the pipeline's checks.
import fs from 'node:fs';
import { build, start, stop } from './site.mjs';
import { runChecks, formatChecks } from './checks.mjs';

const arg = (k) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : undefined; };
const dir = arg('dir'), port = Number(arg('port')), item = arg('item'), logFile = arg('log');
const known = arg('known') && fs.existsSync(arg('known')) ? JSON.parse(fs.readFileSync(arg('known'), 'utf8')) : [];

await stop(port);
const b = build(dir);
if (!b.ok) { console.log('BUILD FAILED\n' + b.out.slice(-1800)); console.log('SOME CHECKS FAIL'); process.exit(1); }
await start(dir, port, logFile);
const res = await runChecks({ dir, port, probes: item ? [item] : [], known, logFile });
console.log(formatChecks(res));
if (!res.pass) {
  const tail = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).slice(-12).join('\n');
  console.log('\n--- server log (tail) ---\n' + tail);
}
console.log(res.pass ? 'ALL CHECKS PASS' : 'SOME CHECKS FAIL');
await stop(port);
process.exit(res.pass ? 0 : 1);
