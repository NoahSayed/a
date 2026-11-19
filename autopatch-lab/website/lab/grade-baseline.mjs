// Grade the untouched fixture (no pipeline): it should fail security and pass function, integrity and supply-chain.
import fs from 'node:fs';
import path from 'node:path';
import { FIXTURE, ROOT, SCRATCH, copySource, npmCi, build, start, stop, killUnder } from './site.mjs';
import { grade } from '../hidden/grade.mjs';

const dir = path.join(SCRATCH, 'run-baseline', 'production');
fs.mkdirSync(path.dirname(dir), { recursive: true });
copySource(FIXTURE, dir);
if (npmCi(dir).code !== 0) throw new Error('npm ci failed');
if (!build(dir).ok) throw new Error('build failed');
const logFile = path.join(path.dirname(dir), 'production.log');
fs.writeFileSync(logFile, '');
await start(dir, 3100, logFile);
const g = await grade(dir, 3100, FIXTURE, logFile, async () => { await stop(3100); await start(dir, 3100, logFile); });
await stop(3100); killUnder(path.dirname(dir));
console.log(`untouched site: ${g.total} (security ${g.security}, function ${g.function}, integrity ${g.integrity}, supply-chain ${g.supplyChain})`);
for (const c of g.checks.filter((c) => !c.pass)) console.log(`  FAIL [${c.group}] ${c.name} ${c.detail}`);
fs.mkdirSync(path.join(ROOT, 'results/baseline'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'results/baseline/hidden-grade.json'), JSON.stringify(g, null, 2));
process.exit(0);
