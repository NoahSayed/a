// Prints the scoreboard (markdown) from results/all-runs.json.
import fs from 'node:fs';
import path from 'node:path';
const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const runs = JSON.parse(fs.readFileSync(path.join(ROOT, 'results/all-runs.json'), 'utf8')).filter((r) => r.hidden);
const short = (o) => (o || '').replace(/^SHIPPED: bump to ([\d.]+) \+ AI repair.*/, 'shipped $1 + AI repair').replace(/^SHIPPED: bump to ([\d.]+)/, 'shipped $1').replace(/^SHIPPED: app-level guard \+ AI guard/, 'shipped AI guard').replace(/^REFUSED.*/, 'refused (release check)').replace(/^NOT SHIPPED: no fix exists and no AI.*/, 'no fix, left for human').replace(/^NOT SHIPPED.*/, 'not shipped (gate)').replace(/^ROLLED BACK.*/, 'rolled back');
const order = ['A', 'B', 'Binj', 'E', 'D', 'R'];
runs.sort((a, b) => order.indexOf(a.arm) - order.indexOf(b.arm) || a.run.localeCompare(b.run, undefined, { numeric: true }));
const out = ['| Run | Hidden | Security | Function | Integrity | Supply-chain | AI cost | Time | next | jsonwebtoken | order-notes | analytics |', '|---|---|---|---|---|---|---|---|---|---|---|---|'];
for (const r of runs) {
  const it = (p) => short(r.items.find((i) => i.pkg === p)?.outcome) || (r.arm === 'D' ? 'n/a (no pipeline)' : '-');
  out.push(`| ${r.run} | ${r.hidden.total} | ${r.hidden.security} | ${r.hidden.function} | ${r.hidden.integrity} | ${r.hidden.supplyChain} | $${r.aiCostUsd.toFixed(3)} | ${r.minutes} min | ${it('next')} | ${it('jsonwebtoken')} | ${it('@bakery/order-notes')} | ${it('@bakery/analytics')} |`);
}
console.log(out.join('\n'));
console.log('\nFailed hidden checks per run:');
for (const r of runs) console.log(`- ${r.run}: ${r.hidden.failed.join('; ') || 'none'}`);
