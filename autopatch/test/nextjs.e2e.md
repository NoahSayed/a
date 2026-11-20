# Next.js adapter: end-to-end run

Needs network (npm registry, OSV mirror), the `claude` CLI, ports 3200-3299 free. Cost of a full run with `--model haiku`: about $0.04.
Fixture: `/home/user/a/autopatch-lab/website/fixture` (bakery shop; fictional packages) plus the files in `test/fixtures/nextjs-e2e/`
(config, OSV advisories with `database_specific.fixed_release`, order-notes probe).

## Set up (use a fresh dir; do not share it with other runs)
```bash
T=<scratch>/nextapp-e2e; AP=/home/user/a/autopatch; L=/home/user/a/autopatch-lab/website
mkdir -p $T/feeds && cp -r $L/fixture $T/nextapp && cp $L/registry/bakery-analytics-1.0.1.tgz $T/feeds/
cp $AP/test/fixtures/nextjs-e2e/bakery-advisories.osv.json $T/feeds/
cp $AP/test/fixtures/nextjs-e2e/autopatch.config.json $T/nextapp/
mkdir $T/nextapp/autopatch-probes && cp $AP/test/fixtures/nextjs-e2e/order-notes.mjs $T/nextapp/autopatch-probes/
cd $T/nextapp && git init -q -b main && git add -A && git commit -qm base   # package.json file: paths (vendor/*.tgz) are relative and need no change
npm ci --no-audit --no-fund
```
(The advisory feed is outside the project on purpose, so the git tree stays clean for `--promote`; the analytics tarball path in it is `../feeds/...`.)

## Run
```bash
node $AP/bin/autopatch.mjs scan --project $T/nextapp --work $T/work
node $AP/bin/autopatch.mjs fix  --project $T/nextapp --work $T/work --model haiku             # stage only
node $AP/bin/autopatch.mjs fix  --project $T/nextapp --work $T/work --model haiku --promote   # also approve with --approve <id|pkg> if a finding says NEEDS HUMAN APPROVAL
```
A `fix` run takes about 4-6 minutes. The report path is printed at the end. Servers use port 3200 (`server.port`); `ps` should show no `next-server` afterwards.

## Observed (2026-11-20)
| Finding | Outcome |
|---|---|
| next 14.2.24, 33 advisories (GHSA-f82v-jwr5-mffw is the worst, 9.1) | Smallest version clearing all 33: **15.5.29** (major). Release check clean, no AI needed, gate passes incl. "advisory cleared" for all 33 ids. STAGED. |
| postcss 8.4.31 (transitive, via next; 4 advisories) | Not in the ticket but found by npm audit. STAGED as `overrides: { postcss: "8.5.23" }`. |
| @bakery/order-notes 2.1.0 (no fix) | AI hotfix (haiku, ~$0.016, 11-16 turns): ownership guard in `app/api/orders/[id]/note/route.js` (+ a helper in lib/). Probe reports blocked before and after restart; owner edit still works. STAGED. |
| jsonwebtoken 8.5.1 (3 advisories) | Fix 9.0.0 (major) breaks login (500, 1024-bit key). AI repair (haiku, ~$0.01) made no change in 3 of 3 runs: it correctly declined to generate keys. **NOT STAGED**, gate failed, still vulnerable, human alerted. The sensitive-change detector path was not triggered end to end; it is covered by `assessChanges('+ crypto.generateKeyPairSync(...)')` -> `humanApprovalRequired: true`. |
| @bakery/analytics 1.0.0 | Fix 1.0.1 has postinstall + eval/new Function + child_process + remote fetch. **HELD** by the release check, never installed. |

Promotion (`--promote`): replayed 3 actions (next, postcss override, hotfix files) on a new git branch `autopatch/<timestamp>`, ran `npm test` and `next build` there, committed. `autopatch check --project <p> --dir <p>` afterwards: all 26 checks pass, including the "(after restart)" ones (session cookie issued before the restart still works after it).

> **Note (v0.2 policy change after this run):** autopatch now prefers the smallest version on the *installed major*
> that clears the most advisories, and every major upgrade needs `--approve`. On this fixture `next` therefore
> goes 14.2.24 → the 14.2.x release that clears the most advisories, and reports the rest (and 15.5.29 as the
> major that clears all) instead of jumping to 15.x automatically. The release check was also changed to a
> per-file comparison (14.2.35 and 15.5.29 are clean; the fictional analytics backdoor is still held).
