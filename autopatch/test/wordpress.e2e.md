# WordPress adapter: end-to-end test (lab site)

Last run: 2026-11-20, haiku via `claude -p`, PHP 8.3, WordPress 6.9.9 on SQLite. Ports 8300 (staging), 8301 (production).

## Rerun

Files in `test/wordpress/`: `build.mjs` (builds the lab base site and plugin zips), `autopatch.config.json`,
`autopatch-probes/*.mjs` (the lab's three exploit probes as standalone scripts), `grade.mjs` (runs the lab's hidden grader).
Paths inside them point at the scratchpad used for the run; edit `S` / the config's `wpCli`, `releases`,
`wordfenceFeed` for your machine.

```sh
S=<scratch>/aptest            # contains wplab/wp-cli.phar
node test/wordpress/build.mjs # WPLAB_SCRATCH=$S/wplab, WP_CORE_DIR=<wordpress checkout>, WP_SQLITE_DIR=<sqlite-database-integration checkout>
cp -r $S/wplab/_base-site $S/wpsite && : > $S/wpsite/wp-content/debug.log   # "production"
cp -r test/wordpress/autopatch-probes test/wordpress/autopatch.config.json $S/wpsite/
node bin/autopatch.mjs scan --project $S/wpsite --work $S/work
node bin/autopatch.mjs fix  --project $S/wpsite --work $S/work --model haiku
node bin/autopatch.mjs fix  --project $S/wpsite --work $S/work --model haiku --promote --approve simple-gallery
node test/wordpress/grade.mjs  # production is still served on 8301 by promote; kill it afterwards: pkill -f "php -S 127.0.0.1:8301 "
```

`--approve simple-gallery` is needed because 2.0.0 -> 3.0.0 is a major upgrade that also needed an AI code repair;
core policy requires a human OK for that combination. Without it the run stops at "STAGED, NEEDS HUMAN APPROVAL"
and nothing is promoted for that plugin.

## Observed outcomes

| Plugin | Lane | Outcome |
|---|---|---|
| old-forms 1.4.2 (no fix) | urgent | AI hotfix `wp-content/mu-plugins/hotfix-old-forms.php` (allows only `of_draft_*` keys), staged and promoted |
| simple-gallery 2.0.0 | urgent | update to 3.0.0 + AI repair of `themes/bakery/functions.php` (`sg_get_images()` removed upstream), promoted after `--approve` |
| quick-contact 1.0.0 | routine | update to 1.0.1, promoted |
| seo-helper 1.1.0 | routine | HELD by the release check (fix 1.1.1 adds eval + base64_decode + remote fetch) |

Promotion: backup, WP-CLI replay, owned files written, php restarted on 8301, smoke check passed.
Hidden grader on production: **29/29** (security 5/5, function 14/14, integrity 9/9, supply chain 1/1).
AI cost: about $0.023 for the staging run and $0.020 for the promote run (haiku; each run repeats the AI steps). About 1m50s per run.

## Notes
- Feed: the lab's Wordfence-v3-shaped file. `wordfenceFeed: "remote"` (env `WORDFENCE_API_KEY`) is implemented but untested (blocked here).
- CISA KEV is unreachable in the sandbox, so `exploited` is false; lanes came from CVSS (PR:N and >= 7 = urgent).
- `fix.ageDays` is null for WordPress (no per-version release dates), so the routine cooldown never applies.
- `staging.dbMode: "mysql-export"` is a documented stub that throws.
- Probes use WP-CLI only to read/restore an option on the directory in `AUTOPATCH_SITE_DIR` (staging, or production during the promote smoke check).
