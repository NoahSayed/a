# autopatch

**Security updates for your npm app, Next.js site or WordPress site: staged on a copy, checked by real tests,
shipped only when you say so.**

autopatch reads security advisories for what you actually run. For each one it:

1. picks the smallest fix, staying on your current major version when it can;
2. inspects the new release for backdoors before installing it;
3. applies it to a **staging copy**;
4. runs your checks, then restarts the app and runs them again.

AI is only used where code needs judgment, and only on the copy:
- **repair:** an update broke your own code;
- **hotfix:** no fixed version exists.

Nothing touches your project until you pass `--promote`. Then code projects get a new git branch, and sites get
a backup plus automatic rollback.

It's the tool version of the experiments in [`../autopatch-lab`](../autopatch-lab/README.md). With the pipeline,
one cheap AI session scored perfect or near-perfect in every lab. Without the pipeline, the same AI broke live
sites and installed a backdoored "fix".

## Quick start

```bash
cd your-project
node /path/to/autopatch/bin/autopatch.mjs init --adapter npm      # or nextjs, wordpress; then edit the config
node /path/to/autopatch/bin/autopatch.mjs scan                    # what affects you (changes nothing)
node /path/to/autopatch/bin/autopatch.mjs fix --model haiku       # stage + verify fixes on a copy, print a report
node /path/to/autopatch/bin/autopatch.mjs fix --approve <id> --promote   # ship what passed (+ approved items)
```

Needs Node 20+. The AI step uses [Claude Code](https://code.claude.com) headless (`claude -p`). Run it with an
**API key** for anything unattended or that serves other people; subscription logins are for your own
interactive use. Use `--no-ai` to run without any model.

## What happens to each advisory

| Situation | What autopatch does |
|---|---|
| Safe update, checks pass | **STAGED**, promoted with `--promote` |
| Update breaks your code | AI **repair** on staging, limited to `ownedPaths`. If checks then pass: STAGED |
| No fixed version exists | AI **hotfix**: a scoped guard in your own code (e.g. a WordPress must-use plugin, a route guard) |
| The "fix" release adds install scripts, or download-and-run code | **HELD**, human alerted. Never installed |
| Major upgrade, or AI touched keys, secrets, env, users/roles, eval or remote calls | **NEEDS HUMAN APPROVAL** (`--approve <id>`) |
| Routine fix released less than `cooldownDays` ago | **HELD** until it ages (poisoned releases get caught in that window) |
| Gate still failing | **NOT STAGED**, still vulnerable, human alerted (the AI is told to stop rather than weaken security) |

The **urgent** lane (skips the cooldown): known exploited (CISA KEV), or exploitable without login at high or
critical severity, in an active component.

## The gate (why changes are trusted)

- **Baseline first.** Things already broken don't block a fix; only new breakage does.
- **Your checks.** Tests, a build, pages, HTTP flows (login, forms, checkout) and the advisory re-scan.
- **Exploit probes.** Scripts that exit 0 if the bug still works. You can have an AI draft them: see
  `../autopatch-lab/experiments`, where adding "fixes may be incomplete, try variants" to the prompt made 18/18
  probes catch incomplete fixes.
- **Integrity.** Dependency set and package scripts unchanged; for WordPress, plugin files byte-identical to an
  official release, no new admins, `wp-config.php` unchanged; no dangerous code in owned paths.
- **Restart, then check again.** This catches fixes that only work until the next restart, e.g. a key generated at
  boot that kills every session.

## Adapters

| Adapter | Finds advisories via | Applies fixes via | Ships via | Tested on |
|---|---|---|---|---|
| `npm` | `npm audit` (GitHub advisory DB) + OSV + local OSV files | `npm install pkg@ver --save-exact` (or `overrides` for transitive deps) | new git branch | lab app: hidden grader 9/9 |
| `nextjs` | as npm | as npm, plus `next build` / `next start` | new git branch | lab Next.js shop (`test/nextjs.e2e.md`) |
| `wordpress` | Wordfence Intelligence v3 (local file or API key) | WP-CLI plugin install from zip | backup, replay on production, smoke check, rollback | lab bakery site: hidden grader 29/29 (`test/wordpress.e2e.md`) |

Write your own: [`docs/ADAPTERS.md`](docs/ADAPTERS.md).

## Configuration

`autopatch.config.json` in your project (templates in `templates/`):

```jsonc
{
  "adapter": "nextjs",
  "ownedPaths": ["app/**", "lib/**"],          // the only files the AI may change
  "ai": { "enabled": true, "model": "haiku" }, // haiku matched sonnet in every lab at ~1/10 the cost
  "policy": { "cooldownDays": 3 },
  "checks": { "test": "npm test", "pages": [...], "flows": [...], "probes": [...], "restartCheck": true },
  "feeds": { "local": ["advisories/internal.json"] },  // OSV files for private packages
  "server": { "port": 3200 }
}
```

## Known limits (v0.2)

- **WordPress staging is SQLite file-copy only.** `mysql-export` staging (DB export/import plus `wp search-replace`)
  is a stub.
- **Live Wordfence/KEV feeds** need network access to those hosts. EPSS isn't used yet.
- **Large frameworks.** The release check holds on install scripts and "download-and-run" code in any package, but
  in large frameworks a lone new `eval` without a fetch next to it is only a warning.
- **Smallest fix.** When no version on your major clears every advisory, autopatch takes the one that clears the
  most and reports what's left and which major would clear all of it.
- **Text-only models.** Repair and hotfix need a tool-using agent (Claude Code). OpenAI-compatible endpoints,
  including open-weight models such as DeepSeek or Qwen, aren't wired in and weren't tested. They would fit advisory
  triage first.
- **Unit tests.** `npm test` covers the safety rules (release check, sensitive changes, lanes, gate). The
  end-to-end runs are documented in `test/*.e2e.md`.
