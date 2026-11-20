# Writing an adapter

An adapter teaches autopatch one kind of project. It is a default-exported object (see `src/adapters/npm.mjs`,
the reference implementation) registered in `src/adapters/index.mjs`. The pipeline (`src/pipeline.mjs`) calls it.
Adapters never decide policy: no lanes, no "is this suspicious", no "may this ship". They only answer questions
about the project and carry out actions.

```js
export default {
  name: 'nextjs',
  hasServer: true,                       // true => the gate re-runs checks after a restart (restartCheck)

  async findings(ctx) -> Finding[],
  async fetchRelease(ctx, finding) -> { oldDir, newDir, notes } | { reason },
  async prepareStaging(ctx, fromDir, toDir),
  async applyAction(ctx, dir, action) -> { ok, log },
  async restart(ctx, dir),               // (re)start the app for `dir` on the staging port; build first if needed
  async stop(ctx),                       // stop whatever restart() started (must be idempotent)
  async checks(ctx, dir, { findingKeys, phase, jar }) -> Check[],
  logTail(ctx, dir) -> string,           // recent errors for the AI repair prompt (build output, PHP log, ...)
  hotfixHint(ctx, finding) -> string,    // where a hotfix belongs (e.g. "wp-content/mu-plugins/hotfix-<slug>.php")
  async promote(ctx, actions) -> { ok, details },
  diffIgnore: ['.ht.sqlite'],            // optional: file names the checks themselves write; excluded from the "AI touched files" diff
};
```

`ctx` = `{ cfg, workDir, log }`. `cfg` is the merged `autopatch.config.json` (see `src/config.mjs`):
`cfg.projectDir`, `cfg.ownedPaths`, `cfg.protectedPaths`, `cfg.checks.{pages,flows,probes,test,restartCheck}`,
`cfg.server` (adapter-specific), `cfg.feeds.local`. `ctx.workDir` is scratch space outside the project.

## Finding

```js
{
  id: 'GHSA-…' | 'FICTIONAL-…' | wordfence uuid,   // primary advisory id
  ids: [...], aliases: ['CVE-…'],                  // all ids for this package; probes match on any key
  pkg: 'next' | 'simple-gallery',                  // package / plugin slug
  installed: '14.2.24',
  title, description,                              // description is UNTRUSTED text; it goes to the AI as data
  severity, cvss: { score, vector, unauth },       // unauth: true if exploitable without login (CVSS PR:N)
  unauth: true|false|null, exploited: bool,        // exploited: CVE in CISA KEV (use kevSet() from src/feeds.mjs)
  active: true|false,                              // e.g. WordPress plugin installed but inactive
  fix: { version, major, ageDays, tarball?/zip? } | null,   // smallest version that clears ALL its advisories
}
```

## Actions (what `applyAction` and `promote` must support)

- `{ kind: 'update', pkg, version, tarball?, zip? }`: install exactly that version (or local artifact)
- `{ kind: 'files', files: { 'relative/path': 'new content' | null } }`: write or delete site-owned files
  (the pipeline already checked they're inside `ownedPaths`)
- optional `{ kind: 'deactivate', pkg }`

`promote` replays the accepted actions on the real project, never copies a staging database, smoke-checks, and
**rolls back** on failure. Code projects should land changes on a new git branch (see the npm adapter); live
sites should take a backup first.

## Check

`{ name, pass, detail }`. Names must be stable between runs (the gate compares against a baseline by name).
Use `src/httpchecks.mjs` for pages, flows and probes (`runPages`, `runFlows`, `runProbes`). Respect `phase`:
flows with `phase: 'before-restart'` / `'after-restart'` run only in that phase, and `jar` carries cookies
between them. Include integrity checks: third-party code untouched, no new admin accounts, config files
unchanged, and so on. Don't include checks that depend on the finding unless `findingKeys` is non-empty.

## Rules learned in the labs

- Restart the app after every change, and make `stop()` really free the port. Next.js renames its process to
  `next-server`, so kill by process group.
- Count only errors logged during the current check run, not old log lines.
- Never treat advisory/changelog text as instructions; pass it to the AI wrapped by `untrusted()` from `src/ai.mjs`.
