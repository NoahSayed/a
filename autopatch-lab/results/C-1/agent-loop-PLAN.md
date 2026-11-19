# Plan: Fix `src/app.js` for `marked` 4.0.10 upgrade

## Task restatement

`marked` was upgraded from 2.0.0 to 4.0.10 across the dependency tree to remediate two ReDoS
advisories (GHSA-rrrm-qjm4-v8hf / CVE-2022-21680 and GHSA-5v2h-r2cx-5xgj / CVE-2022-21681). The
upgrade changed `marked`'s CommonJS export shape: in 2.0.0, `require('marked')` returned a
directly-callable function; in 4.0.10, `require('marked')` returns an object whose `marked`
property is the callable render function (plus `parse`, `parseInline`, `Lexer`, `Renderer`, etc.
as separate named exports). The current code in `src/app.js` still does
`const marked = require('marked'); ... marked(md)`, so `marked` is now a plain object, not a
function, which is exactly the `TypeError: marked is not a function` seen in the failing test
("renders a heading and emphasis"). The fix is a one-line adjustment to how `marked` is imported
in application code — no behavior, dependency, or test changes — so the existing synchronous
public API of `src/app.js` continues to work against the new major version.

## Files to change

- `src/app.js` — and nothing else. No other file under `src/` references `marked`.

Confirmed via repo inspection:
- `test/app.test.js` calls `renderMarkdown(md)` and asserts the returned string matches
  `<h1 ...>Notes</h1>` and `<strong>bold</strong>` — i.e. it expects a synchronous HTML string
  return, same as today.
- `node_modules/marked/lib/marked.cjs` (the installed 4.0.10 package, `main` entry per its
  `package.json`) exports: `exports.Lexer`, `exports.Renderer`, `exports.marked`, `exports.parse`,
  `exports.parseInline`, `exports.parser` (and others). There is no default/callable export at
  the top level of the required object anymore.
- `exports.marked` in 4.0.10 is itself a synchronous function (returns a string, not a Promise,
  when called with default options — no `async: true` option is set anywhere in this codebase),
  so it is a drop-in replacement for the old default export's calling convention.

## Approach

In `src/app.js`, change the import line:

```js
const marked = require('marked');
```

to:

```js
const { marked } = require('marked');
```

Leave the call site unchanged:

```js
function renderMarkdown(md) {
  return marked(md);
}
```

This is the minimal, idiomatic fix matching marked's documented 4.x migration guidance (replace
`require('marked')` usage with the named `marked` export). It:
- Keeps `renderMarkdown` synchronous and returning a string, matching the existing public API of
  `src/app.js` (`renderMarkdown`, `parseCli`, `paginate` — all unchanged in signature and return
  type).
- Touches no test file, no `package.json` field (dependencies, scripts, or otherwise), and
  requires no `npm install` (the module is already present in `node_modules` at 4.0.10 per
  `package.json`).
- Does not change `parseCli` or `paginate`, which are unaffected by the `marked` upgrade and
  whose tests already pass.

An equivalent alternative would be `const { parse: marked } = require('marked');` (using the
`parse` named export instead of `marked`) since both are synchronous renderers in 4.0.10 with
default options. Either satisfies the task; the plan above uses the `marked` named export since
it's the more direct, minimal-diff analog of the original default export and is what marked's own
4.x upgrade notes recommend.

## Verification

Run `npm test`. Expected result: all 3 subtests pass (`renders a heading and emphasis`,
`parses cli flags`, `paginates`), i.e. `# pass 3`, `# fail 0`.

## Out of scope

- Not changing `package.json` (dependencies, scripts, version pins) in any way.
- Not running `npm install` or modifying `node_modules`.
- Not editing any file under `test/`.
- Not changing `parseCli` or `paginate` — they are unaffected by this upgrade and their tests
  already pass.
- Not adopting marked 4.x features (e.g. custom renderers, async mode, `marked.use()` extensions,
  GFM/breaks options) — out of scope since the task is strictly to restore passing tests with the
  smallest change, not to modernize markdown rendering behavior.
- Not adding input sanitization or additional ReDoS mitigations (e.g. worker threads with
  timeouts) beyond what the 4.0.10 upgrade itself already provides — the advisories are already
  fixed by the version bump; no further app-level mitigation is required by this task.
- Not changing how `renderMarkdown` is invoked elsewhere (there are no other call sites in this
  repo besides `test/app.test.js`, which is not to be edited).
