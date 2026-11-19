## Security fixes (written by agent)

`npm audit` now reports 0 vulnerabilities, and all 3 tests pass.

I upgraded `lodash`, `marked` and `minimist` to their latest versions. The `marked` upgrade was a major-version jump and broke the old `marked(md)` call. I changed it to `marked.parse(md)` in `src/app.js`, which fixed the failing test.

I haven't committed anything.