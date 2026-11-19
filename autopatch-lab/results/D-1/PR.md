## Security fixes (written by agent)

`npm audit` now reports 0 vulnerabilities, and all 3 tests pass.

- **Upgrades:** I moved `lodash`, `marked` and `minimist` to their latest versions in `package.json`. `marked` is now 18.2.1. It was 2.0.0 before, so that's a major jump.
- **Code change:** `marked` 18 no longer exports a callable function. In `src/app.js` I switched to `const { marked } = require('marked')` and `marked.parse(md, { async: false })`. That keeps `renderMarkdown` synchronous, as it was before.

I only ran the test suite, not the CLI itself. The tests cover heading and emphasis rendering and pagination.