'use strict';
// A tiny "notes" CLI: parse args, render markdown notes, paginate the output.
const marked = require('marked');
const parseArgs = require('minimist');
const _ = require('lodash');

/** Render user-supplied markdown to an HTML string (synchronous). */
function renderMarkdown(md) {
  return marked(md);
}

/** Parse command-line arguments (untrusted input). */
function parseCli(argv) {
  const a = parseArgs(argv, { boolean: ['verbose'], default: { pageSize: 2 } });
  return { verbose: Boolean(a.verbose), pageSize: Number(a.pageSize), files: a._.map(String) };
}

/** Split rendered pages into groups of `size`. */
function paginate(items, size) {
  return _.chunk(items, size);
}

module.exports = { renderMarkdown, parseCli, paginate };
