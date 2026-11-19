'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { renderMarkdown, parseCli, paginate } = require('../src/app');

test('renders a heading and emphasis', () => {
  const html = renderMarkdown('# Notes\n\nsome **bold** text');
  assert.match(html, /<h1[^>]*>Notes<\/h1>/);
  assert.match(html, /<strong>bold<\/strong>/);
});

test('parses cli flags', () => {
  assert.deepStrictEqual(parseCli(['--verbose', 'a.md', '--pageSize', '3']), { verbose: true, pageSize: 3, files: ['a.md'] });
});

test('paginates', () => {
  assert.deepStrictEqual(paginate([1, 2, 3], 2), [[1, 2], [3]]);
});
