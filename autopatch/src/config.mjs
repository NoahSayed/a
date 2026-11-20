// Loads autopatch.config.json from the target project and fills in defaults.
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULTS = {
  adapter: 'npm',
  // Where the AI may create or edit files (site-owned code). Everything else is off limits.
  ownedPaths: ['src/**'],
  // Never editable by the AI, whatever ownedPaths says.
  protectedPaths: ['package.json', 'package-lock.json', 'test/**', 'tests/**', '**/*.test.*', '.github/**', '.env', '.env.*'],
  ai: { enabled: true, provider: 'claude-cli', model: 'haiku', maxTurns: 40 },
  policy: {
    cooldownDays: 3,            // routine fixes younger than this wait (supply-chain safety); urgent ones skip it
    smallestFix: true,          // pick the smallest version that clears ALL known advisories for the package
  },
  checks: {
    test: null,                 // e.g. "npm test"; null = adapter default
    pages: [],                  // [{ path, status?: 200, notIncludes?: [..] }]
    flows: [],                  // HTTP flows, see docs/CONFIG.md
    probes: [],                 // [{ finding: "<advisory id or package>", script: "path/to/probe.mjs" }]
    restartCheck: true,         // restart the app and run the checks again before trusting a change
  },
  sensitive: { extraPatterns: [] }, // more regexes that force human approval when the AI adds them
  feeds: { local: [] },             // extra advisory files (OSV JSON array/object, or Wordfence v3 map)
  server: {},                       // adapter-specific (ports, start command, ...)
};

function merge(a, b) {
  if (Array.isArray(a) || Array.isArray(b) || typeof a !== 'object' || typeof b !== 'object' || !a || !b) return b === undefined ? a : b;
  const out = { ...a };
  for (const k of Object.keys(b)) out[k] = merge(a[k], b[k]);
  return out;
}

export function loadConfig(dir, overrides = {}) {
  const file = path.join(dir, 'autopatch.config.json');
  const user = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const cfg = merge(merge(DEFAULTS, user), overrides);
  cfg.projectDir = path.resolve(dir);
  return cfg;
}
