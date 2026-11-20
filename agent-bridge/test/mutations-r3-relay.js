// Mutations for the round-3 relay and message-display fixes (R3-08, R3-09, R3-12, R3-16, R3-18).
// Same shape as test/mutations.js: { name, file, find, replace, suite }; `find` occurs exactly once in `file`.
// Loaded by test/mutations.js; test/regressions-r3-relay.js must fail with each one applied.
const S = ["test/regressions-r3-relay.js"];

export default [
  // --- R3-08: the audit limiter's table of sources
  { name: "R3-08 the table of sources grows without bound", file: "relay.js",
    find: `      if (this.entries.size >= this.maxSources) {`, replace: `      if (false) {`, suite: S },
  { name: "R3-08 a new source is not recorded when the table is full", file: "relay.js",
    find: `      if (this.entries.size >= this.maxSources) {`, replace: `      if (this.entries.size >= this.maxSources) return;\n      if (false) {`, suite: S },
  { name: "R3-08 the table size default is changed", file: "relay.js",
    find: `  authFailAuditSources: 10_000, //`, replace: `  authFailAuditSources: 100_000, //`, suite: S },

  // --- R3-09: a per-address share of the connection budget
  { name: "R3-09 no per-address connection limit", file: "relay.js",
    find: `    if (count >= lim.maxConnectionsPerIp) {`, replace: `    if (false) {`, suite: S },
  { name: "R3-09 a closed connection is never given back", file: "relay.js",
    find: `    sock.once("close", () => {\n      const left`, replace: `    sock.once("never", () => {\n      const left`, suite: S },
  { name: "R3-09 default share is the whole budget", file: "relay.js",
    find: `  maxConnectionsPerIp: 32, //`, replace: `  maxConnectionsPerIp: 512, //`, suite: S },
  { name: "R3-09 RELAY_MAX_CONNECTIONS_PER_IP is ignored", file: "relay.js",
    find: `    maxConnectionsPerIp: intSetting(e, "RELAY_MAX_CONNECTIONS_PER_IP", D.maxConnectionsPerIp),`, replace: `    maxConnectionsPerIp: D.maxConnectionsPerIp,`, suite: S },
  { name: "R3-09 posture line doesn't show the connection shares", file: "relay.js",
    find: `    \`connections: \${config.limits?.maxConnections ?? DEFAULT_LIMITS.maxConnections} total, \${config.limits?.maxConnectionsPerIp ?? DEFAULT_LIMITS.maxConnectionsPerIp} per address\`,\n`, replace: ``, suite: S },
  { name: "R3-09 IPv6 addresses are counted one by one, not per /64", file: "relay.js",
    find: `  return all.slice(0, 4).map(`, replace: `  return all.slice(0, 8).map(`, suite: S },
  { name: "R3-09 IPv4-mapped IPv6 addresses are a different source", file: "relay.js",
    find: `  if (mapped) return mapped[1];`, replace: ``, suite: S },

  // --- R3-12: every line break is a line break
  { name: "R3-12 body lines are split on \\n only", file: "server.js",
    find: `String(m.body).split(LINE_BREAK_SPLIT)`, replace: `String(m.body).split("\\n")`, suite: S },
  { name: "R3-12 a subject is flattened only for \\r and \\n", file: "server.js",
    find: `String(m.subject).replace(LINE_BREAK_RUN, " ")`, replace: `String(m.subject).replace(/[\\r\\n]+/g, " ")`, suite: S },
  { name: "R3-12 send refuses a subject only for \\r and \\n", file: "stores/common.js",
    find: `    if (hasLineBreak(subject)) throw`, replace: `    if (/[\\r\\n]/.test(subject)) throw`, suite: S },
  { name: "R3-12 the list of line breaks is only CR and LF", file: "stores/common.js",
    find: `const LINE_BREAK_CHARS = "\\\\n\\\\v\\\\f\\\\u0085\\\\u2028\\\\u2029\\\\u001c-\\\\u001e";`, replace: `const LINE_BREAK_CHARS = "\\\\n";`, suite: S },
  { name: "R3-12 a bare CR is not a line break in a body", file: "stores/common.js",
    find: "new RegExp(`\\\\r(?!\\\\n)|[${LINE_BREAK_CHARS}]`)", replace: "new RegExp(`[${LINE_BREAK_CHARS}]`)", suite: S },
  { name: "R3-12 the list of line breaks lacks the Unicode ones (NEL, LS, PS)", file: "stores/common.js",
    find: `\\\\u0085\\\\u2028\\\\u2029`, replace: ``, suite: S },
  { name: "R3-12 cli log splits bodies on \\n only", file: "cli.js",
    find: `m.body.split(LINE_BREAK_SPLIT).join("\\n    ")`, replace: `m.body.split("\\n").join("\\n    ")`, suite: S },

  // --- R3-16: an applied change is not reported as refused
  { name: "R3-16 an unaudited outcome is answered as 'refused'", file: "relay.js",
    find: `      if (e instanceof AuditError && started && fn.admin && !fn.auditor) {`, replace: `      if (false) {`, suite: S },
  { name: "R3-16 a failed INTENT line is treated as an applied change", file: "relay.js",
    find: `      if (e instanceof AuditError && started && fn.admin && !fn.auditor) {`, replace: `      if (e instanceof AuditError && fn.admin && !fn.auditor) {`, suite: S },
  { name: "R3-16 the result (new token) is not handed over", file: "relay.js",
    find: `      if (e instanceof AuditError) e.result = result === undefined ? null : result;`, replace: `      if (e instanceof AuditError) e.result = null;`, suite: S },
  { name: "R3-16 no intent line is written before an admin change", file: "relay.js",
    find: `        if (fn.admin) audit.write({ action:`, replace: `        if (false) audit.write({ action:`, suite: S },

  // --- R3-18: the relay's own DLP mode
  { name: "R3-18 the relay's DLP mode comes from AGENT_BRIDGE_DLP", file: "relay.js",
    find: `    dlp = dlpModeFromEnv({ AGENT_BRIDGE_DLP: e.RELAY_DLP });`, replace: `    dlp = dlpModeFromEnv(e);`, suite: S },
  { name: "R3-18 RELAY_DLP is not validated at startup", file: "relay.js",
    find: `    dlp = dlpModeFromEnv({ AGENT_BRIDGE_DLP: e.RELAY_DLP });`, replace: `    dlp = (e.RELAY_DLP ?? "").trim().toLowerCase() || "block";`, suite: S },
  { name: "R3-18 the DLP mode is not in the posture line", file: "relay.js",
    find: `    \`DLP: \${config.dlp === "warn" || config.dlp === "off" ? config.dlp.toUpperCase() : config.dlp}\`,\n`, replace: ``, suite: S },
  { name: "R3-18 the store is not given the relay's DLP mode", file: "relay.js",
    find: `busyTimeoutMs: 10000, dlpMode: config.dlp });`, replace: `busyTimeoutMs: 10000 });`, suite: S },
  { name: "R3-18 no warning for DLP warn/off", file: "relay.js",
    find: `  if (dlp === "warn" || dlp === "off") {`, replace: `  if (false) {`, suite: S },
  { name: "R3-18 a set AGENT_BRIDGE_DLP is not mentioned", file: "relay.js",
    find: `  if (e.AGENT_BRIDGE_DLP?.trim()) warnings.push(`, replace: `  if (false) warnings.push(`, suite: S },
  { name: "R3-18 startup warnings are not printed", file: "relay.js",
    find: `    for (const w of config.warnings ?? []) console.error(`, replace: `    for (const w of []) console.error(`, suite: S },
  { name: "R3-18 the store ignores a given DLP mode", file: "stores/sqlite.js",
    find: `this.dlpMode ? { dlpMode: this.dlpMode } : {}`, replace: `{}`, suite: S },
];
