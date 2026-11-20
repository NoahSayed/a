// Mutations for adversary round 3, client-side configuration (R3-05, R3-06, R3-07, R3-10, R3-11, R3-17).
// Same shape as the entries in test/mutations.js: { name, file, find, replace, suite }; `find` occurs exactly once.
// Every guard added for these findings has an entry here, and test/regressions-r3-config.js must fail with it applied.
const S = ["test/regressions-r3-config.js"];

export default [
  // --- R3-05: proxy credentials
  { name: "R3-05 URL masking stops at the first @ (the tail of a password is shown)", file: "proxy.js",
    find: "const USERINFO = /^((?:[a-z][a-z0-9+.-]*:)?\\/\\/)?[^/?#]*@/i;", replace: "const USERINFO = /^((?:[a-z][a-z0-9+.-]*:)?\\/\\/)?[^/?#@]*@/i;", suite: S },
  { name: "R3-05 a user name with no password (a token) is shown", file: "proxy.js",
    find: "      if (u.password) user = `${u.username}:***`;", replace: "      user = `${u.username}${u.password ? \":***\" : \"\"}`;", suite: S },
  { name: "R3-05 a user-only proxy URL is not treated as carrying credentials", file: "proxy.js",
    find: "    if (u.host) return Boolean(u.username || u.password);", replace: "    if (u.host) return Boolean(u.username && u.password);", suite: S },
  { name: "R3-05 a proxy credential is written onto the hook's command line", file: "clients/common.js",
    find: "  env = Object.fromEntries(Object.entries(env).filter((e) => !hookCarriesProxyCredential(e)));\n", replace: "", suite: S },
  { name: "R3-05 peek's re-run repeats the proxy settings in its arguments", file: "cli.js",
    find: "...withoutStartupSets(argv)", replace: "...argv", suite: S },

  // --- R3-06: managed installs, agent name from the folder
  { name: "R3-06 a folder name is cleaned up into an agent name (look-alike folders collapse)", file: "store.js",
    find: "  const name = base.replace(/[A-Z]/g, (c) => c.toLowerCase());",
    replace: "  const name = base.toLowerCase().replace(/[^a-z0-9_-]+/g, \"-\").replace(/^[-_]+/, \"\").slice(0, 40).replace(/-+$/, \"\");", suite: S },
  { name: "R3-06 Unicode case folding names the agent (KELVIN SIGN becomes k)", file: "store.js",
    find: "  const name = base.replace(/[A-Z]/g, (c) => c.toLowerCase());", replace: "  const name = base.toLowerCase();", suite: S },
  { name: "R3-06 an AGENT_NAME that is not the folder's name is obeyed", file: "store.js",
    find: "    if (given && given !== derived) {", replace: "    if (false) {", suite: S },
  { name: "R3-06 a relative project folder variable is accepted", file: "store.js",
    find: "      if (env[k] && !isAbsolute(env[k])) throw", replace: "      if (false) throw", suite: S },

  // --- R3-07: userinfo in URLs
  { name: "R3-07 managed-config copies userinfo in RELAY_URL", file: "cli.js",
    find: "        refuseUrlCredentials(process.env.RELAY_URL, \"RELAY_URL\");\n", replace: "", suite: S },
  { name: "R3-07 managed-config copies userinfo in SUPABASE_URL", file: "cli.js",
    find: "        refuseUrlCredentials(process.env.SUPABASE_URL, \"SUPABASE_URL\");\n", replace: "", suite: S },
  { name: "R3-07 managed-config copies userinfo in SLACK_API_URL", file: "cli.js",
    find: "managed-config for Slack needs SLACK_CHANNEL_ID.\");\n        refuseUrlCredentials(process.env.SLACK_API_URL, \"SLACK_API_URL\");\n",
    replace: "managed-config for Slack needs SLACK_CHANNEL_ID.\");\n", suite: S },
  { name: "R3-07 init --relay writes userinfo in RELAY_URL", file: "cli.js",
    find: "        refuseUrlCredentials(url, \"RELAY_URL\");\n", replace: "", suite: S },
  { name: "R3-07 init --supabase writes userinfo in SUPABASE_URL", file: "cli.js",
    find: "        refuseUrlCredentials(url, \"SUPABASE_URL\");\n", replace: "", suite: S },
  { name: "R3-07 init --slack writes userinfo in SLACK_API_URL", file: "cli.js",
    find: "in your shell.\");\n        refuseUrlCredentials(process.env.SLACK_API_URL, \"SLACK_API_URL\");\n",
    replace: "in your shell.\");\n", suite: S },
  { name: "R3-07 doctor accepts and prints userinfo in SUPABASE_URL", file: "doctor.js",
    find: "      const cred = urlCredentialsProblem(env.SUPABASE_URL, \"SUPABASE_URL\");\n      try {\n        if (cred) throw new BridgeError(cred);",
    replace: "      const cred = null;\n      try {", suite: S },
  { name: "R3-07 doctor accepts and prints userinfo in RELAY_URL", file: "doctor.js",
    find: "      const cred = urlCredentialsProblem(env.RELAY_URL, \"RELAY_URL\");\n      try {\n        if (cred) throw new BridgeError(cred);",
    replace: "      const cred = null;\n      try {", suite: S },
  { name: "R3-07 doctor accepts and prints userinfo in SLACK_API_URL", file: "doctor.js",
    find: "      const cred = urlCredentialsProblem(env.SLACK_API_URL, \"SLACK_API_URL\");\n      try {\n        if (cred) throw new BridgeError(cred);",
    replace: "      const cred = null;\n      try {", suite: S },

  // --- R3-10: doctor checks the relay backend
  { name: "R3-10 doctor doesn't check RELAY_URL's scheme", file: "doctor.js",
    find: "        assertSecureUrl(env.RELAY_URL, \"RELAY_URL\");\n", replace: "", suite: S },
  { name: "R3-10 doctor doesn't check the relay's agent token", file: "doctor.js",
    find: "    out.push(...t.out);\n    if (!t.value) out.blocked = true;\n    const tlsChecks", replace: "    const tlsChecks", suite: S },
  { name: "R3-10 doctor doesn't check RELAY_TLS_* files", file: "doctor.js",
    find: "    const tlsChecks = checkRelayTls(env);", replace: "    const tlsChecks = [];", suite: S },
  { name: "R3-10 doctor doesn't probe the relay", file: "doctor.js",
    find: "  if (backend === \"relay\") return probeRelay(env, proxy);", replace: "  if (backend === \"relay\") return [];", suite: S },
  { name: "R3-10 doctor lets a relay AGENT_NAME mismatch pass", file: "doctor.js",
    find: "    if (named && named !== me.agent) {", replace: "    if (false) {", suite: S },
  { name: "R3-10 doctor doesn't check the relay client key's permissions", file: "doctor.js",
    find: "    if (kind === \"KEY\") out.push(...checkSecretFile(name, path));", replace: "    if (kind === \"KEY\") {}", suite: S },
  { name: "R3-10 doctor accepts a client certificate without its key", file: "doctor.js",
    find: "  if (set(\"RELAY_TLS_CLIENT_CERT\") && !set(\"RELAY_TLS_CLIENT_KEY\")) {", replace: "  if (false) {", suite: S },
  { name: "R3-10 doctor accepts a RELAY_TLS_* file that is not PEM", file: "doctor.js",
    find: "    if (!PEM_RE[kind].test(text)) {", replace: "    if (false) {", suite: S },
  { name: "R3-10 doctor doesn't expand ~ in RELAY_TLS_*", file: "doctor.js",
    find: "    const path = expandHome(env[name].trim());", replace: "    const path = env[name].trim();", suite: S },

  // --- R3-11: the relay client's TLS fetch and the proxy
  { name: "R3-11 the TLS fetch never uses the proxy", file: "stores/tls-fetch.js",
    find: "    if (!proxy) return direct;", replace: "    return direct;", suite: S },
  { name: "R3-11 the TLS fetch uses a proxy without NODE_USE_ENV_PROXY", file: "stores/tls-fetch.js",
    find: "  if (!requested) return null;", replace: "", suite: S },
  { name: "R3-11 the TLS fetch ignores NO_PROXY", file: "stores/tls-fetch.js",
    find: "  if (noProxy(target, (env.NO_PROXY ?? env.no_proxy ?? \"\").trim())) return null;", replace: "", suite: S },
  { name: "R3-11 the TLS fetch ignores lower-case https_proxy", file: "stores/tls-fetch.js",
    find: "env.HTTPS_PROXY || env.https_proxy || \"\"", replace: "env.HTTPS_PROXY || \"\"", suite: S },
  { name: "R3-11 the TLS fetch sends no Proxy-Authorization", file: "stores/tls-fetch.js",
    find: "const auth = proxy.username || proxy.password ?", replace: "const auth = false ?", suite: S },
  { name: "R3-11 the TLS fetch carries on after the proxy refuses CONNECT", file: "stores/tls-fetch.js",
    find: "        if (status !== 200) return fail(", replace: "        if (false) return fail(", suite: S },

  // --- R3-17: RELAY_TLS_* paths
  { name: "R3-17 RELAY_TLS_* paths starting with ~ are not expanded", file: "stores/tls-fetch.js",
    find: "  const path = expandHome(String(value).trim());", replace: "  const path = String(value).trim();", suite: S },
  { name: "R3-17 the RELAY_TLS_* read error doesn't name the variable and file", file: "stores/tls-fetch.js",
    find: "    throw new BridgeError(`Can't read ${name} ${path}: ${e.code || e.message}`);", replace: "    throw new BridgeError(`Can't read a relay TLS file: ${e.code || e.message}`);", suite: S },
];
