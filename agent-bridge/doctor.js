// `cli.js doctor`: diagnose a setup and say how to fix each problem.
//
// Every check yields { level: "ok" | "warn" | "fail", title, detail, fix? }. The exit code is 0
// when nothing failed. Secrets are never printed: known token values are replaced by their first
// six characters and an ellipsis, and the DLP scanner is run over the final text as a safety net.
//
// Network checks (reachability, auth) run in a child process started with the effective
// environment, so they behave exactly like the MCP server would: NODE_USE_ENV_PROXY and
// NODE_EXTRA_CA_CERTS are read at process start and can't be applied to a running process.

import { accessSync, constants, existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  BACKENDS,
  AGENT_NAME_RE,
  BridgeError,
  NetworkError,
  backendFromEnv,
  expandHome,
  readSecret,
  readSlackToken,
  readToken,
  resolveDbPath,
} from "./store.js";
import { assertSecureUrl } from "./stores/common.js";
import { dlpModeFromEnv, redactText, scanText } from "./stores/dlp.js";
import {
  CA_VAR,
  SYSTEM_CA_VAR,
  maskProxyUrl,
  nodeSupportsEnvProxy,
  nodeSupportsSystemCa,
  proxyStatus,
  PROXY_VARS,
  PROXY_URL_VARS,
} from "./proxy.js";

const CLI = fileURLToPath(new URL("./cli.js", import.meta.url));
export const mask = (s) => (s ? `${String(s).slice(0, 6)}…` : "");

const ok = (title, detail = "") => ({ level: "ok", title, detail });
const warn = (title, detail, fix) => ({ level: "warn", title, detail, fix });
const fail = (title, detail, fix) => ({ level: "fail", title, detail, fix });

const IS_WINDOWS = process.platform === "win32";
const modeStr = (m) => "0" + (m & 0o777).toString(8).padStart(3, "0");

function nodeVersionOk(version = process.versions.node) {
  const [major, minor] = version.split(".").map(Number);
  return major > 22 || (major === 22 && minor >= 13);
}

// ------------------------------------------------------------------ file permissions

// A secret file: exists, is a regular file (symlinks are followed but reported), 0600, ours.
function checkSecretFile(label, path) {
  const out = [];
  let st;
  try {
    st = statSync(path);
  } catch (e) {
    out.push(fail(`${label} file`, `${path}: ${e.code === "ENOENT" ? "does not exist" : e.code || e.message}`,
      `Create it (cli.js save-token <name> / save-slack-token <name>) or fix the path in the *_FILE variable.`));
    return out;
  }
  if (!st.isFile()) {
    out.push(fail(`${label} file`, `${path} is not a regular file`, "Point the *_FILE variable at a file."));
    return out;
  }
  if (IS_WINDOWS) {
    out.push(warn(`${label} file permissions`, "can't be checked on Windows", `Make sure only your account can read ${path}.`));
    return out;
  }
  const bits = st.mode & 0o777;
  if (bits & 0o007) {
    out.push(fail(`${label} file permissions`, `${path} is readable or writable by everyone (mode ${modeStr(bits)})`, `chmod 600 ${path}`));
  } else if (bits & 0o070) {
    out.push(warn(`${label} file permissions`, `${path} is accessible by your group (mode ${modeStr(bits)}), expected 0600`, `chmod 600 ${path}`));
  } else {
    out.push(ok(`${label} file`, `${path} exists, mode ${modeStr(bits)} (owner only)`));
  }
  try {
    if (lstatSync(path).isSymbolicLink()) out.push(warn(`${label} file`, `${path} is a symlink`, "Prefer a regular file inside a private directory."));
  } catch {}
  if (st.uid !== process.getuid?.() && process.getuid) {
    out.push(warn(`${label} file owner`, `${path} is owned by another user (uid ${st.uid})`, `chown $(id -un) ${path}`));
  }
  const dir = dirname(path);
  try {
    const dm = statSync(dir).mode & 0o777;
    if (!IS_WINDOWS && dm & 0o007) out.push(warn(`${label} directory`, `${dir} is accessible by everyone (mode ${modeStr(dm)})`, `chmod 700 ${dir}`));
  } catch {}
  return out;
}

function tokenFromEnv(env, name, shape, shapeHint, label) {
  const out = [];
  const inline = env[name] && env[name].trim();
  const file = env[`${name}_FILE`] && env[`${name}_FILE`].trim();
  let value = null;
  if (!inline && !file) {
    out.push(fail(`${label} token`, `neither ${name} nor ${name}_FILE is set`, `Set ${name}_FILE to a file holding the token (cli.js save-${label === "Slack" ? "slack-" : ""}token <name>).`));
    return { out, value };
  }
  if (inline) {
    value = inline;
    out.push(warn(`${label} token`, `${name} is set directly (${mask(inline)}): it is visible in config files and process listings`, `Store it in a 0600 file and set ${name}_FILE instead.`));
  }
  if (file) {
    const path = expandHome(file);
    const checks = checkSecretFile(`${label} token`, path);
    out.push(...checks);
    // The server refuses a token file that other users can read (R2-11), so the probe must not use it either.
    if (!inline && checks.some((c) => c.level === "fail")) return { out, value: null };
    if (!inline) {
      try {
        value = readFileSync(path, "utf8").trim();
      } catch {}
    }
  }
  if (value) {
    if (!shape.test(value)) {
      // Neither the server nor this probe sends something that isn't a token to the backend (R2-11).
      out.push(fail(`${label} token format`, `${mask(value)} doesn't look like ${shapeHint}; it would not be sent anywhere`, `Check that the file holds only the token.`));
      return { out, value: null };
    }
    out.push(ok(`${label} token`, `${mask(value)} (${shapeHint})`));
  }
  return { out, value };
}

// ------------------------------------------------------------------ error explanations

const CERT_CODES = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_GET_ISSUER_CERT", "CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID",
  "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_UNTRUSTED",
]);

export function explainFailure(e, { what, env, proxy }) {
  const code = e.code || "";
  const proxyHint = proxy.configured && !proxy.active
    ? ` A proxy is configured but not active: set NODE_USE_ENV_PROXY=1 (Node ${proxy.supported ? "supports" : "does NOT support"} it).`
    : "";
  if (CERT_CODES.has(code)) {
    return {
      detail: `${what}: the TLS certificate isn't trusted (${code}). A corporate TLS-inspection proxy re-signs HTTPS traffic with its own CA.`,
      fix: `Export your company's root CA as a PEM file and set NODE_EXTRA_CA_CERTS=/path/to/ca.pem (or NODE_USE_SYSTEM_CA=1 on Node 22.19+/24.6+) in the server's env, then restart. Never disable TLS verification.`,
    };
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return {
      detail: `${what}: DNS lookup failed (${code}).`,
      fix: `Check the URL for typos. Behind a corporate proxy the proxy resolves names, so make sure HTTPS_PROXY is set and NODE_USE_ENV_PROXY=1 is in the server's env.${proxyHint}`,
    };
  }
  if (code === "ECONNREFUSED") {
    return { detail: `${what}: connection refused.`, fix: `Check the host and port${proxy.configured ? " (and the proxy address in HTTPS_PROXY)" : ""}.${proxyHint}` };
  }
  if (code === "ETIMEDOUT" || code === "UND_ERR_CONNECT_TIMEOUT" || code === "TimeoutError" || /timeout|timed out/i.test(e.message)) {
    return {
      detail: `${what}: timed out.`,
      fix: `A firewall is probably dropping the traffic. If your network requires a proxy, set HTTPS_PROXY and NODE_USE_ENV_PROXY=1 (cli.js init does this from your shell).${proxyHint}`,
    };
  }
  if (/\b(407)\b|proxy authentication/i.test(e.message)) {
    return { detail: `${what}: the proxy wants credentials (HTTP 407).`, fix: `Put them in the proxy URL: HTTPS_PROXY=http://user:password@host:port (stored in plain text in the generated files).` };
  }
  return { detail: e.message, fix: proxyHint.trim() || undefined };
}

// ------------------------------------------------------------------ backend probes (child process)

async function probeSupabase(env, proxy) {
  const { SupabaseStore } = await import("./stores/supabase.js");
  const out = [];
  const token = readToken(env);
  const store = new SupabaseStore({ url: env.SUPABASE_URL, key: env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY, token });
  try {
    const me = await store.whoami(); // bridge_whoami: proves reachability, the apikey and the token at once
    out.push(ok("Supabase reachable and token accepted", `bridge_whoami → agent "${me.agent}", ${me.unread} unread`));
    const wanted = (env.AGENT_NAME || "").trim();
    if (wanted && wanted !== me.agent) {
      out.push(fail("AGENT_NAME", `AGENT_NAME is "${wanted}" but the token belongs to "${me.agent}"`, "Remove AGENT_NAME or use the right token."));
    }
  } catch (e) {
    if (e instanceof NetworkError) {
      const x = explainFailure(e, { what: `Can't reach ${store.url}`, env, proxy });
      out.push(fail("Supabase reachability", x.detail, x.fix));
    } else if (/not found\. Run supabase\/migration\.sql/i.test(e.message)) {
      out.push(fail("Supabase schema", e.message, "Open the project's SQL editor and run supabase/migration.sql."));
    } else if (/invalid api key|jwt|apikey/i.test(e.message)) {
      out.push(fail("Supabase API key", `Supabase rejected the publishable key: ${e.message}`, "Copy the publishable key from Settings → API keys into SUPABASE_PUBLISHABLE_KEY."));
    } else if (/token|unauthor|revoked|agent/i.test(e.message)) {
      out.push(fail("Supabase agent token", e.message, "Ask the admin for a new token (cli.js rotate-token <name>) and save it with cli.js save-token <name>."));
    } else {
      const x = explainFailure(e, { what: "Supabase call failed", env, proxy });
      out.push(fail("Supabase call", x.detail, x.fix));
    }
  }
  return out;
}

async function probeSlack(env, proxy) {
  const { SlackStore } = await import("./stores/slack.js");
  const out = [];
  const store = new SlackStore({
    apiUrl: env.SLACK_API_URL || undefined,
    token: readSlackToken(env),
    channel: env.SLACK_CHANNEL_ID,
    // the same reading limits the server would use
    lookbackHours: Number(env.AGENT_BRIDGE_LOOKBACK_HOURS) || undefined,
    maxPages: Number(env.AGENT_BRIDGE_SLACK_MAX_PAGES) || undefined,
    ratePerMinute: Number(env.AGENT_BRIDGE_RATE_PER_MIN) || undefined,
    maxUnreadPerSender: Number(env.AGENT_BRIDGE_MAX_UNREAD) || undefined,
  });
  const explain = (e, title) => {
    if (e instanceof NetworkError) {
      const x = explainFailure(e, { what: "Can't reach Slack", env, proxy });
      return fail(title, x.detail, x.fix);
    }
    if (/invalid agent token/.test(e.message)) {
      return fail("Slack bot token", `Slack rejected the token (${e.message})`, "Copy the Bot User OAuth Token (xoxb-...) from the app's OAuth & Permissions page and run cli.js save-slack-token <name>.");
    }
    if (e.slackError === "missing_scope") {
      return fail("Slack scopes", `the app lacks a scope: ${e.message}`, "Reinstall the app with the scopes from `cli.js slack-manifest <name>`.");
    }
    if (/isn't a member|can't use channel|channel_not_found|not_in_channel/.test(e.message)) {
      return fail("Slack channel membership", e.message, `Invite the bot to the channel and check SLACK_CHANNEL_ID (${env.SLACK_CHANNEL_ID}).`);
    }
    return fail(title, e.message, "See README: Stage 3.");
  };
  try {
    const a = await store.api("auth.test", {}, { retries: 1 });
    out.push(ok("Slack auth.test", `bot "${a.user}" (${a.user_id}) is authenticated`));
    if (!AGENT_NAME_RE.test(a.user || "")) {
      out.push(fail("Slack bot name", `"${a.user}" isn't a valid agent name`, "Rename the bot user to lowercase letters, digits, - or _."));
    }
  } catch (e) {
    out.push(explain(e, "Slack auth.test"));
    return out;
  }
  try {
    const name = await store.identify();
    out.push(ok("Slack channel", `bot "${name}" is a member of ${env.SLACK_CHANNEL_ID} (${store.dir.byId.size} members)`));
    const wanted = (env.AGENT_NAME || "").trim();
    if (wanted && wanted !== name) out.push(fail("AGENT_NAME", `AGENT_NAME is "${wanted}" but the bot is "${name}"`, "Remove AGENT_NAME or use that bot's token."));
  } catch (e) {
    out.push(explain(e, "Slack channel"));
    return out;
  }
  // Read the lookback window the way the server does, and say if it can't be read completely (R2-07).
  try {
    await store.scan();
    const s = store.lastScan;
    const warnings = store.scanWarnings();
    const since = new Date(Math.floor(s.coveredSince * 1000)).toISOString();
    if (!warnings.length) out.push(ok("Slack channel scan", `${s.messages} message(s) in ${s.pages} page(s), complete back to ${since}`));
    for (const w of warnings) {
      out.push(warn("Slack channel scan", w, "The channel is too busy for the page cap, or senders are flooding it: see AGENT_BRIDGE_SLACK_MAX_PAGES and AGENT_BRIDGE_LOOKBACK_HOURS."));
    }
  } catch (e) {
    out.push(explain(e, "Slack channel scan"));
  }
  return out;
}

// Run inside the child process (cli.js __probe).
export async function probeBackend(env = process.env) {
  const backend = backendFromEnv(env);
  const proxy = proxyStatus({ env });
  if (backend === "supabase") return probeSupabase(env, proxy);
  if (backend === "slack") return probeSlack(env, proxy);
  return [];
}

function runProbe(env, timeoutMs = 45000) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [CLI, "__probe"], { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    const t = setTimeout(() => p.kill(), timeoutMs);
    p.on("close", (code) => {
      clearTimeout(t);
      try {
        res(JSON.parse(out.trim().split("\n").at(-1)));
      } catch {
        res([fail("Backend probe", `the probe process failed (exit ${code}): ${(err || out).trim().slice(0, 300) || "no output"}`, "Run with AGENT_BRIDGE_DEBUG=1 and check the output above.")]);
      }
    });
  });
}

// ------------------------------------------------------------------ local checks

function checkSqlite(env) {
  const out = [];
  const name = (env.AGENT_NAME || "").trim();
  if (!name) out.push(fail("AGENT_NAME", "not set (the local backend needs it)", "Set AGENT_NAME=<your-agent> (lowercase letters, digits, - and _)."));
  else if (!AGENT_NAME_RE.test(name)) out.push(fail("AGENT_NAME", `${JSON.stringify(name)} is invalid`, "Use lowercase letters, digits, - and _ (max 40)."));
  else out.push(ok("AGENT_NAME", name));

  const db = resolveDbPath(env.AGENT_BRIDGE_DB);
  out.push(ok("Mailbox path", db));
  // nearest existing ancestor must be a directory we can write to
  let anc = dirname(db);
  while (!existsSync(anc) && dirname(anc) !== anc) anc = dirname(anc);
  let ancStat = null;
  try {
    ancStat = statSync(anc);
  } catch {}
  if (!ancStat?.isDirectory()) {
    out.push(fail("Mailbox directory", `${anc} is not a directory`, "Set AGENT_BRIDGE_DB to a path inside a real directory."));
    return out;
  }
  try {
    accessSync(anc, constants.W_OK);
  } catch {
    out.push(fail("Mailbox directory", `${anc} is not writable by this user`, `Choose another AGENT_BRIDGE_DB, or: chmod u+w ${anc}`));
    return out;
  }
  const dir = dirname(db);
  if (existsSync(dir) && !IS_WINDOWS) {
    const dm = statSync(dir).mode & 0o777;
    if (dm & 0o007) out.push(warn("Mailbox directory permissions", `${dir} is accessible by everyone (mode ${modeStr(dm)})`, `chmod 700 ${dir}`));
  }
  if (existsSync(db) && !IS_WINDOWS) {
    const bits = statSync(db).mode & 0o777;
    if (bits & 0o004) out.push(fail("Mailbox permissions", `${db} is readable by everyone (mode ${modeStr(bits)}): it holds your agents' messages`, `chmod 600 ${db}`));
    else if (bits & 0o077) out.push(warn("Mailbox permissions", `${db} is accessible by your group (mode ${modeStr(bits)})`, `chmod 600 ${db}`));
    else out.push(ok("Mailbox permissions", `mode ${modeStr(bits)}, private`));
  }
  return out;
}

async function sqliteWriteTest(env) {
  const name = (env.AGENT_NAME || "").trim();
  if (!AGENT_NAME_RE.test(name)) return [];
  try {
    const { SqliteStore } = await import("./stores/sqlite.js");
    const store = new SqliteStore({ agentName: name, dbPath: resolveDbPath(env.AGENT_BRIDGE_DB), busyTimeoutMs: 3000 });
    store.db.exec("BEGIN IMMEDIATE");
    store.db.exec("ROLLBACK");
    await store.close();
    return [ok("Mailbox open and writable", "opened, took the write lock, rolled back")];
  } catch (e) {
    return [fail("Mailbox open/write", e.message, /locked|busy/i.test(e.message) ? "Another process holds the database lock; retry, and check for stuck agents." : "Check the path and permissions of AGENT_BRIDGE_DB.")];
  }
}

// Returns the checks; `.blocked` is true when the configuration is too incomplete to try the network.
function checkConfig(env, backend) {
  const out = [];
  out.blocked = false;
  if (backend === "supabase") {
    if (!env.SUPABASE_URL) {
      out.push(fail("SUPABASE_URL", "not set", "export SUPABASE_URL=https://<project-ref>.supabase.co"));
      out.blocked = true;
    } else {
      try {
        assertSecureUrl(env.SUPABASE_URL, "SUPABASE_URL");
        out.push(ok("SUPABASE_URL", env.SUPABASE_URL));
      } catch (e) {
        out.push(fail("SUPABASE_URL", e.message, "Use the project's https:// URL."));
        out.blocked = true;
      }
    }
    const key = env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY;
    if (!key) {
      out.push(fail("SUPABASE_PUBLISHABLE_KEY", "not set", "Copy the publishable key (sb_publishable_...) from Settings → API keys."));
      out.blocked = true;
    }
    else if (/^sb_secret_/.test(key)) out.push(fail("SUPABASE_PUBLISHABLE_KEY", `holds a SECRET key (${mask(key)})`, "Agents must only hold the publishable key. Rotate the secret key; it is now in an agent's config."));
    else out.push(ok("Supabase publishable key", mask(key)));
    if (env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY) {
      out.push(warn("Admin secret key in this environment", "SUPABASE_SECRET_KEY is set; agents must never have it", "Keep it only in the shell where you run admin commands."));
    }
    const t = tokenFromEnv(env, "AGENT_BRIDGE_TOKEN", /^abt_[0-9a-f]{64}$/, "an agent-bridge token (abt_ + 64 hex)", "Agent");
    out.push(...t.out);
    if (!t.value) out.blocked = true;
  } else if (backend === "slack") {
    const ch = env.SLACK_CHANNEL_ID;
    if (!ch) {
      out.push(fail("SLACK_CHANNEL_ID", "not set", "export SLACK_CHANNEL_ID=C0123ABCDEF (channel details → About)."));
      out.blocked = true;
    }
    else if (!/^[CG][A-Z0-9]{6,}$/.test(ch)) out.push(warn("SLACK_CHANNEL_ID", `${ch} doesn't look like a channel id`, "Use the id (C0... or G0...), not the channel name."));
    else out.push(ok("SLACK_CHANNEL_ID", ch));
    if (env.SLACK_API_URL) {
      try {
        assertSecureUrl(env.SLACK_API_URL, "SLACK_API_URL");
        out.push(ok("SLACK_API_URL", env.SLACK_API_URL));
      } catch (e) {
        out.push(fail("SLACK_API_URL", e.message, "Unset it or use an https URL."));
        out.blocked = true;
      }
    }
    const t = tokenFromEnv(env, "SLACK_BOT_TOKEN", /^xoxb-[A-Za-z0-9-]+$/, "a Slack bot token (xoxb-...)", "Slack");
    out.push(...t.out);
    if (!t.value) out.blocked = true;
  }
  return out;
}

function checkProxy(env, backend, execArgv) {
  const out = [];
  const network = backend !== "sqlite";
  const st = proxyStatus({ env, execArgv });
  const present = PROXY_VARS.filter((k) => env[k] && env[k].trim());
  const clip = (v) => (v.length > 60 ? `${v.slice(0, 60)}…` : v);
  const shown = present.map((k) => `${k}=${clip(PROXY_URL_VARS.includes(k) ? maskProxyUrl(env[k]) : env[k])}`).join(" ");
  if (!st.configured) {
    out.push(ok("Proxy", present.length ? `no HTTP(S)_PROXY (${shown})` : "none configured"));
  } else if (!st.supported) {
    out.push((network ? fail : warn)("Proxy / Node version", `${shown}, but Node ${process.versions.node} is too old to use proxy variables (needs 22.21+ or 24+)`, "Upgrade Node. Until then requests go direct and a corporate firewall will block them."));
  } else if (!st.active) {
    out.push((network ? warn : ok)("Proxy not active", `${shown}, but NODE_USE_ENV_PROXY=1 is not set, so Node's fetch() ignores it`, `Add NODE_USE_ENV_PROXY=1 to the server's env (re-run "cli.js init", it copies your proxy settings), or start node with --use-env-proxy.`));
  } else {
    out.push(ok("Proxy active", `${shown} NODE_USE_ENV_PROXY=1`));
  }
  if (env[CA_VAR]) {
    const p = expandHome(env[CA_VAR]);
    try {
      const pem = readFileSync(p, "utf8");
      if (/-----BEGIN CERTIFICATE-----/.test(pem)) out.push(ok("Extra CA certificates", `${CA_VAR}=${p}`));
      else out.push(fail("Extra CA certificates", `${p} contains no PEM certificate`, "Export the CA as PEM (-----BEGIN CERTIFICATE-----)."));
    } catch (e) {
      out.push(fail("Extra CA certificates", `${CA_VAR}=${p}: ${e.code === "ENOENT" ? "file not found" : e.code || e.message}`, "Fix the path; Node ignores a missing file and then rejects the company's TLS certificate."));
    }
  } else if (st.configured && network) {
    out.push(ok("Extra CA certificates", `${CA_VAR} not set (fine unless your proxy inspects TLS)`));
  }
  if (env[SYSTEM_CA_VAR] === "1") {
    out.push(
      nodeSupportsSystemCa()
        ? ok("System CA store", `${SYSTEM_CA_VAR}=1: Node trusts the operating system's certificates`)
        : warn("System CA store", `${SYSTEM_CA_VAR}=1 has no effect on Node ${process.versions.node} (needs 22.19+ or 24.6+)`, `Use ${CA_VAR}=/path/to/ca.pem instead.`)
    );
  }
  return out;
}

// ------------------------------------------------------------------ entry point

// Gathers every check. `env` is the effective environment of the server being diagnosed.
export async function diagnose(env, { execArgv = process.execArgv, probe = runProbe, allowNetwork = true, source = null } = {}) {
  const checks = [];
  checks.push(
    nodeVersionOk()
      ? ok("Node.js", `v${process.versions.node} (needs >= 22.13 for node:sqlite)`)
      : fail("Node.js", `v${process.versions.node} is too old`, "Install Node 22.13 or newer (node:sqlite is required).")
  );
  let backend;
  try {
    backend = backendFromEnv(env);
    const forced = (env.AGENT_BRIDGE_BACKEND || "").trim();
    const why = forced ? "AGENT_BRIDGE_BACKEND" : env.SUPABASE_URL ? "SUPABASE_URL is set" : env.SLACK_CHANNEL_ID ? "SLACK_CHANNEL_ID is set" : "default";
    checks.push(ok("Backend", `${backend} (${why})`));
  } catch (e) {
    checks.push(fail("Backend", e.message, `Set AGENT_BRIDGE_BACKEND to one of ${BACKENDS.join(", ")}, or unset it.`));
    return checks;
  }
  let blocked = false;
  if (backend === "sqlite") checks.push(...checkSqlite(env));
  else {
    const cfg = checkConfig(env, backend);
    blocked = cfg.blocked;
    checks.push(...cfg);
  }
  checks.push(...checkProxy(env, backend, execArgv));
  try {
    const mode = dlpModeFromEnv(env);
    if (mode === "block" || mode === "redact") checks.push(ok("DLP", `${mode}: secrets, card numbers and IBANs are ${mode === "block" ? "refused" : "redacted"} before sending`));
    else checks.push(warn("DLP", `mode "${mode}": ${mode === "off" ? "nothing is scanned" : "secrets are sent anyway (the sender is only told)"}`, "Set AGENT_BRIDGE_DLP=block (default) for regulated environments."));
  } catch (e) {
    checks.push(fail("DLP", e.message, "Set AGENT_BRIDGE_DLP to block, redact, warn or off."));
  }
  // The network probe is pointless if the configuration is already broken.
  if (backend === "sqlite") {
    if (!checks.some((c) => c.level === "fail")) checks.push(...(await sqliteWriteTest(env)));
  } else if (!blocked) {
    const dest = probeDestination(env);
    if (!allowNetwork && dest) {
      // R3-04: with `doctor <repo>` the address comes from a file in the repo; don't hand it this agent's
      // credentials unless the person running doctor says that host is right.
      checks.push(
        warn(
          "Reachability",
          `skipped: the check would send this agent's credentials to ${dest}, an address taken from ${source}`,
          "If that host is right, re-run with --probe."
        )
      );
    } else {
      checks.push(...(await probe(env)));
    }
  } else {
    checks.push(warn("Reachability", "skipped: fix the configuration problems above first"));
  }
  return checks;
}

// Text for the terminal; known secrets are masked and the DLP scanner is a last line of defence.
export function render(checks, env, header) {
  const secrets = [];
  for (const n of ["AGENT_BRIDGE_TOKEN", "SLACK_BOT_TOKEN", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY"]) {
    try {
      const v = readSecret(env, n);
      if (v && v.length >= 8) secrets.push(v);
    } catch {}
  }
  const scrub = (s) => {
    let t = String(s ?? "");
    for (const v of secrets) t = t.split(v).join(mask(v));
    return redactText(t, scanText(t));
  };
  const tag = { ok: "OK  ", warn: "WARN", fail: "FAIL" };
  const lines = [header];
  for (const c of checks) {
    lines.push(`  ${tag[c.level]}  ${scrub(c.title)}${c.detail ? `: ${scrub(c.detail)}` : ""}`);
    if (c.fix && c.level !== "ok") lines.push(`        fix: ${scrub(c.fix)}`);
  }
  const n = (l) => checks.filter((c) => c.level === l).length;
  lines.push("", `${n("ok")} ok, ${n("warn")} warning(s), ${n("fail")} failure(s)`);
  return lines.join("\n");
}

// Effective environment for `doctor <repo>`: the repo's .mcp.json `bridge` env over this shell's.
// The only settings `doctor <repo>` takes from a repo's .mcp.json (R3-04). A committed file must
// not be able to set NODE_OPTIONS, LD_PRELOAD and the like for the probe process.
export const REPO_ENV_KEYS = new Set([
  "AGENT_NAME", "AGENT_DESCRIPTION", "AGENT_BRIDGE_BACKEND", "AGENT_BRIDGE_DB", "AGENT_BRIDGE_TOKEN_FILE",
  "AGENT_BRIDGE_NAME_FROM", "AGENT_BRIDGE_LOOKBACK_HOURS", "AGENT_BRIDGE_SLACK_MAX_PAGES", "AGENT_BRIDGE_DLP",
  "AGENT_BRIDGE_MAX_HOPS", "AGENT_BRIDGE_RATE_PER_MIN", "AGENT_BRIDGE_MAX_UNREAD", "AGENT_BRIDGE_MAX_BYTES_PER_DAY",
  "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY", "SLACK_CHANNEL_ID", "SLACK_BOT_TOKEN_FILE",
  "SLACK_API_URL", "RELAY_URL", "RELAY_TLS_CA", "RELAY_TLS_CLIENT_CERT", "RELAY_TLS_CLIENT_KEY",
  "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy",
  "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA",
]);

// Where a network check would send this agent's credentials, or null for the local backend.
export function probeDestination(env) {
  const backend = (env.AGENT_BRIDGE_BACKEND || "").trim() || (env.SUPABASE_URL ? "supabase" : env.RELAY_URL ? "relay" : env.SLACK_CHANNEL_ID ? "slack" : "sqlite");
  if (backend === "supabase") return env.SUPABASE_URL || "(SUPABASE_URL not set)";
  if (backend === "relay") return env.RELAY_URL || "(RELAY_URL not set)";
  if (backend === "slack") return env.SLACK_API_URL || "https://slack.com/api";
  return null;
}

// Which client's file `doctor <repo>` reads: the given one, else the first that exists, in this order.
export const REPO_CONFIG_FILES = { claude: ".mcp.json", cursor: ".cursor/mcp.json", codex: ".codex/config.toml" };

export async function envFromRepo(repoDir, base = process.env, { client } = {}) {
  const dir = resolve(repoDir);
  if (client && !REPO_CONFIG_FILES[client]) throw new BridgeError(`unknown client "${client}" (use claude, cursor or codex)`);
  const order = client ? [client] : Object.keys(REPO_CONFIG_FILES);
  const found = order.find((c) => existsSync(join(dir, REPO_CONFIG_FILES[c])));
  if (!found) {
    const names = order.map((c) => REPO_CONFIG_FILES[c]).join(", ");
    throw new BridgeError(`no ${names} in ${dir}; run "cli.js init" first.`);
  }
  const p = join(dir, REPO_CONFIG_FILES[found]);
  let srvEnv;
  if (found === "claude") {
    let cfg;
    try {
      cfg = JSON.parse(readFileSync(p, "utf8"));
    } catch (e) {
      throw new BridgeError(`${p} is not valid JSON: ${e.message}`);
    }
    const srv = cfg.mcpServers?.bridge;
    if (!srv) throw new BridgeError(`${p} has no "bridge" server; run "cli.js init" first.`);
    srvEnv = srv.env;
  } else {
    // Cursor / Codex formats are parsed by their client module (clients/<client>.js).
    const mod = await import(`./clients/${found}.js`);
    let r;
    try {
      r = mod.readServerEnv(dir);
    } catch (e) {
      throw new BridgeError(`${p} could not be read: ${e.message}`);
    }
    if (r?.error) throw new BridgeError(`${p} could not be read: ${r.error}`);
    if (!r || !r.env || !Object.keys(r.env).length) throw new BridgeError(`${p} has no "bridge" server; run "cli.js init --client ${found}" first.`);
    srvEnv = r.env;
  }
  const taken = {};
  const ignored = [];
  for (const [k, v] of Object.entries(srvEnv || {})) {
    if (REPO_ENV_KEYS.has(k) && typeof v === "string") taken[k] = v;
    else ignored.push(k);
  }
  return { env: { ...base, ...taken }, path: p, ignored, client: found };
}
