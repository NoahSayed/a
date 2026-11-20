// Picks the backend from environment variables.
//
//   Local (same machine):   AGENT_NAME, optional AGENT_BRIDGE_DB
//   Supabase (any machine): SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY,
//                           AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE
//   Relay (self-hosted):    RELAY_URL, AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE (see relay.js)
//   Slack (any machine):    SLACK_CHANNEL_ID, SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_FILE
//
// AGENT_BRIDGE_BACKEND=sqlite|supabase|relay|slack forces one; otherwise SUPABASE_URL selects
// Supabase, then RELAY_URL the relay, then SLACK_CHANNEL_ID selects Slack, else SQLite.

import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, resolve } from "node:path";
import { AGENT_NAME_RE, BridgeError } from "./stores/common.js";

export { BridgeError, NetworkError, MESSAGE_TYPES, LIMITS, AGENT_NAME_RE, isUuid } from "./stores/common.js";

// "~", "~/x" and (Windows) "~\x" mean the home directory; "~name" is just a relative file name.
const HOME_PREFIX = process.platform === "win32" ? /^~[\\/]/ : /^~\//;
export const expandHome = (p) => resolve(p === "~" || HOME_PREFIX.test(p) ? homedir() + p.slice(1) : p);

export function resolveDbPath(p = process.env.AGENT_BRIDGE_DB) {
  return expandHome(p && p.trim() ? p.trim() : "~/.agent-bridge/bridge.db");
}

export const BACKENDS = ["sqlite", "supabase", "relay", "slack"];

export function backendFromEnv(env = process.env) {
  const forced = (env.AGENT_BRIDGE_BACKEND || "").trim().toLowerCase();
  if (forced && !BACKENDS.includes(forced)) {
    throw new BridgeError(`AGENT_BRIDGE_BACKEND must be one of ${BACKENDS.join(", ")}, got "${forced}".`);
  }
  if (forced) return forced;
  if (env.SUPABASE_URL) return "supabase";
  if (env.RELAY_URL) return "relay";
  if (env.SLACK_CHANNEL_ID) return "slack";
  return "sqlite";
}

// The only shapes a token may have. A file named by AGENT_BRIDGE_TOKEN_FILE / SLACK_BOT_TOKEN_FILE is
// sent to the configured URL, so anything that is not a token is refused before any network call
// (R2-11): a poisoned .mcp.json must not turn the server into a way to ship arbitrary files out.
export const TOKEN_SHAPES = {
  AGENT_BRIDGE_TOKEN: { re: /^abt_[0-9a-f]{64}$/, what: "an agent-bridge token (abt_ + 64 hex characters)" },
  SLACK_BOT_TOKEN: { re: /^xoxb-[A-Za-z0-9-]+$/, what: "a Slack bot token (xoxb-...)" },
};
const TOKEN_FILE_MAX_BYTES = 4096;

// A secret from VAR, or from the file named in VAR_FILE (preferred: keeps it out of configs).
// With `shape` (a TOKEN_SHAPES entry) the value must look like that token, and a token file must be a
// small regular file that is not accessible to "other" users (POSIX; the same bar as doctor's FAIL).
// Error messages name the variable and path, never the contents.
export function readSecret(env, name, { shape } = {}) {
  const check = (value, where) => {
    if (shape && !shape.re.test(value)) {
      throw new BridgeError(`${where} doesn't hold ${shape.what}; refusing to send it anywhere. Check the variable.`);
    }
    return value;
  };
  if (env[name] && env[name].trim()) return check(env[name].trim(), name);
  const file = env[`${name}_FILE`];
  if (file) {
    const p = expandHome(file.trim());
    if (shape) {
      let st;
      try {
        st = statSync(p);
      } catch (e) {
        throw new BridgeError(`Can't read ${name}_FILE ${p}: ${e.code || e.message}`);
      }
      if (!st.isFile() || st.size > TOKEN_FILE_MAX_BYTES) {
        throw new BridgeError(`${name}_FILE ${p} is not a token file (it must be a small regular file); refusing to send it anywhere.`);
      }
      if (process.platform !== "win32" && st.mode & 0o007) {
        throw new BridgeError(
          `${name}_FILE ${p} is accessible by other users (mode 0${(st.mode & 0o777).toString(8)}); refusing to use it. Run: chmod 600 ${p}`
        );
      }
    }
    let text;
    try {
      text = readFileSync(p, "utf8").trim();
    } catch (e) {
      throw new BridgeError(`Can't read ${name}_FILE ${p}: ${e.code || e.message}`);
    }
    return check(text, `${name}_FILE ${p}`);
  }
  return null;
}

export const readToken = (env = process.env) => readSecret(env, "AGENT_BRIDGE_TOKEN", { shape: TOKEN_SHAPES.AGENT_BRIDGE_TOKEN });
export const readSlackToken = (env = process.env) => readSecret(env, "SLACK_BOT_TOKEN", { shape: TOKEN_SHAPES.SLACK_BOT_TOKEN });

const intEnv = (v) => (v != null && v !== "" && Number.isFinite(Number(v)) ? Number(v) : undefined);

// ------------------------------------------------------------------ managed installs
// One machine-wide managed-mcp.json entry can serve every project: with AGENT_BRIDGE_NAME_FROM=project
// the agent's name is its project folder's name, and "{agent}" in a token-file path becomes that name.
// The project folder is AGENT_BRIDGE_PROJECT_DIR, else CLAUDE_PROJECT_DIR, else the working directory. An inherited
// CURSOR_PROJECT_DIR is deliberately not used (R4-11): any process started from a Cursor terminal has it. peek,
// when it runs as a Cursor hook, passes Cursor's workspace folder as AGENT_BRIDGE_PROJECT_DIR instead.
//
// The name is the folder's name, not a clean-up of it (R3-06). A name that picks a token file must not be the
// same for folders that merely look alike (".Billing!", "billing.", "billing" + a zero-width space, two names
// sharing their first 40 characters), so the folder name must already be a valid agent name; the only change
// is that ASCII capitals are lower-cased (never Unicode case folding: U+212A KELVIN SIGN would become "k").
// Anything else is refused, with the folder named. A folder that differs from another only in ASCII case
// ("Billing" / "billing") still maps to the same agent: that is documented, not hidden.
export function agentNameFromDir(dir) {
  const base = basename(resolve(dir || "."));
  const name = base.replace(/[A-Z]/g, (c) => c.toLowerCase());
  if (!AGENT_NAME_RE.test(name)) {
    throw new BridgeError(
      `The project folder ${JSON.stringify(base)} can't be used as an agent name as it is: with AGENT_BRIDGE_NAME_FROM=project the folder name ` +
        `must be lowercase letters, digits, - and _ only (capitals are lower-cased), start with a letter or digit and have at most 40 characters. ` +
        `Rename the folder, or give this project its own agent name with "cli.js init".`
    );
  }
  return name;
}

const AGENT_PLACEHOLDER_VARS = ["AGENT_BRIDGE_TOKEN_FILE", "SLACK_BOT_TOKEN_FILE"];

export function resolveIdentityEnv(env = process.env, cwd = process.cwd()) {
  const out = { ...env };
  const from = (env.AGENT_BRIDGE_NAME_FROM || "").trim().toLowerCase();
  if (from && from !== "project") throw new BridgeError(`AGENT_BRIDGE_NAME_FROM must be "project", got "${from}".`);
  if (from === "project") {
    // Both project-folder variables must be absolute: a relative one would be taken against the working directory.
    for (const k of ["AGENT_BRIDGE_PROJECT_DIR", "CLAUDE_PROJECT_DIR"]) {
      if (env[k] && !isAbsolute(env[k])) throw new BridgeError(`${k} must be an absolute path, got ${JSON.stringify(env[k])}.`);
    }
    const derived = agentNameFromDir(env.AGENT_BRIDGE_PROJECT_DIR || env.CLAUDE_PROJECT_DIR || cwd);
    // An AGENT_NAME that is not the folder's name is refused rather than obeyed: in a managed install it can only
    // have been inherited (from the shell, or from a project's own settings), and it would pick another agent's
    // token file (R3-06). A project that needs a different name uses its own "cli.js init" entry.
    const given = (out.AGENT_NAME || "").trim();
    if (given && given !== derived) {
      throw new BridgeError(
        `AGENT_NAME is "${given}" but AGENT_BRIDGE_NAME_FROM=project names this agent "${derived}" after its project folder; refusing to guess. ` +
          `Unset AGENT_NAME (a managed entry takes the name from the folder).`
      );
    }
    out.AGENT_NAME = derived;
  }
  for (const k of AGENT_PLACEHOLDER_VARS) {
    if (!out[k] || !out[k].includes("{agent}")) continue;
    const name = (out.AGENT_NAME || "").trim();
    if (!AGENT_NAME_RE.test(name)) {
      throw new BridgeError(`${k} contains {agent} but no valid agent name is known: set AGENT_NAME or AGENT_BRIDGE_NAME_FROM=project.`);
    }
    out[k] = out[k].replaceAll("{agent}", name);
  }
  return out;
}

export async function createStore({ env: rawEnv = process.env, agentName, busyTimeoutMs } = {}) {
  const env = resolveIdentityEnv(rawEnv);
  agentName ??= env.AGENT_NAME;
  const backend = backendFromEnv(env);
  if (backend === "supabase") {
    const { SupabaseStore } = await import("./stores/supabase.js");
    return new SupabaseStore({
      url: env.SUPABASE_URL,
      key: env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY,
      token: readToken(env),
    });
  }
  if (backend === "relay") {
    // A self-hosted relay.js speaks Supabase's RPC protocol; it ignores the apikey for agent calls
    // (the token decides who the caller is).
    const { SupabaseStore } = await import("./stores/supabase.js");
    const { tlsFetchFromEnv } = await import("./stores/tls-fetch.js");
    let fetchImpl;
    try {
      fetchImpl = tlsFetchFromEnv(env); // only with RELAY_TLS_CA / RELAY_TLS_CLIENT_CERT / RELAY_TLS_CLIENT_KEY
    } catch (e) {
      throw e instanceof BridgeError ? e : new BridgeError(`Can't read a relay TLS file: ${e.code || e.message}`); // names the variable and file
    }
    return new SupabaseStore({ url: env.RELAY_URL, key: "relay", token: readToken(env), label: "relay", ...(fetchImpl ? { fetchImpl } : {}) });
  }
  if (backend === "slack") {
    const { SlackStore } = await import("./stores/slack.js");
    return new SlackStore({
      apiUrl: env.SLACK_API_URL || undefined,
      token: readSlackToken(env),
      channel: env.SLACK_CHANNEL_ID,
      lookbackHours: intEnv(env.AGENT_BRIDGE_LOOKBACK_HOURS),
      maxPages: intEnv(env.AGENT_BRIDGE_SLACK_MAX_PAGES),
      ratePerMinute: intEnv(env.AGENT_BRIDGE_RATE_PER_MIN),
      maxUnreadPerSender: intEnv(env.AGENT_BRIDGE_MAX_UNREAD),
    });
  }
  const name = (agentName || "").trim();
  if (!name) throw new BridgeError("Set AGENT_NAME (e.g. AGENT_NAME=frontend).");
  const { SqliteStore } = await import("./stores/sqlite.js");
  const limits = Object.fromEntries(
    Object.entries({
      ratePerMinute: intEnv(env.AGENT_BRIDGE_RATE_PER_MIN),
      maxUnreadPerSender: intEnv(env.AGENT_BRIDGE_MAX_UNREAD),
      maxBytesPerDay: intEnv(env.AGENT_BRIDGE_MAX_BYTES_PER_DAY),
    }).filter(([, v]) => v !== undefined)
  );
  return new SqliteStore({ agentName: name, dbPath: resolveDbPath(env.AGENT_BRIDGE_DB), busyTimeoutMs, limits });
}
