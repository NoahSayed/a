// Picks the backend from environment variables.
//
//   Local (same machine):   AGENT_NAME, optional AGENT_BRIDGE_DB
//   Supabase (any machine): SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY,
//                           AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE
//   Slack (any machine):    SLACK_CHANNEL_ID, SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_FILE
//
// AGENT_BRIDGE_BACKEND=sqlite|supabase|slack forces one; otherwise SUPABASE_URL selects
// Supabase, then SLACK_CHANNEL_ID selects Slack, else SQLite.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { BridgeError } from "./stores/common.js";

export { BridgeError, NetworkError, MESSAGE_TYPES, LIMITS, AGENT_NAME_RE, isUuid } from "./stores/common.js";

export const expandHome = (p) => resolve(p.startsWith("~") ? homedir() + p.slice(1) : p);

export function resolveDbPath(p = process.env.AGENT_BRIDGE_DB) {
  return expandHome(p && p.trim() ? p.trim() : "~/.agent-bridge/bridge.db");
}

export const BACKENDS = ["sqlite", "supabase", "slack"];

export function backendFromEnv(env = process.env) {
  const forced = (env.AGENT_BRIDGE_BACKEND || "").trim().toLowerCase();
  if (forced && !BACKENDS.includes(forced)) {
    throw new BridgeError(`AGENT_BRIDGE_BACKEND must be one of ${BACKENDS.join(", ")}, got "${forced}".`);
  }
  if (forced) return forced;
  if (env.SUPABASE_URL) return "supabase";
  if (env.SLACK_CHANNEL_ID) return "slack";
  return "sqlite";
}

// A secret from VAR, or from the file named in VAR_FILE (preferred: keeps it out of configs).
export function readSecret(env, name) {
  if (env[name] && env[name].trim()) return env[name].trim();
  const file = env[`${name}_FILE`];
  if (file) {
    const p = expandHome(file.trim());
    try {
      return readFileSync(p, "utf8").trim();
    } catch (e) {
      throw new BridgeError(`Can't read ${name}_FILE ${p}: ${e.code || e.message}`);
    }
  }
  return null;
}

export const readToken = (env = process.env) => readSecret(env, "AGENT_BRIDGE_TOKEN");

const intEnv = (v) => (v != null && v !== "" && Number.isFinite(Number(v)) ? Number(v) : undefined);

export async function createStore({ env = process.env, agentName = env.AGENT_NAME, busyTimeoutMs } = {}) {
  const backend = backendFromEnv(env);
  if (backend === "supabase") {
    const { SupabaseStore } = await import("./stores/supabase.js");
    return new SupabaseStore({
      url: env.SUPABASE_URL,
      key: env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY,
      token: readToken(env),
    });
  }
  if (backend === "slack") {
    const { SlackStore } = await import("./stores/slack.js");
    return new SlackStore({
      apiUrl: env.SLACK_API_URL || undefined,
      token: readSecret(env, "SLACK_BOT_TOKEN"),
      channel: env.SLACK_CHANNEL_ID,
      lookbackHours: intEnv(env.AGENT_BRIDGE_LOOKBACK_HOURS),
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
