// Test backends. Each one returns { name, envFor(agent), addAgent(name), cleanup(), ... }.
//   sqlite         temp SQLite file
//   supabase-local real Postgres (TEST_PG_URL) + the migration + fake PostgREST
//   supabase-live  your real Supabase project (SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SECRET_KEY);
//                  creates agents with a random suffix and deletes them afterwards
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { SupabaseAdmin } from "../stores/supabase.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

export async function sqliteBackend() {
  const dir = mkdtempSync(join(tmpdir(), "agent-bridge-test-"));
  const db = join(dir, "bridge.db");
  let limitEnv = {};
  return {
    name: "sqlite",
    kind: "sqlite",
    remote: false,
    registered: false, // unknown recipients are queued, not refused
    maxBody: 50000,
    hasProjectDir: true,
    nameOf: (a) => a,
    envFor: (agent) => ({ AGENT_BRIDGE_BACKEND: "sqlite", AGENT_NAME: agent, AGENT_BRIDGE_DB: db, ...limitEnv }),
    addAgent: async () => {},
    // Raise or lower the per-agent abuse limits for this backend; returns a function that restores them.
    setLimits: async ({ ratePerMinute, maxUnreadPerSender, maxBytesPerDay }) => {
      const before = limitEnv;
      limitEnv = { ...limitEnv };
      if (ratePerMinute != null) limitEnv.AGENT_BRIDGE_RATE_PER_MIN = String(ratePerMinute);
      if (maxUnreadPerSender != null) limitEnv.AGENT_BRIDGE_MAX_UNREAD = String(maxUnreadPerSender);
      if (maxBytesPerDay != null) limitEnv.AGENT_BRIDGE_MAX_BYTES_PER_DAY = String(maxBytesPerDay);
      return async () => (limitEnv = before);
    },
    cleanup: async () => rmSync(dir, { recursive: true, force: true }),
  };
}

function supabaseCommon({ name, url, publishable, admin, suffix }) {
  const tokens = {};
  const nameOf = (a) => `${a}${suffix}`;
  return {
    name,
    kind: "supabase",
    remote: true,
    registered: true,
    maxBody: 50000,
    hasProjectDir: true,
    tokenVar: "AGENT_BRIDGE_TOKEN",
    urlVar: "SUPABASE_URL",
    badToken: "abt_" + "0".repeat(64),
    url,
    publishable,
    admin,
    tokens,
    nameOf,
    envFor: (agent) => ({
      AGENT_BRIDGE_BACKEND: "supabase",
      SUPABASE_URL: url,
      SUPABASE_PUBLISHABLE_KEY: publishable,
      AGENT_BRIDGE_TOKEN: tokens[agent],
      AGENT_NAME: nameOf(agent),
    }),
    addAgent: async (agent) => {
      tokens[agent] = await admin.createAgent(nameOf(agent), `test agent ${agent}`);
    },
    setLimits: async (limits) => {
      const before = await admin.setLimits({});
      await admin.setLimits(limits);
      return async () =>
        admin.setLimits({
          ratePerMinute: before.rate_per_minute,
          maxUnreadPerSender: before.max_unread_per_sender,
          maxBytesPerDay: before.max_bytes_per_day,
        });
    },
  };
}

export async function supabaseLocalBackend() {
  const { startFakePostgrest, KEYS } = await import("./fake-postgrest.js");
  const pg = (await import("pg")).default;
  const base = process.env.TEST_PG_URL || "postgresql://postgres@127.0.0.1:54329/postgres";
  const dbName = `bridge_test_${randomBytes(4).toString("hex")}`;
  const adminClient = new pg.Client({ connectionString: base });
  await adminClient.connect();
  // Supabase databases are UTF8; a SQL_ASCII test database counts bytes, not characters (R1-11).
  await adminClient.query(`create database ${dbName} template template0 encoding 'UTF8'`);
  const dbUrl = base.replace(/\/[^/]*$/, `/${dbName}`);
  const c = new pg.Client({ connectionString: dbUrl });
  await c.connect();
  await c.query(readFileSync(join(ROOT, "test/supabase-roles.sql"), "utf8"));
  await c.query(readFileSync(join(ROOT, "supabase/migration.sql"), "utf8"));
  await c.end();
  const api = await startFakePostgrest({ connectionString: dbUrl });
  const admin = new SupabaseAdmin({ url: api.url, secretKey: KEYS.secret });
  const b = supabaseCommon({ name: "supabase-local", url: api.url, publishable: KEYS.publishable, admin, suffix: "" });
  api.pool.on("error", () => {});
  b.secret = KEYS.secret;
  b.pool = api.pool;
  b.cleanup = async () => {
    await api.close();
    await adminClient.query(`drop database ${dbName} with (force)`);
    await adminClient.end();
  };
  return b;
}

export async function supabaseLiveBackend() {
  const url = process.env.SUPABASE_URL;
  const publishable = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  const secret = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !publishable || !secret) {
    throw new Error("live tests need SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY and SUPABASE_SECRET_KEY");
  }
  const admin = new SupabaseAdmin({ url, secretKey: secret });
  const suffix = `-t${randomBytes(3).toString("hex")}`;
  const b = supabaseCommon({ name: "supabase-live", url, publishable, admin, suffix });
  b.secret = secret;
  b.cleanup = async () => {
    for (const agent of Object.keys(b.tokens)) {
      await admin.store.rpc("bridge_admin_delete_agent", { p_name: b.nameOf(agent) }).catch(() => {});
    }
  };
  return b;
}

export async function slackLocalBackend() {
  const { startFakeSlack } = await import("./fake-slack.js");
  const slack = await startFakeSlack();
  const tokens = {};
  const users = {};
  return {
    name: "slack-local",
    kind: "slack",
    remote: true,
    registered: true,
    maxBody: 30000,
    hasProjectDir: false,
    tokenVar: "SLACK_BOT_TOKEN",
    urlVar: "SLACK_API_URL",
    badToken: "xoxb-not-a-real-token",
    slack,
    tokens,
    users,
    nameOf: (a) => a,
    envFor: (agent) => ({
      AGENT_BRIDGE_BACKEND: "slack",
      SLACK_API_URL: slack.url,
      SLACK_CHANNEL_ID: slack.channel.id,
      SLACK_BOT_TOKEN: tokens[agent],
      AGENT_NAME: agent,
    }),
    addAgent: async (agent) => {
      const u = slack.addUser({ name: agent });
      users[agent] = u;
      tokens[agent] = u.token;
    },
    addHuman: (name) => slack.addUser({ name, isBot: false }),
    setLimits: async () => async () => {}, // Slack has no server-side bridge limits
    cleanup: () => slack.close(),
  };
}

export async function backendsFromArgs(argv = process.argv.slice(2)) {
  const wanted = argv.length ? argv : ["sqlite", "supabase-local"];
  const make = {
    sqlite: sqliteBackend,
    "supabase-local": supabaseLocalBackend,
    "supabase-live": supabaseLiveBackend,
    "slack-local": slackLocalBackend,
  };
  return wanted.map((w) => {
    if (!make[w]) throw new Error(`unknown backend ${w} (use: ${Object.keys(make).join(", ")})`);
    return make[w];
  });
}
