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
  return {
    name: "sqlite",
    remote: false,
    nameOf: (a) => a,
    envFor: (agent) => ({ AGENT_BRIDGE_BACKEND: "sqlite", AGENT_NAME: agent, AGENT_BRIDGE_DB: db }),
    addAgent: async () => {},
    cleanup: async () => rmSync(dir, { recursive: true, force: true }),
  };
}

function supabaseCommon({ name, url, publishable, admin, suffix }) {
  const tokens = {};
  const nameOf = (a) => `${a}${suffix}`;
  return {
    name,
    remote: true,
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
  };
}

export async function supabaseLocalBackend() {
  const { startFakePostgrest, KEYS } = await import("./fake-postgrest.js");
  const pg = (await import("pg")).default;
  const base = process.env.TEST_PG_URL || "postgresql://postgres@127.0.0.1:54329/postgres";
  const dbName = `bridge_test_${randomBytes(4).toString("hex")}`;
  const adminClient = new pg.Client({ connectionString: base });
  await adminClient.connect();
  await adminClient.query(`create database ${dbName}`);
  const dbUrl = base.replace(/\/[^/]*$/, `/${dbName}`);
  const c = new pg.Client({ connectionString: dbUrl });
  await c.connect();
  await c.query(readFileSync(join(ROOT, "test/supabase-roles.sql"), "utf8"));
  await c.query(readFileSync(join(ROOT, "supabase/migration.sql"), "utf8"));
  await c.end();
  const api = await startFakePostgrest({ connectionString: dbUrl });
  const admin = new SupabaseAdmin({ url: api.url, secretKey: KEYS.secret });
  const b = supabaseCommon({ name: "supabase-local", url: api.url, publishable: KEYS.publishable, admin, suffix: "" });
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

export async function backendsFromArgs(argv = process.argv.slice(2)) {
  const wanted = argv.length ? argv : ["sqlite", "supabase-local"];
  const make = { sqlite: sqliteBackend, "supabase-local": supabaseLocalBackend, "supabase-live": supabaseLiveBackend };
  return wanted.map((w) => {
    if (!make[w]) throw new Error(`unknown backend ${w} (use: ${Object.keys(make).join(", ")})`);
    return make[w];
  });
}
