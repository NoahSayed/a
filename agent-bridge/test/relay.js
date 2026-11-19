// Relay suite: what only relay.js has (config checks, key separation, limits on requests, audit log,
// retention and legal hold, auditor key, TLS and mTLS, persistence). The shared suites (e2e, security,
// concurrency) run against the relay through the `relay-local` backend.
//   node test/relay.js
import assert from "node:assert/strict";
import https from "node:https";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { startRelayProcess } from "./backends.js";
import { homeEnv, rmrf, runCli, summary, test } from "./harness.js";
import { SupabaseAdmin } from "../stores/supabase.js";
import { createStore } from "../store.js";

const sh = promisify(execFile);
const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-relay-suite-"));
const key = () => randomBytes(32).toString("hex");
const sha = (s) => createHash("sha256").update(s).digest("hex");
let n = 0;
const fresh = (name) => join(tmp, `${name}-${n++}`);

async function rpc(base, fn, body, apikey, { raw, headers = {}, agent } = {}) {
  const res = await fetch(`${base}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(apikey ? { apikey } : {}), ...headers },
    body: raw ?? JSON.stringify(body),
    ...(agent ? { dispatcher: agent } : {}),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {}
  return { status: res.status, json, text };
}

// A running relay with two registered agents.
async function relayWith(env = {}, args = []) {
  const dbPath = env.RELAY_DB ?? fresh("db") + ".db";
  const r = await startRelayProcess({ env: { RELAY_DB: dbPath, ...env }, args });
  r.dbPath = dbPath;
  r.admin = new SupabaseAdmin({ url: r.url, secretKey: r.adminKey });
  r.call = (fn, body, apikey = "relay", opts) => rpc(r.url, fn, body, apikey, opts);
  r.tokens = {};
  r.addAgents = async (...names) => {
    for (const nm of names) r.tokens[nm] = await r.admin.createAgent(nm, `agent ${nm}`);
  };
  r.send = (from, to, body) => r.call("bridge_send", { p_token: r.tokens[from], p_to: to, p_body: body, p_type: "fyi" });
  return r;
}

const refusedAtStart = async (env) => {
  try {
    const r = await startRelayProcess({ env: { RELAY_DB: fresh("db") + ".db", ...env } });
    await r.stop();
    return null;
  } catch (e) {
    return e;
  }
};

const opensslOk = await sh("openssl", ["version"]).then(() => true, () => false);

// ------------------------------------------------------------------ startup config

console.log("\n=== relay: startup ===");

await test("refuses to start without an admin key", async () => {
  const e = await refusedAtStart({ RELAY_ADMIN_KEY: "" });
  assert.ok(e, "relay started with no admin key");
  assert.notEqual(e.code, 0);
  assert.match(e.stderr, /RELAY_ADMIN_KEY/);
});

await test("refuses a weak admin key (< 32 characters), accepts 32", async () => {
  for (const weak of ["short", "x".repeat(31), "admin", "password123"]) {
    const e = await refusedAtStart({ RELAY_ADMIN_KEY: weak });
    assert.ok(e, `accepted weak key ${JSON.stringify(weak)}`);
    assert.match(e.stderr, /too weak/);
    assert.ok(!e.stderr.includes(weak) || weak.length < 6, "the key was echoed");
  }
  const ok = await startRelayProcess({ env: { RELAY_DB: fresh("db") + ".db", RELAY_ADMIN_KEY: "k".repeat(32) } });
  await ok.stop();
});

await test("admin key can come from a file; a weak or missing file is refused", async () => {
  const f = join(tmp, "admin.key");
  writeFileSync(f, key() + "\n", { mode: 0o600 });
  const ok = await startRelayProcess({ env: { RELAY_DB: fresh("db") + ".db", RELAY_ADMIN_KEY: undefined, RELAY_ADMIN_KEY_FILE: f } });
  const adminKey = readFileSync(f, "utf8").trim();
  assert.equal((await rpc(ok.url, "bridge_admin_purge", { p_older_than: "30 days" }, adminKey)).status, 200);
  await ok.stop();
  writeFileSync(f, "weak\n");
  assert.match((await refusedAtStart({ RELAY_ADMIN_KEY: undefined, RELAY_ADMIN_KEY_FILE: f })).stderr, /too weak/);
  assert.match((await refusedAtStart({ RELAY_ADMIN_KEY: undefined, RELAY_ADMIN_KEY_FILE: join(tmp, "nope") })).stderr, /RELAY_ADMIN_KEY_FILE/);
});

await test("the same key can't be used for admin and auditor; a weak auditor key is refused", async () => {
  const k = key();
  assert.match((await refusedAtStart({ RELAY_ADMIN_KEY: k, RELAY_AUDITOR_KEY: k })).stderr, /different/);
  assert.match((await refusedAtStart({ RELAY_AUDITOR_KEY: "weak" })).stderr, /too weak/);
});

await test("TLS cert without key (or the reverse) is refused", async () => {
  const e = await refusedAtStart({ RELAY_TLS_CERT: "/nonexistent/cert.pem" });
  assert.match(e.stderr, /together/);
});

// ------------------------------------------------------------------ request handling

console.log("\n=== relay: requests ===");
const R = await relayWith();
await R.addAgents("alice", "bob");

await test("GET /healthz needs no auth and reveals nothing", async () => {
  const res = await fetch(`${R.url}/healthz`);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), { status: "ok" });
  for (const secret of ["alice", "bob", "agent", "unread", R.adminKey, R.tokens.alice]) assert.ok(!text.includes(secret), secret);
  assert.equal((await fetch(`${R.url}/healthz`, { method: "POST" })).status, 405);
});

await test("unknown paths and methods reveal nothing", async () => {
  for (const [method, path] of [["GET", "/"], ["GET", "/rest/v1/bridge_messages"], ["GET", "/rest/v1/bridge_agents"], ["POST", "/rest/v1/bridge_messages"], ["GET", "/admin"], ["GET", "/rest/v1/rpc/bridge_whoami"]]) {
    const res = await fetch(R.url + path, { method, headers: { apikey: R.adminKey }, ...(method === "POST" ? { body: "{}" } : {}) });
    const t = await res.text();
    assert.ok([404, 405].includes(res.status), `${method} ${path}: ${res.status}`);
    assert.ok(!/alice|bob|token_hash|abt_/.test(t), t);
  }
});

await test("PostgREST-style errors: PGRST202 for unknown functions and arguments, JSON error shape", async () => {
  for (const [fn, body] of [
    ["bridge_nope", {}],
    ["bridge_whoami", {}],
    ["bridge_whoami", { p_token: R.tokens.alice, p_extra: 1 }],
    ["bridge_send", { p_token: R.tokens.alice, p_from: "bob", p_to: "bob", p_body: "x" }],
    ["bridge_auth", { p_token: R.tokens.alice }],
    ["constructor", {}],
    ["__proto__", {}],
  ]) {
    const r = await R.call(fn, body);
    assert.equal(r.status, 404, `${fn}: ${r.text}`);
    assert.equal(r.json.code, "PGRST202");
    assert.deepEqual(Object.keys(r.json).sort(), ["code", "details", "hint", "message"]);
  }
  const bad = await R.call("bridge_whoami", { p_token: "x".repeat(30) });
  assert.equal(bad.status, 403);
  assert.deepEqual(Object.keys(bad.json).sort(), ["code", "details", "hint", "message"]);
});

await test("void functions answer 204 with no body", async () => {
  const hb = await R.call("bridge_heartbeat", { p_token: R.tokens.alice, p_description: "d" });
  assert.equal(hb.status, 204);
  assert.equal(hb.text, "");
});

await test("admin key and agent tokens are not interchangeable", async () => {
  const adminFns = [
    ["bridge_admin_create_agent", { p_name: "mallory" }],
    ["bridge_admin_rotate_token", { p_name: "alice" }],
    ["bridge_admin_revoke_agent", { p_name: "alice" }],
    ["bridge_admin_delete_agent", { p_name: "alice" }],
    ["bridge_admin_set_limits", { p_rate_per_minute: 1 }],
    ["bridge_admin_purge", { p_older_than: "0 days" }],
  ];
  for (const [fn, body] of adminFns) {
    for (const k of [null, "", "relay", R.tokens.alice, R.adminKey.slice(0, -1), R.adminKey + "x", R.adminKey.toUpperCase()]) {
      const r = await R.call(fn, body, k);
      assert.equal(r.status, 401, `${fn} with key ${String(k).slice(0, 8)}: ${r.status} ${r.text}`);
    }
  }
  // nothing happened
  assert.equal((await R.call("bridge_whoami", { p_token: R.tokens.alice })).status, 200);
  assert.ok((await R.call("bridge_list_agents", { p_token: R.tokens.alice })).json.every((a) => a.name !== "mallory"));
  // the admin key is not an agent token, in any argument position
  for (const fn of ["bridge_whoami", "bridge_list_agents", "bridge_unread_summary", "bridge_recent"]) {
    const r = await R.call(fn, { p_token: R.adminKey }, R.adminKey);
    assert.equal(r.status, 403, `${fn}: ${r.text}`);
    assert.match(r.json.message, /invalid agent token/);
  }
  // an agent call with the admin key as apikey and a good token acts as the agent, never as admin
  const me = await R.call("bridge_whoami", { p_token: R.tokens.alice }, R.adminKey);
  assert.equal(me.json.agent, "alice");
});

await test("bodies over 256 KB get 413 (declared and streamed), and the relay stays healthy", async () => {
  const big = JSON.stringify({ p_token: R.tokens.alice, p_to: "bob", p_body: "a".repeat(300 * 1024) });
  const r = await R.call("bridge_send", null, "relay", { raw: big });
  assert.equal(r.status, 413, r.text);
  // chunked, no content-length
  const stream = new ReadableStream({
    start(c) {
      for (let i = 0; i < 40; i++) c.enqueue(new TextEncoder().encode("x".repeat(10000)));
      c.close();
    },
  });
  const res = await fetch(`${R.url}/rest/v1/rpc/bridge_send`, { method: "POST", body: stream, duplex: "half", headers: { apikey: "relay" } });
  assert.equal(res.status, 413);
  // just under the limit still works (50000 four-byte characters = 200 KB)
  const ok = await R.send("alice", "bob", "😀".repeat(50000));
  assert.equal(ok.status, 200, ok.text.slice(0, 200));
  assert.equal((await fetch(`${R.url}/healthz`)).status, 200);
});

await test("a JSON body that isn't an object is refused", async () => {
  for (const raw of ["[]", "[1,2]", "null", '"str"', "123", "true", "{bad json", '[{"p_token":"x"}]']) {
    const r = await R.call("bridge_whoami", null, "relay", { raw });
    assert.equal(r.status, 400, `${raw}: ${r.status} ${r.text}`);
    assert.ok(/^PGRST/.test(r.json.code), r.text);
  }
});

await test("errors never carry stack traces, file paths or SQL", async () => {
  const probes = [
    R.call("bridge_whoami", null, "relay", { raw: "{{{" }),
    R.call("bridge_send", { p_token: R.tokens.alice, p_to: "bob", p_body: "x", p_max_hops: "abc" }),
    R.call("bridge_inbox", { p_token: R.tokens.alice, p_thread_id: "nope" }),
    R.call("bridge_inbox", { p_token: R.tokens.alice, p_limit: 1.5 }),
    R.call("bridge_unmark", { p_token: R.tokens.alice, p_ids: "x" }),
    R.call("bridge_send", { p_token: R.tokens.alice, p_to: { a: 1 }, p_body: "x" }),
    R.call("bridge_send", { p_token: R.tokens.alice, p_to: "bob", p_body: "x\u0000y" }),
    R.call("bridge_admin_purge", { p_older_than: "banana" }, R.adminKey),
    R.call("bridge_send", { p_token: R.tokens.alice, p_to: "bob", p_body: "x", p_subject: "s".repeat(300) }), // a rule from the message store
  ];
  for (const r of await Promise.all(probes)) {
    assert.ok(r.status >= 400 && r.status < 500, `${r.status} ${r.text}`);
    assert.ok(!/\bat .*\(|node:|\.js:\d|SELECT |INSERT |sqlite/i.test(r.text), r.text);
  }
});

await test("agent-function arguments are type-checked like Postgres would (400, not 500)", async () => {
  for (const body of [
    { p_token: R.tokens.alice, p_limit: "x" },
    { p_token: R.tokens.alice, p_mark_read: "maybe" },
    { p_token: R.tokens.alice, p_limit: 99999999999 },
  ]) {
    const r = await R.call("bridge_inbox", body);
    assert.equal(r.status, 400, r.text);
  }
});

await test("limits: set via admin, validated, enforced with the SQL messages, and persisted", async () => {
  const lim = await R.admin.setLimits({ ratePerMinute: 2, maxUnreadPerSender: 3 });
  assert.deepEqual(lim, { rate_per_minute: 2, max_unread_per_sender: 3, max_bytes_per_day: 20000000 });
  for (const bad of [{ p_rate_per_minute: 0 }, { p_rate_per_minute: 10001 }, { p_max_bytes_per_day: 10 }]) {
    assert.equal((await R.call("bridge_admin_set_limits", bad, R.adminKey)).status, 400);
  }
  assert.equal((await R.call("bridge_admin_set_limits", { p_rate_per_minute: "x" }, R.adminKey)).status, 400);
  const t = R.tokens.bob;
  const s = (body) => R.call("bridge_send", { p_token: t, p_to: "alice", p_body: body, p_type: "fyi" });
  assert.equal((await s("1")).status, 200);
  assert.equal((await s("2")).status, 200);
  const third = await s("3");
  assert.equal(third.status, 400);
  assert.match(third.json.message, /Rate limit/);
  await R.admin.setLimits({ ratePerMinute: 10000, maxUnreadPerSender: 1, maxBytesPerDay: 1000 });
  assert.match((await s("4")).json.message, /unread messages from you/);
  await R.admin.setLimits({ maxUnreadPerSender: 100000 });
  assert.match((await s("x".repeat(2000))).json.message, /Daily limit/);
  await R.admin.setLimits({ ratePerMinute: 10000, maxUnreadPerSender: 100000, maxBytesPerDay: 100000000 });
});

await test("purge and delete-agent: counts, unknown agents, interval parsing", async () => {
  await R.addAgents("temp");
  await R.send("temp", "alice", "t1");
  await R.send("bob", "temp", "t2");
  assert.equal(await R.admin.deleteAgent("temp"), 2);
  assert.equal((await R.call("bridge_whoami", { p_token: R.tokens.temp })).status, 403);
  await assert.rejects(() => R.admin.deleteAgent("temp"), /Unknown agent/);
  await assert.rejects(() => R.admin.rotateToken("ghost"), /Unknown agent/);
  await assert.rejects(() => R.admin.revokeAgent("ghost"), /Unknown agent/);
  assert.equal(await R.admin.purge(30), 0);
  assert.equal((await R.call("bridge_admin_purge", { p_older_than: "5 fortnights" }, R.adminKey)).status, 400);
  assert.ok((await R.admin.purge(0)) >= 1);
});

await test("agent tokens look like the SQL ones: abt_ + 64 hex, all different", async () => {
  const toks = [R.tokens.alice, R.tokens.bob, await R.admin.rotateToken("bob")];
  for (const t of toks) assert.match(t, /^abt_[0-9a-f]{64}$/);
  assert.equal(new Set(toks).size, 3);
  R.tokens.bob = toks[2];
});

await test("the relay never logs tokens or keys", async () => {
  const out = R.stdout() + R.stderr();
  for (const secret of [R.adminKey, ...Object.values(R.tokens)]) assert.ok(!out.includes(secret), "a secret reached the log");
});

// ------------------------------------------------------------------ at rest

// POSIX permission bits don't exist on NTFS (Windows protects these files with the user-profile ACL),
// so mode assertions only run on POSIX.
const POSIX = process.platform !== "win32";
const assertPrivate = (f, what = f) => {
  if (POSIX) assert.equal(statSync(f).mode & 0o077, 0, `${what} is accessible to others`);
};
const assertMode600 = (f) => {
  if (POSIX) assert.equal(statSync(f).mode & 0o777, 0o600);
};

console.log("\n=== relay: files and persistence ===");

await test("the database file is private (0600) and so are its WAL files", async () => {
  const dir = fresh("perm");
  const r = await relayWith({ RELAY_DB: join(dir, "relay.db") });
  await r.addAgents("alice");
  for (const f of [r.dbPath, r.dbPath + "-wal", r.dbPath + "-shm"]) {
    if (existsSync(f)) assertPrivate(f);
  }
  assertMode600(r.dbPath);
  if (POSIX) assert.equal(statSync(dir).mode & 0o077, 0, "directory is accessible to others");
  await r.stop();
});

await test("tokens are stored only as SHA-256 hashes", async () => {
  const r = await relayWith();
  await r.addAgents("alice", "bob");
  const rotated = await r.admin.rotateToken("bob");
  const db = new DatabaseSync(r.dbPath, { readOnly: true, timeout: 5000 });
  const rows = db.prepare(`SELECT name, token_hash FROM relay_agents ORDER BY name`).all();
  db.close();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].token_hash, sha(r.tokens.alice));
  assert.equal(rows[1].token_hash, sha(rotated));
  await r.stop(); // checkpoints the WAL into the main file
  const bytes = readdirSync(join(r.dbPath, ".."))
    .filter((f) => f.startsWith(r.dbPath.split("/").pop()))
    .map((f) => readFileSync(join(r.dbPath, "..", f)).toString("latin1"))
    .join("");
  for (const t of [r.tokens.alice, r.tokens.bob, rotated, r.adminKey]) assert.ok(!bytes.includes(t), "a token or key is in the database files");
});

await test("restart persistence: agents, tokens, mail, limits, revocation and threads survive", async () => {
  const dbPath = fresh("persist") + ".db";
  const r1 = await relayWith({ RELAY_DB: dbPath });
  await r1.addAgents("alice", "bob", "carol");
  const first = await r1.send("alice", "bob", "before restart");
  await r1.admin.setLimits({ ratePerMinute: 77 });
  await r1.admin.revokeAgent("carol");
  const adminKey = r1.adminKey;
  await r1.stop();
  const r2 = await relayWith({ RELAY_DB: dbPath, RELAY_ADMIN_KEY: adminKey });
  r2.tokens = r1.tokens;
  const inbox = await r2.call("bridge_inbox", { p_token: r2.tokens.bob });
  assert.equal(inbox.json.length, 1);
  assert.equal(inbox.json[0].body, "before restart");
  assert.equal((await r2.call("bridge_whoami", { p_token: r2.tokens.carol })).status, 403);
  assert.equal((await r2.admin.setLimits({})).rate_per_minute, 77);
  const reply = await r2.call("bridge_send", { p_token: r2.tokens.bob, p_to: "alice", p_body: "after", p_type: "fyi", p_thread_id: first.json.thread_id });
  assert.equal(reply.json.hop, 2);
  await assert.rejects(() => r2.admin.createAgent("alice"), /already exists/);
  await r2.stop();
});

await test("the client works against the relay through the real store (relay backend)", async () => {
  const r = await relayWith();
  await r.addAgents("alice", "bob");
  const env = (a) => ({ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: r.url, AGENT_BRIDGE_TOKEN: r.tokens[a] });
  const alice = await createStore({ env: env("alice") });
  const bob = await createStore({ env: env("bob") });
  assert.match(alice.describe(), /^relay:/);
  assert.equal(await alice.identify(), "alice");
  await alice.send({ to: "bob", body: "hello relay", type: "request" });
  assert.equal((await bob.inbox({}))[0].body, "hello relay");
  await assert.rejects(() => createStore({ env: { ...env("alice"), AGENT_BRIDGE_TOKEN: "abt_" + "0".repeat(64) } }).then((s) => s.identify()), /invalid agent token/);
  // auto-selection from RELAY_URL alone
  assert.match((await createStore({ env: { RELAY_URL: r.url, AGENT_BRIDGE_TOKEN: r.tokens.bob } })).describe(), /^relay:/);
  await r.stop();
});

// ------------------------------------------------------------------ audit log

console.log("\n=== relay: audit log ===");

const readAudit = (p) => readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

await test("audit log: sends and deliveries recorded with hashes, never bodies or tokens; file is 0600", async () => {
  const audit = fresh("audit") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob");
  const body = "TOP-SECRET-PAYLOAD-" + randomBytes(6).toString("hex");
  const sent = await r.call("bridge_send", { p_token: r.tokens.alice, p_to: "bob", p_body: body, p_type: "request", p_subject: "SUBJECT-LINE-XYZ" });
  await r.call("bridge_inbox", { p_token: r.tokens.bob });
  await r.call("bridge_whoami", { p_token: "x".repeat(40) }); // a failed login
  await r.call("bridge_admin_purge", { p_older_than: "1 day" }, "wrong".repeat(10));
  await r.stop();
  const raw = readFileSync(audit, "utf8");
  for (const secret of [body, "SUBJECT-LINE-XYZ", ...Object.values(r.tokens), r.adminKey, "x".repeat(40)]) assert.ok(!raw.includes(secret), "secret or body in the audit log");
  assertPrivate(audit, "audit log");
  const lines = readAudit(audit);
  const send = lines.find((l) => l.action === "send");
  assert.equal(send.agent, "alice");
  assert.equal(send.to, "bob");
  assert.equal(send.type, "request");
  assert.equal(send.id, sent.json.id);
  assert.equal(send.thread_id, sent.json.thread_id);
  assert.equal(send.bytes, Buffer.byteLength(body));
  assert.equal(send.sha256, sha(body));
  assert.ok(!Number.isNaN(Date.parse(send.ts)));
  const del = lines.find((l) => l.action === "deliver");
  assert.equal(del.agent, "bob");
  assert.equal(del.id, sent.json.id);
  assert.equal(del.sha256, sha(body));
  assert.ok(lines.some((l) => l.action === "admin.create_agent" && l.agent === "alice"));
  assert.ok(lines.some((l) => l.action === "auth_failed" && l.scope === "agent"));
  assert.ok(lines.some((l) => l.action === "auth_failed" && l.scope === "admin"));
});

await test("audit log: RELAY_AUDIT_BODIES=1 adds the body, nothing else changes", async () => {
  const audit = fresh("audit") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit, RELAY_AUDIT_BODIES: "1" });
  await r.addAgents("alice", "bob");
  await r.send("alice", "bob", "visible-when-asked");
  await r.stop();
  const send = readAudit(audit).find((l) => l.action === "send");
  assert.equal(send.body, "visible-when-asked");
  assert.ok(!readFileSync(audit, "utf8").includes(r.tokens.alice));
});

// ---- tamper evidence

const verify = async (file) => runCli(["verify-audit", file], {});

await test("audit log is hash-chained and verify-audit says OK (also across a relay restart)", async () => {
  const audit = fresh("chain") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob");
  for (let i = 0; i < 5; i++) await r.send("alice", "bob", `m${i}`);
  const adminKey = r.adminKey;
  await r.stop();
  let lines = readAudit(audit);
  assert.equal(lines[0].prev, "0".repeat(64));
  const raw = readFileSync(audit, "utf8").split("\n").filter(Boolean);
  for (let i = 1; i < lines.length; i++) assert.equal(lines[i].prev, sha(raw[i - 1]), `line ${i + 1} prev`);
  for (const l of lines) assert.match(l.hash, /^[0-9a-f]{64}$/);
  const v = await verify(audit);
  assert.equal(v.code, 0, v.err);
  assert.match(v.out, /^OK/);
  // a second run appends to the same chain
  const r2 = await relayWith({ RELAY_AUDIT_LOG: audit, RELAY_DB: r.dbPath, RELAY_ADMIN_KEY: adminKey });
  await r2.admin.setLimits({ ratePerMinute: 50 });
  await r2.stop();
  assert.ok(readAudit(audit).length > lines.length);
  assert.match((await verify(audit)).out, /^OK/);
});

const chainFile = async () => {
  const audit = fresh("tamper") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob");
  for (let i = 0; i < 6; i++) await r.send("alice", "bob", `msg ${i}`);
  await r.stop();
  return { audit, lines: readFileSync(audit, "utf8").split("\n").filter(Boolean) };
};
const brokenAt = async (audit, lines) => {
  writeFileSync(audit, lines.join("\n") + "\n");
  const v = await verify(audit);
  assert.notEqual(v.code, 0, "tampering not detected");
  assert.ok(!v.out.startsWith("OK"));
  return Number((v.out + v.err).match(/line (\d+)/)?.[1]);
};

await test("verify-audit detects an edited line (first broken line reported)", async () => {
  const { audit, lines } = await chainFile();
  const edited = [...lines];
  const e = JSON.parse(edited[4]);
  e.agent = "mallory";
  edited[4] = JSON.stringify(e);
  assert.equal(await brokenAt(audit, edited), 5);
  // editing and re-hashing that line still breaks the NEXT line's link
  const e2 = JSON.parse(lines[4]);
  e2.sha256 = "f".repeat(64);
  const { hash: _h, ...rest } = e2;
  const rehashed = JSON.stringify({ ...rest, hash: sha(JSON.stringify(rest)) });
  const edited2 = [...lines];
  edited2[4] = rehashed;
  assert.equal(await brokenAt(audit, edited2), 6);
  // garbage line
  const garbage = [...lines];
  garbage[2] = "not json";
  assert.equal(await brokenAt(audit, garbage), 3);
});

await test("verify-audit detects a deleted line (middle and first)", async () => {
  const { audit, lines } = await chainFile();
  assert.equal(await brokenAt(audit, [...lines.slice(0, 3), ...lines.slice(4)]), 4);
  assert.equal(await brokenAt(audit, lines.slice(1)), 1);
});

await test("verify-audit detects reordered and duplicated lines", async () => {
  const { audit, lines } = await chainFile();
  const swapped = [...lines];
  [swapped[3], swapped[4]] = [swapped[4], swapped[3]];
  assert.equal(await brokenAt(audit, swapped), 4);
  assert.equal(await brokenAt(audit, [...lines.slice(0, 4), lines[3], ...lines.slice(4)]), 5);
});

await test("verify-audit: missing file and usage errors fail loudly", async () => {
  assert.notEqual((await verify(join(tmp, "does-not-exist"))).code, 0);
  assert.notEqual((await runCli(["verify-audit"], {})).code, 0);
});

// ------------------------------------------------------------------ retention and legal hold

console.log("\n=== relay: retention, legal hold, auditor ===");

const backdate = (dbPath, days, where = "1=1") => {
  const db = new DatabaseSync(dbPath, { timeout: 5000 });
  db.prepare(`UPDATE messages SET created_at = ? WHERE ${where}`).run(new Date(Date.now() - days * 86400000).toISOString());
  db.close();
};
const count = (dbPath) => {
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 5000 });
  const c = db.prepare(`SELECT COUNT(*) AS n FROM messages`).get().n;
  db.close();
  return c;
};

await test("minimum retention: purge and delete-agent refuse to remove younger messages", async () => {
  const audit = fresh("ret") + ".jsonl";
  const r = await relayWith({ RELAY_MIN_RETENTION_DAYS: "30", RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob", "idle");
  await r.send("alice", "bob", "young");
  await assert.rejects(() => r.admin.purge(0), /retention/i);
  await assert.rejects(() => r.admin.purge(29), /retention/i);
  await assert.rejects(() => r.admin.deleteAgent("alice"), /retention/i);
  await assert.rejects(() => r.admin.deleteAgent("bob"), /retention/i);
  assert.equal(count(r.dbPath), 1, "a message younger than the retention period was deleted");
  assert.equal(await r.admin.purge(30), 0);
  assert.equal(await r.admin.deleteAgent("idle"), 0); // no messages: nothing to protect
  backdate(r.dbPath, 40);
  assert.equal(await r.admin.purge(30), 1);
  assert.equal(count(r.dbPath), 0);
  await r.send("alice", "bob", "old one");
  backdate(r.dbPath, 31);
  assert.equal(await r.admin.deleteAgent("bob"), 1);
  await r.stop();
  const lines = readAudit(audit);
  const refused = lines.filter((l) => l.outcome === "refused");
  assert.ok(refused.length >= 4, `refused attempts are audited (${refused.length})`);
  assert.ok(refused.some((l) => l.action === "admin.purge") && refused.some((l) => l.action === "admin.delete_agent" && l.agent === "alice"));
  assert.ok(lines.some((l) => l.action === "admin.purge" && l.outcome === "ok"));
});

await test("legal hold: purge and delete-agent refuse entirely, whatever the age", async () => {
  const audit = fresh("hold") + ".jsonl";
  const r = await relayWith({ RELAY_LEGAL_HOLD: "1", RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob", "idle");
  await r.send("alice", "bob", "held");
  backdate(r.dbPath, 4000);
  await assert.rejects(() => r.admin.purge(0), /legal hold/i);
  await assert.rejects(() => r.admin.purge(3650), /legal hold/i);
  await assert.rejects(() => r.admin.deleteAgent("alice"), /legal hold/i);
  await assert.rejects(() => r.admin.deleteAgent("idle"), /legal hold/i);
  assert.equal(count(r.dbPath), 1);
  // everything else still works, including revoking
  await r.admin.revokeAgent("idle");
  await r.admin.rotateToken("idle");
  await r.stop();
  const lines = readAudit(audit);
  assert.equal(lines.filter((l) => l.outcome === "refused").length, 4);
  assert.ok(lines.every((l) => !("body" in l)));
  assert.match((await verify(audit)).out, /^OK/);
});

await test("RELAY_MIN_RETENTION_DAYS must be a non-negative number", async () => {
  for (const v of ["-1", "abc"]) assert.match((await refusedAtStart({ RELAY_MIN_RETENTION_DAYS: v })).stderr, /RELAY_MIN_RETENTION_DAYS/);
});

await test("auditor key: bridge_admin_export reads messages in a time range, and nothing else works with it", async () => {
  const auditorKey = key();
  const audit = fresh("auditor") + ".jsonl";
  const r = await relayWith({ RELAY_AUDITOR_KEY: auditorKey, RELAY_AUDIT_LOG: audit });
  await r.addAgents("alice", "bob");
  await r.send("alice", "bob", "old message");
  backdate(r.dbPath, 10);
  await r.send("bob", "alice", "new message");
  const exp = (body, k = auditorKey) => r.call("bridge_admin_export", body, k);

  const all = await exp({});
  assert.equal(all.status, 200, all.text);
  assert.deepEqual(all.json.map((m) => m.body), ["old message", "new message"]);
  assert.deepEqual(Object.keys(all.json[0]).sort(), ["body", "created_at", "from_agent", "hop", "id", "max_hops", "read_at", "subject", "thread_id", "to_agent", "type"]);
  const since = new Date(Date.now() - 5 * 86400000).toISOString();
  assert.deepEqual((await exp({ p_from: since })).json.map((m) => m.body), ["new message"]);
  assert.deepEqual((await exp({ p_to: since })).json.map((m) => m.body), ["old message"]);
  assert.deepEqual((await exp({ p_after_id: all.json[0].id, p_limit: 1 })).json.map((m) => m.body), ["new message"]);
  assert.equal((await exp({ p_from: "not a date" })).status, 400);
  // exporting does not consume mail
  assert.equal((await r.call("bridge_inbox", { p_token: r.tokens.bob, p_mark_read: false })).json.length, 1);

  // nobody else can call it
  for (const k of [r.adminKey, r.tokens.alice, "relay", null, auditorKey.slice(0, -1), auditorKey + "0"]) {
    assert.equal((await exp({}, k)).status, 401, `export with ${String(k).slice(0, 8)}`);
  }
  // and the auditor key can do nothing else
  for (const [fn, body] of [
    ["bridge_admin_create_agent", { p_name: "mallory" }],
    ["bridge_admin_purge", { p_older_than: "0 days" }],
    ["bridge_admin_set_limits", { p_rate_per_minute: 1 }],
    ["bridge_admin_delete_agent", { p_name: "alice" }],
  ]) {
    assert.equal((await r.call(fn, body, auditorKey)).status, 401, fn);
  }
  for (const fn of ["bridge_whoami", "bridge_recent", "bridge_inbox"]) {
    const res = await r.call(fn, { p_token: auditorKey }, auditorKey);
    assert.equal(res.status, 403, fn);
  }
  assert.equal(await r.admin.purge(0) >= 0, true);
  await r.stop();
  const lines = readAudit(audit);
  const ex = lines.find((l) => l.action === "auditor.export");
  assert.ok(ex && ex.count === 2);
  assert.ok(!readFileSync(audit, "utf8").includes(auditorKey));
});

await test("without RELAY_AUDITOR_KEY, export is disabled for everyone", async () => {
  const r = await relayWith();
  for (const k of [r.adminKey, "relay", null, "", "undefined", "null"]) assert.equal((await r.call("bridge_admin_export", {}, k)).status, 401);
  await r.stop();
});

// ------------------------------------------------------------------ TLS

console.log("\n=== relay: TLS ===");

async function makePki(dir) {
  const o = (...a) => sh("openssl", a, { cwd: dir });
  await o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=test-ca");
  const leaf = async (name, cn, ext) => {
    await o("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    writeFileSync(join(dir, `${name}.ext`), ext);
    await o("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", `${name}.pem`, "-days", "2", "-extfile", `${name}.ext`);
  };
  await leaf("server", "localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n");
  await leaf("client", "agent-client", "extendedKeyUsage=clientAuth\n");
  // a client certificate from a CA the relay does not trust
  await o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue.key", "-out", "rogue.pem", "-days", "2", "-subj", "/CN=rogue", "-addext", "extendedKeyUsage=clientAuth");
  return (f) => join(dir, f);
}

// registers an agent on a TLS relay (the suite's own fetch can't trust the test CA)
async function addAgentTls(r, name, opts) {
  const res = await httpsPost(r.url, "/rest/v1/rpc/bridge_admin_create_agent", {
    ...opts,
    body: JSON.stringify({ p_name: name }),
    headers: { apikey: r.adminKey },
  });
  assert.equal(res.status, 200, res.text);
  r.tokens[name] = JSON.parse(res.text);
}

function httpsPost(url, path, { ca, cert, key: k, body = "{}", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      { host: u.hostname, port: u.port, path, method: path === "/healthz" ? "GET" : "POST", ca, cert, key: k, headers: { "Content-Type": "application/json", ...headers } },
      (res) => {
        let t = "";
        res.on("data", (d) => (t += d));
        res.on("end", () => resolve({ status: res.statusCode, text: t }));
      }
    );
    req.on("error", reject);
    req.end(path === "/healthz" ? undefined : body);
  });
}

if (!opensslOk) {
  console.log("  SKIP TLS and mTLS tests: openssl is not installed");
} else {
  const pkiDir = mkdtempSync(join(tmp, "pki-"));
  const pki = await makePki(pkiDir);
  const ca = readFileSync(pki("ca.pem"));

  await test("TLS mode: serves HTTPS with the given certificate, plain HTTP is refused", async () => {
    const r = await relayWith({ RELAY_TLS_CERT: pki("server.pem"), RELAY_TLS_KEY: pki("server.key") });
    assert.match(r.url, /^https:/);
    const h = await httpsPost(r.url, "/healthz", { ca });
    assert.equal(h.status, 200);
    // the real client over TLS, trusting the CA the standard Node way
    await addAgentTls(r, "alice", { ca });
    const res = await httpsPost(r.url, "/rest/v1/rpc/bridge_whoami", { ca, body: JSON.stringify({ p_token: r.tokens.alice }) });
    assert.equal(JSON.parse(res.text).agent, "alice");
    // an untrusted certificate is not accepted by default
    await assert.rejects(() => httpsPost(r.url, "/healthz"), /self.signed|unable to verify|certificate/i);
    await assert.rejects(() => fetch(r.url.replace("https:", "http:") + "/healthz"));
    // and the store connects when NODE_EXTRA_CA_CERTS names the CA
    const { stdout } = await sh(
      process.execPath,
      ["-e", `import("./store.js").then(async m=>{const s=await m.createStore({env:{AGENT_BRIDGE_BACKEND:"relay",RELAY_URL:${JSON.stringify(r.url)},AGENT_BRIDGE_TOKEN:${JSON.stringify(r.tokens.alice)}}});console.log(await s.identify())})`],
      { cwd: join(import.meta.dirname, ".."), env: { ...process.env, NODE_EXTRA_CA_CERTS: pki("ca.pem") } }
    );
    assert.equal(stdout.trim(), "alice");
    await r.stop();
  });

  await test("mTLS: with RELAY_TLS_CA only clients holding a certificate from that CA get through", async () => {
    const r = await relayWith({ RELAY_TLS_CERT: pki("server.pem"), RELAY_TLS_KEY: pki("server.key"), RELAY_TLS_CA: pki("ca.pem") });
    const good = { ca, cert: readFileSync(pki("client.pem")), key: readFileSync(pki("client.key")) };
    assert.equal((await httpsPost(r.url, "/healthz", good)).status, 200);
    await assert.rejects(() => httpsPost(r.url, "/healthz", { ca }), /./, "no client certificate was accepted");
    await assert.rejects(
      () => httpsPost(r.url, "/healthz", { ca, cert: readFileSync(pki("rogue.pem")), key: readFileSync(pki("rogue.key")) }),
      /./,
      "a certificate from another CA was accepted"
    );
    // the server certificate itself is not a client credential for this CA... it IS signed by the CA, so it would pass;
    // what matters is the rogue one failing. Now the full client path:
    await addAgentTls(r, "alice", good);
    const env = {
      AGENT_BRIDGE_BACKEND: "relay",
      RELAY_URL: r.url,
      AGENT_BRIDGE_TOKEN: r.tokens.alice,
      RELAY_TLS_CA: pki("ca.pem"),
      RELAY_TLS_CLIENT_CERT: pki("client.pem"),
      RELAY_TLS_CLIENT_KEY: pki("client.key"),
    };
    const s = await createStore({ env });
    assert.equal(await s.identify(), "alice");
    await assert.rejects(
      () => createStore({ env: { ...env, RELAY_TLS_CLIENT_CERT: pki("rogue.pem"), RELAY_TLS_CLIENT_KEY: pki("rogue.key") } }).then((x) => x.identify()),
      /Can't reach/
    );
    await assert.rejects(() => createStore({ env: { ...env, RELAY_TLS_CLIENT_CERT: undefined, RELAY_TLS_CLIENT_KEY: undefined } }).then((x) => x.identify()), /Can't reach/);
    await r.stop();
  });

  await test("RELAY_TLS_CA without a server certificate is refused", async () => {
    assert.match((await refusedAtStart({ RELAY_TLS_CA: pki("ca.pem") })).stderr, /RELAY_TLS_CA/);
  });
}

// ------------------------------------------------------------------ CLI admin against the relay

console.log("\n=== relay: admin CLI ===");

await test("cli admin commands work against the relay (RELAY_URL + RELAY_ADMIN_KEY)", async () => {
  const r = await relayWith();
  const HOME = mkdtempSync(join(tmp, "home-"));
  const env = { ...homeEnv(HOME), RELAY_URL: r.url, RELAY_ADMIN_KEY: r.adminKey };
  const add = await runCli(["add-agent", "gamma", "API server", "--save"], env);
  assert.equal(add.code, 0, add.err);
  const tf = join(HOME, ".agent-bridge", "tokens", "gamma.token");
  assertMode600(tf);
  const tok = readFileSync(tf, "utf8").trim();
  assert.equal((await r.call("bridge_whoami", { p_token: tok })).json.agent, "gamma");
  assert.match((await runCli(["add-agent", "gamma"], env)).err, /already exists/);
  const rot = await runCli(["rotate-token", "gamma", "--save"], env);
  assert.equal(rot.code, 0, rot.err);
  assert.equal((await r.call("bridge_whoami", { p_token: tok })).status, 403);
  assert.match(JSON.parse((await runCli(["limits", "--rate", "7"], env)).out).rate_per_minute.toString(), /^7$/);
  assert.equal((await runCli(["revoke-agent", "gamma"], env)).code, 0);
  assert.match((await runCli(["purge", "30"], env)).out, /deleted 0 message/);
  assert.match((await runCli(["delete-agent", "gamma"], env)).out, /deleted "gamma"/);
  // a wrong admin key is refused, a missing one explains itself
  const bad = await runCli(["add-agent", "delta"], { ...env, RELAY_ADMIN_KEY: key() });
  assert.notEqual(bad.code, 0);
  const missing = await runCli(["add-agent", "delta"], { ...homeEnv(HOME), RELAY_URL: r.url });
  assert.notEqual(missing.code, 0);
  assert.match(missing.err, /RELAY_ADMIN_KEY/);
  // the admin key may also come from a file
  const kf = join(HOME, "admin.key");
  writeFileSync(kf, r.adminKey + "\n");
  assert.equal((await runCli(["add-agent", "delta"], { ...homeEnv(HOME), RELAY_URL: r.url, RELAY_ADMIN_KEY_FILE: kf })).code, 0);
  await r.stop();
});

await test("cli init --relay wires a repo to the relay (token file, no token in .mcp.json)", async () => {
  const r = await relayWith();
  const HOME = mkdtempSync(join(tmp, "home-"));
  const repo = mkdtempSync(join(tmp, "repo-"));
  const env = { ...homeEnv(HOME), RELAY_URL: r.url, RELAY_ADMIN_KEY: r.adminKey };
  const no = await runCli(["init", repo, "gamma", "--relay"], { HOME });
  assert.notEqual(no.code, 0);
  assert.match(no.err, /RELAY_URL/);
  const noTok = await runCli(["init", repo, "gamma", "--relay"], { ...homeEnv(HOME), RELAY_URL: r.url });
  assert.match(noTok.err, /no token file/);
  await runCli(["add-agent", "gamma", "--save"], env);
  const ok = await runCli(["init", repo, "gamma", "API", "--relay"], { ...homeEnv(HOME), RELAY_URL: r.url });
  assert.equal(ok.code, 0, ok.err);
  const mcp = JSON.parse(readFileSync(join(repo, ".mcp.json"), "utf8"));
  const e = mcp.mcpServers.bridge.env;
  assert.equal(e.AGENT_BRIDGE_BACKEND, "relay");
  assert.equal(e.RELAY_URL, r.url);
  assert.equal(e.AGENT_BRIDGE_TOKEN_FILE, join(HOME, ".agent-bridge", "tokens", "gamma.token"));
  assert.ok(!readFileSync(join(repo, ".mcp.json"), "utf8").includes(readFileSync(e.AGENT_BRIDGE_TOKEN_FILE, "utf8").trim()));
  assert.match((await runCli(["init", repo, "gamma", "--relay", "--supabase"], { ...homeEnv(HOME), RELAY_URL: r.url })).err, /choose one/);
  await r.stop();
});

await R.stop();
rmrf(tmp);
process.exit(summary() ? 1 : 0);
