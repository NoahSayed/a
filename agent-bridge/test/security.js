// Security suite: what can someone do with only the publishable key (which is not secret)
// and/or a valid token for ONE agent? Talks raw HTTP to the REST layer, bypassing our client.
//   node test/security.js [supabase-local] [supabase-live]
import assert from "node:assert/strict";
import { backendsFromArgs } from "./backends.js";
import { summary, test } from "./harness.js";

const args = process.argv.slice(2);
for (const make of await backendsFromArgs(args.length ? args : ["supabase-local"])) {
  const b = await make();
  if (!b.remote) continue;
  console.log(`\n=== security: ${b.name} ===`);
  const N = b.nameOf;

  const http = async (method, path, { key = b.publishable, body, bearer } = {}) => {
    const headers = { "Content-Type": "application/json" };
    if (key) headers.apikey = key;
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const res = await fetch(`${b.url}/rest/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {}
    return { status: res.status, json, text };
  };
  const rpc = (fn, body, opts) => http("POST", `rpc/${fn}`, { ...opts, body });
  const denied = (r) => [401, 403, 404].includes(r.status);

  try {
    for (const a of ["alice", "bob", "eve"]) await b.addAgent(a);
    const T = b.tokens;
    const first = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "secret plans for bob" });
    assert.equal(first.status, 200, first.text);
    const aliceBobThread = first.json.thread_id;

    await test("no apikey -> 401", async () => {
      assert.equal((await http("GET", "bridge_messages", { key: null })).status, 401);
    });

    await test("tables are unreadable with the publishable key", async () => {
      for (const t of ["bridge_messages", "bridge_agents"]) {
        const r = await http("GET", t);
        assert.ok(denied(r), `${t}: HTTP ${r.status} ${r.text.slice(0, 200)}`);
        assert.ok(!r.text.includes("secret plans"), "message content leaked");
        assert.ok(!r.text.includes("token_hash"), "token hashes leaked");
      }
    });

    await test("direct insert with a forged sender is refused", async () => {
      const r = await http("POST", "bridge_messages", {
        body: { thread_id: aliceBobThread, from_agent: N("alice"), to_agent: N("bob"), type: "fyi", body: "forged", hop: 2 },
      });
      assert.ok(denied(r), `HTTP ${r.status} ${r.text}`);
    });

    await test("direct update/delete of messages and agents is refused", async () => {
      for (const [t, body] of [
        ["bridge_messages", { read_at: null }],
        ["bridge_agents", { revoked_at: null }],
      ]) {
        const r = await http("PATCH", t, { body });
        assert.ok(denied(r), `PATCH ${t}: HTTP ${r.status} ${r.text}`);
        assert.ok(denied(await http("DELETE", t)), `DELETE ${t}`);
      }
    });

    await test("admin functions are refused with the publishable key", async () => {
      for (const [fn, body] of [
        ["bridge_admin_create_agent", { p_name: "mallory" }],
        ["bridge_admin_rotate_token", { p_name: N("alice") }],
        ["bridge_admin_revoke_agent", { p_name: N("alice") }],
        ["bridge_admin_delete_agent", { p_name: N("alice") }],
        ["bridge_admin_purge", { p_older_than: "0 days" }],
      ]) {
        const r = await rpc(fn, body);
        assert.ok(denied(r), `${fn}: HTTP ${r.status} ${r.text}`);
      }
    });

    await test("internal helpers are not callable", async () => {
      for (const [fn, body] of [
        ["bridge_auth", { p_token: T.alice }],
        ["bridge_new_token", {}],
        ["bridge_hash_token", { p_token: "x" }],
      ]) {
        const r = await rpc(fn, body);
        assert.ok(denied(r), `${fn}: HTTP ${r.status} ${r.text}`);
      }
    });

    await test("every agent function rejects a missing, short, long or wrong token", async () => {
      for (const tok of [null, "", "abc", "abt_" + "0".repeat(64), "x".repeat(500)]) {
        for (const [fn, extra] of [
          ["bridge_whoami", {}],
          ["bridge_list_agents", {}],
          ["bridge_inbox", {}],
          ["bridge_unread_summary", {}],
          ["bridge_recent", {}],
          ["bridge_thread", { p_thread_id: aliceBobThread }],
          ["bridge_send", { p_to: N("bob"), p_body: "x" }],
          ["bridge_heartbeat", {}],
        ]) {
          const r = await rpc(fn, { p_token: tok, ...extra });
          assert.ok(r.status >= 400, `${fn} with token ${JSON.stringify(tok)?.slice(0, 20)} -> HTTP ${r.status}`);
        }
      }
    });

    await test("cannot spoof the sender with an extra argument", async () => {
      const r = await rpc("bridge_send", { p_token: T.eve, p_from: N("alice"), p_to: N("bob"), p_body: "I am alice" });
      assert.equal(r.status, 404, r.text); // no such function signature
      const ok = await rpc("bridge_send", { p_token: T.eve, p_to: N("bob"), p_body: "hi from eve", p_type: "fyi" });
      assert.equal(ok.status, 200, ok.text);
      assert.equal(ok.json.from_agent, N("eve"), "sender must come from the token");
    });

    await test("eve can't read alice->bob mail via any read function", async () => {
      const inbox = await rpc("bridge_inbox", { p_token: T.eve, p_mark_read: false });
      assert.ok(!JSON.stringify(inbox.json).includes("secret plans"));
      const recent = await rpc("bridge_recent", { p_token: T.eve, p_limit: 200 });
      assert.ok(!JSON.stringify(recent.json).includes("secret plans"));
      const tail = await rpc("bridge_recent", { p_token: T.eve, p_after_id: 1, p_limit: 200 });
      assert.ok(!JSON.stringify(tail.json).includes("secret plans"));
      const thread = await rpc("bridge_thread", { p_token: T.eve, p_thread_id: aliceBobThread });
      assert.equal(thread.status, 400);
      assert.ok(!thread.text.includes("secret plans"));
    });

    await test("eve can't mark bob's mail as read or inject into alice/bob's thread", async () => {
      await rpc("bridge_inbox", { p_token: T.eve, p_mark_read: true, p_thread_id: aliceBobThread });
      const bobs = await rpc("bridge_inbox", { p_token: T.bob, p_mark_read: false });
      assert.ok(JSON.stringify(bobs.json).includes("secret plans"), "bob's message was consumed by eve");
      const inject = await rpc("bridge_send", { p_token: T.eve, p_to: N("bob"), p_body: "x", p_thread_id: aliceBobThread });
      assert.equal(inject.status, 400);
      assert.match(inject.json.message, /Unknown thread_id/);
    });

    await test("clients can't lift the hop cap above 100", async () => {
      const first = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "hop 1", p_type: "fyi", p_max_hops: 100000 });
      const tid = first.json.thread_id;
      for (let i = 2; i <= 100; i++) {
        const r = await rpc("bridge_send", {
          p_token: i % 2 ? T.alice : T.bob,
          p_to: i % 2 ? N("bob") : N("alice"),
          p_body: `hop ${i}`,
          p_type: "fyi",
          p_thread_id: tid,
          p_max_hops: 100000,
        });
        assert.equal(r.status, 200, `hop ${i}: ${r.text}`);
      }
      const over = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "101", p_thread_id: tid, p_max_hops: 100000 });
      assert.equal(over.status, 400);
      assert.match(over.json.message, /100-message limit/);
      await rpc("bridge_inbox", { p_token: T.bob, p_limit: 100 });
      await rpc("bridge_inbox", { p_token: T.alice, p_limit: 100 });
    });

    await test("oversized inputs are rejected by the database itself", async () => {
      const big = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "z".repeat(50001) });
      assert.equal(big.status, 400, big.text);
      const empty = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "" });
      assert.equal(empty.status, 400, empty.text);
      const subj = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "x", p_subject: "s".repeat(201) });
      assert.equal(subj.status, 400, subj.text);
      const type = await rpc("bridge_send", { p_token: T.alice, p_to: N("bob"), p_body: "x", p_type: "command" });
      assert.equal(type.status, 400, type.text);
      const self = await rpc("bridge_send", { p_token: T.alice, p_to: N("alice"), p_body: "x" });
      assert.equal(self.status, 400, self.text);
    });

    await test("a new-style key in the Authorization header is rejected (client must not send it)", async () => {
      const r = await rpc("bridge_whoami", { p_token: T.alice }, { bearer: b.publishable });
      assert.equal(r.status, 401);
    });

    await test("rotating a token kills the old one", async () => {
      const newTok = await b.admin.rotateToken(N("eve"));
      assert.equal((await rpc("bridge_whoami", { p_token: T.eve })).status, 403);
      const me = await rpc("bridge_whoami", { p_token: newTok });
      assert.equal(me.status, 200);
      assert.equal(me.json.agent, N("eve"));
      T.eve = newTok;
    });

    await test("revoked agents can't act and can't be messaged; rotate re-enables", async () => {
      await b.admin.revokeAgent(N("eve"));
      assert.equal((await rpc("bridge_whoami", { p_token: T.eve })).status, 403);
      const toEve = await rpc("bridge_send", { p_token: T.alice, p_to: N("eve"), p_body: "x" });
      assert.equal(toEve.status, 400);
      assert.match(toEve.json.message, /Unknown agent/);
      const list = await rpc("bridge_list_agents", { p_token: T.alice });
      assert.ok(!list.json.some((a) => a.name === N("eve")), "revoked agent still listed");
      T.eve = await b.admin.rotateToken(N("eve"));
      assert.equal((await rpc("bridge_whoami", { p_token: T.eve })).status, 200);
    });

    await test("duplicate agent names are refused", async () => {
      await assert.rejects(() => b.admin.createAgent(N("alice")), /already exists/);
    });

    await test("agent names are validated", async () => {
      for (const bad of ["Alice", "a b", "../x", "", "x".repeat(41), "-lead"]) {
        await assert.rejects(() => b.admin.createAgent(bad), undefined, `accepted "${bad}"`);
      }
    });

    if (b.pool) {
      await test("tokens are stored only as SHA-256 hashes", async () => {
        const { rows } = await b.pool.query(`select name, token_hash from public.bridge_agents`);
        for (const r of rows) {
          assert.equal(r.token_hash.length, 32);
          for (const tok of Object.values(T)) assert.ok(!r.token_hash.toString("utf8").includes(tok));
        }
      });

      await test("anon role has no table privileges at the SQL level", async () => {
        const { rows } = await b.pool.query(
          `select t, has_table_privilege('anon', t, 'select') s, has_table_privilege('anon', t, 'insert') i,
                  has_table_privilege('anon', t, 'update') u, has_table_privilege('anon', t, 'delete') d
             from unnest(array['public.bridge_messages','public.bridge_agents']) t`
        );
        for (const r of rows) assert.deepEqual([r.s, r.i, r.u, r.d], [false, false, false, false], r.t);
      });
    }
  } finally {
    await b.cleanup();
  }
}

process.exit(summary() ? 1 : 0);
