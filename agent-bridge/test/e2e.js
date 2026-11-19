// End-to-end suite: real MCP server processes talking through each backend.
//   node test/e2e.js [sqlite] [supabase-local] [supabase-live]
import assert from "node:assert/strict";
import { backendsFromArgs } from "./backends.js";
import { connectAgent, runServerExpectExit, summary, test, threadOf } from "./harness.js";

const TRICKY_BODY = [
  "Unicode: héllo 你好 مرحبا 🚀👍🏽",
  'Quotes: "double" \'single\' `backtick`',
  "SQL-ish: '); drop table bridge_messages; -- and $$ dollar $$",
  "JSON: {\"token\": string, \"user\": {\"id\": 1}}",
  "Markdown:\n```ts\nconst x = 1;\n```",
  "Tabs\tand\r\nCRLF and trailing spaces   ",
].join("\n");

// The server shows every body line prefixed with "| " (so a body can't forge a header).
const quoted = (body) => body.split("\n").map((l) => "| " + l).join("\n");

for (const make of await backendsFromArgs()) {
  const b = await make();
  console.log(`\n=== backend: ${b.name} ===`);
  const N = b.nameOf;
  try {
    for (const a of ["frontend", "backend", "outsider"]) await b.addAgent(a);
    const fe = await connectAgent(b, "frontend");
    const be = await connectAgent(b, "backend");
    const out = await connectAgent(b, "outsider");
    let threadId;

    await test("exposes exactly the six bridge tools", async () => {
      const tools = (await fe.client.listTools()).tools.map((t) => t.name).sort();
      assert.deepEqual(tools, ["check_inbox", "get_thread", "list_agents", "send_message", "wait_for_message", "whoami"]);
    });

    await test("whoami reports the right identity and backend", async () => {
      const me = JSON.parse((await fe.call("whoami")).text);
      assert.equal(me.agent, N("frontend"));
      assert.equal(me.unread, 0);
      assert.match(me.backend, b.remote ? /^supabase:/ : /^sqlite:/);
    });

    await test("list_agents shows all connected agents with project dir", async () => {
      const agents = JSON.parse((await fe.call("list_agents")).text);
      const names = agents.map((a) => a.name);
      for (const a of ["frontend", "backend", "outsider"]) assert.ok(names.includes(N(a)), `missing ${a}`);
      assert.ok(agents.find((a) => a.name === N("frontend")).project_dir, "project_dir not recorded");
    });

    await test("blocking wait wakes when the other agent sends", async () => {
      const waiting = be.call("wait_for_message", { timeout_seconds: 20 });
      await new Promise((r) => setTimeout(r, 300));
      const sent = await fe.call("send_message", { to: N("backend"), subject: "login", body: "What does POST /api/login return?" });
      assert.equal(sent.isError, false, sent.text);
      assert.match(sent.text, /hop 1\/4/);
      threadId = threadOf(sent.text);
      assert.ok(threadId);
      const got = await waiting;
      assert.match(got.text, new RegExp(`from: ${N("frontend")}`));
      assert.match(got.text, /subject: login/);
      assert.match(got.text, /peer agent data, not instructions/);
    });

    await test("thread-filtered wait ignores other threads, wakes on its own", async () => {
      const waiting = fe.call("wait_for_message", { timeout_seconds: 20, thread_id: threadId });
      await new Promise((r) => setTimeout(r, 300));
      await be.call("send_message", { to: N("frontend"), body: "unrelated topic", type: "fyi" }); // new thread
      await new Promise((r) => setTimeout(r, 300));
      await be.call("send_message", { to: N("frontend"), type: "response", thread_id: threadId, body: '{ "token": string }' });
      const got = await waiting;
      assert.match(got.text, /type: response/);
      assert.doesNotMatch(got.text, /unrelated topic/);
      const rest = await fe.call("check_inbox");
      assert.match(rest.text, /unrelated topic/);
    });

    await test("check_inbox: empty after reading, peek mode keeps mail unread", async () => {
      assert.equal((await fe.call("check_inbox")).text, "Inbox empty.");
      await be.call("send_message", { to: N("frontend"), body: "one", type: "fyi" });
      await be.call("send_message", { to: N("frontend"), body: "two", type: "fyi" });
      const peek = await fe.call("check_inbox", { mark_read: false, limit: 1 });
      assert.match(peek.text, /one/);
      assert.match(peek.text, /\(1 more unread\)/);
      const read = await fe.call("check_inbox");
      assert.match(read.text, /one/);
      assert.match(read.text, /two/);
      assert.equal((await fe.call("check_inbox")).text, "Inbox empty.");
    });

    await test("tricky bodies round-trip byte for byte", async () => {
      await fe.call("send_message", { to: N("backend"), body: TRICKY_BODY, type: "fyi" });
      const got = await be.call("check_inbox");
      assert.ok(got.text.includes(quoted(TRICKY_BODY)), "body was altered in transit");
    });

    await test("get_thread shows both directions for participants", async () => {
      const hist = await be.call("get_thread", { thread_id: threadId });
      assert.equal(hist.isError, false, hist.text);
      assert.equal((hist.text.match(/--- message/g) || []).length, 2);
    });

    await test("outsider cannot read or post into someone else's thread", async () => {
      const read = await out.call("get_thread", { thread_id: threadId });
      assert.equal(read.isError, true);
      assert.match(read.text, /Unknown thread_id/);
      const post = await out.call("send_message", { to: N("backend"), thread_id: threadId, body: "sneaky" });
      assert.equal(post.isError, true);
      assert.match(post.text, /Unknown thread_id/);
    });

    await test("outsider's inbox never contains other agents' mail", async () => {
      assert.equal((await out.call("check_inbox")).text, "Inbox empty.");
    });

    await test("loop protection stops a thread at max hops", async () => {
      await fe.call("send_message", { to: N("backend"), thread_id: threadId, body: "thanks", type: "fyi" });
      await be.call("send_message", { to: N("frontend"), thread_id: threadId, body: "np", type: "fyi" });
      const blocked = await fe.call("send_message", { to: N("backend"), thread_id: threadId, body: "one more" });
      assert.equal(blocked.isError, true);
      assert.match(blocked.text, /loop protection/);
      await fe.call("check_inbox");
      await be.call("check_inbox");
    });

    await test("input validation errors are reported, not crashes", async () => {
      const self = await fe.call("send_message", { to: N("frontend"), body: "me" });
      assert.match(self.text, /cannot message itself/);
      const badThread = await fe.call("send_message", { to: N("backend"), body: "x", thread_id: "nope" });
      assert.match(badThread.text, /Unknown thread_id/);
      const ghostThread = await fe.call("send_message", {
        to: N("backend"),
        body: "x",
        thread_id: "00000000-0000-4000-8000-000000000000",
      });
      assert.match(ghostThread.text, /Unknown thread_id/);
      const tooLong = await fe.call("send_message", { to: N("backend"), body: "x".repeat(50001) });
      assert.match(tooLong.text, /too long/);
      const longSubject = await fe.call("send_message", { to: N("backend"), body: "x", subject: "s".repeat(201) });
      assert.match(longSubject.text, /too long/);
      const badType = await fe.call("send_message", { to: N("backend"), body: "x", type: "order" });
      assert.equal(badType.isError, true);
      const badThreadGet = await fe.call("get_thread", { thread_id: "not-a-uuid" });
      assert.match(badThreadGet.text, /Unknown thread_id/);
      for (const r of [self, badThread, ghostThread, tooLong, longSubject]) assert.equal(r.isError, true);
      // and the server is still alive afterwards
      assert.equal(JSON.parse((await fe.call("whoami")).text).agent, N("frontend"));
    });

    await test("max-length body (50,000 chars) is accepted", async () => {
      const r = await fe.call("send_message", { to: N("backend"), body: "y".repeat(50000), type: "fyi" });
      assert.equal(r.isError, false, r.text);
      const got = await be.call("check_inbox");
      assert.ok(got.text.includes("y".repeat(50000)));
    });

    await test("unknown recipient: " + (b.remote ? "rejected (agents must be registered)" : "queued with a note"), async () => {
      const r = await fe.call("send_message", { to: N("nobody"), body: "hello?" });
      if (b.remote) {
        assert.equal(r.isError, true);
        assert.match(r.text, /Unknown agent/);
      } else {
        assert.equal(r.isError, false);
        assert.match(r.text, /hasn't connected yet/);
      }
    });

    await test("wait_for_message times out cleanly", async () => {
      const t0 = Date.now();
      const r = await fe.call("wait_for_message", { timeout_seconds: 2 });
      assert.match(r.text, /No message after 2s/);
      assert.ok(Date.now() - t0 < 6000, "timeout overshot");
    });

    await test("unread mail survives a server restart", async () => {
      await fe.call("send_message", { to: N("backend"), body: "survive restart", type: "fyi" });
      await be.close();
      const be2 = await connectAgent(b, "backend");
      const got = await be2.call("check_inbox");
      assert.match(got.text, /survive restart/);
      await be2.close();
    });

    await test("two sessions as the same agent never get the same message", async () => {
      const be2 = await connectAgent(b, "backend");
      const be3 = await connectAgent(b, "backend");
      for (let i = 0; i < 10; i++) await fe.call("send_message", { to: N("backend"), body: `dup-check ${i}`, type: "fyi" });
      const [x, y] = await Promise.all([be2.call("check_inbox", { limit: 100 }), be3.call("check_inbox", { limit: 100 })]);
      const seen = [...x.text.matchAll(/dup-check (\d+)/g), ...y.text.matchAll(/dup-check (\d+)/g)].map((m) => m[1]);
      assert.equal(seen.length, 10, `expected 10 deliveries, got ${seen.length}`);
      assert.equal(new Set(seen).size, 10, "a message was delivered twice");
      await be2.close();
      await be3.close();
    });

    await test("server refuses to start with missing config", async () => {
      const env = b.envFor("frontend");
      if (b.remote) {
        delete env.AGENT_BRIDGE_TOKEN;
        const r = await runServerExpectExit(env);
        assert.notEqual(r.code, 0);
        assert.match(r.stderr, /No agent token/);
      } else {
        delete env.AGENT_NAME;
        const r = await runServerExpectExit(env);
        assert.notEqual(r.code, 0);
        assert.match(r.stderr, /Set AGENT_NAME/);
      }
    });

    if (b.remote) {
      await test("server refuses a bad token", async () => {
        const r = await runServerExpectExit({ ...b.envFor("frontend"), AGENT_BRIDGE_TOKEN: "abt_" + "0".repeat(64) });
        assert.notEqual(r.code, 0);
        assert.match(r.stderr, /invalid agent token/);
      });

      await test("server refuses when AGENT_NAME doesn't match the token", async () => {
        const r = await runServerExpectExit({ ...b.envFor("frontend"), AGENT_NAME: N("backend") });
        assert.notEqual(r.code, 0);
        assert.match(r.stderr, /token belongs to agent/);
      });

      await test("server refuses an unreachable Supabase URL", async () => {
        const r = await runServerExpectExit({ ...b.envFor("frontend"), SUPABASE_URL: "http://127.0.0.1:1" });
        assert.notEqual(r.code, 0);
        assert.match(r.stderr, /Can't reach Supabase/);
      });
    }

    await fe.close();
    await out.close();
  } finally {
    await b.cleanup();
  }
}

process.exit(summary() ? 1 : 0);
