// Concurrency suite: separate OS processes hammering one backend at the same time.
//   node test/concurrency.js [sqlite] [supabase-local] [supabase-live]
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { backendsFromArgs } from "./backends.js";
import { summary, test } from "./harness.js";

const WORKER = fileURLToPath(new URL("./worker.js", import.meta.url));

function worker(env, op, payload) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [WORKER], { env: { ...process.env, ...env } });
    let out = "",
      err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.stdin.end(JSON.stringify({ op, ...payload }));
    p.on("close", (code) => (code === 0 ? resolve(JSON.parse(out)) : reject(new Error(`worker ${op} failed: ${err}`))));
  });
}

const live = process.argv.includes("supabase-live");
const PER_WORKER = live ? 10 : 25;
const WORKERS = 4;

for (const make of await backendsFromArgs()) {
  const b = await make();
  console.log(`\n=== concurrency: ${b.name} (${WORKERS} processes x ${PER_WORKER}) ===`);
  const N = b.nameOf;
  let restoreLimits = null;
  try {
    if (!b.remote) {
      await test("16 agents starting at the same instant on a brand-new database (8 rounds)", async () => {
        const env = b.envFor("ping");
        // The race is probabilistic, so race many times: 16 processes x 8 fresh mailboxes.
        const names = Array.from({ length: 16 }, (_, i) => `starter${i}`);
        for (let round = 0; round < 8; round++) {
          const fresh = { ...env, AGENT_BRIDGE_DB: env.AGENT_BRIDGE_DB.replace(/bridge\.db$/, `fresh-start-${round}.db`) };
          const openAt = Date.now() + 1200; // every process opens the brand-new mailbox at the same moment
          const res = await Promise.all(
            names.map((n, i) =>
              worker({ ...fresh, AGENT_NAME: n }, "send", { to: names[(i + 1) % names.length], body: `hi from ${n}`, openAt })
            )
          );
          assert.equal(res.flat().length, 16, `round ${round}`);
        }
      });
    }

    for (const a of ["ping", "pong", "reader"]) await b.addAgent(a);
    // load/attack tests send far faster than a real agent; the abuse limits have their own tests
    restoreLimits = await b.setLimits({ ratePerMinute: 10000, maxUnreadPerSender: 100000 });

    // the server caps a thread at 100 messages: seed + WORKERS * perThread must stay <= 100
    const perThread = Math.min(PER_WORKER, Math.floor(99 / WORKERS));
    // Slack has no lock, so parallel replies can share a hop number (readers count messages instead;
    // see test/slack.js). Exactly-once delivery below still has to hold on Slack.
    if (b.kind !== "slack") await test(`${WORKERS * perThread} concurrent sends into ONE thread get unique, gap-free hops`, async () => {
      const [seed] = await worker(b.envFor("ping"), "send", { to: N("pong"), body: "seed", maxHops: 100 });
      assert.ok(seed?.thread_id, "seed message has no thread_id");
      const barrier = Date.now() + 1500;
      const results = await Promise.all(
        Array.from({ length: WORKERS }, (_, w) =>
          worker(b.envFor(w % 2 ? "ping" : "pong"), "sendMany", {
            startAt: barrier,
            to: N(w % 2 ? "pong" : "ping"),
            n: perThread,
            threadId: seed.thread_id,
            tag: `w${w}`,
            maxHops: 100,
          })
        )
      );
      const all = results.flat();
      assert.ok(all.every((m) => m.thread_id === seed.thread_id), "a send escaped into another thread");
      const hops = [1, ...all.map((m) => m.hop)].sort((a, b) => a - b);
      assert.equal(hops.length, WORKERS * perThread + 1);
      hops.forEach((h, i) => assert.equal(h, i + 1, `hop sequence broken at ${i + 1}: ${h}`));
      await worker(b.envFor("ping"), "drain", {});
      await worker(b.envFor("pong"), "drain", {});
    });

    const drainAll = () => Promise.all(["ping", "pong", "reader"].map((a) => worker(b.envFor(a), "drain", {})));

    await test(`${WORKERS} processes reading ONE inbox at once: every message delivered exactly once`, async () => {
      await drainAll();
      const total = WORKERS * PER_WORKER;
      await worker(b.envFor("ping"), "sendMany", { to: N("reader"), n: total, tag: "r", fresh: true });
      const got = await Promise.all(
        (() => {
          const startAt = Date.now() + 1500;
          return Array.from({ length: WORKERS }, () => worker(b.envFor("reader"), "drain", { batch: 2, startAt, pauseMs: 5 }));
        })()
      );
      const ids = got.flat().map((m) => m.id);
      assert.equal(ids.length, total, `delivered ${ids.length}, expected ${total}`);
      assert.equal(new Set(ids).size, total, "some message was delivered more than once");
      const per = got.map((g) => g.length);
      console.log(`       split across readers: ${per.join(" / ")}`);
      assert.ok(per.filter((n) => n > 0).length >= 2, "readers did not actually overlap; test proved nothing");
    });

    await test("mixed send + read storm leaves no unread mail and no duplicates", async () => {
      await drainAll();
      const senders = Array.from({ length: WORKERS }, (_, w) =>
        worker(b.envFor("ping"), "sendMany", { to: N("pong"), n: PER_WORKER, tag: `m${w}`, fresh: true })
      );
      const readers = Array.from({ length: 2 }, () =>
        worker(b.envFor("pong"), "drainFor", { ms: live ? 15000 : 6000, batch: 5 })
      );
      await Promise.all(senders);
      const got = (await Promise.all(readers)).flat();
      const rest = await worker(b.envFor("pong"), "drain", {});
      const ids = [...got, ...rest].map((m) => m.id);
      assert.equal(ids.length, WORKERS * PER_WORKER);
      assert.equal(new Set(ids).size, ids.length);
    });
  } finally {
    if (restoreLimits) await restoreLimits().catch(() => {});
    await b.cleanup();
  }
}

process.exit(summary() ? 1 : 0);
