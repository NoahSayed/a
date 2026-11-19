// Child process used by concurrency.js: one agent doing one job against the store.
import { createStore } from "../store.js";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const job = JSON.parse(input);
// Barrier before the mailbox is even opened: the startup race is in opening it.
if (job.openAt) await new Promise((r) => setTimeout(r, Math.max(0, job.openAt - Date.now())));
const store = await createStore();
await store.identify();
// Start barrier: every worker in a batch begins at the same wall-clock moment.
if (job.startAt) await new Promise((r) => setTimeout(r, Math.max(0, job.startAt - Date.now())));

const out = [];
switch (job.op) {
  case "send":
    out.push(await store.send({ to: job.to, body: job.body, type: "fyi", maxHops: job.maxHops }));
    break;
  case "sendMany":
    for (let i = 0; i < job.n; i++) {
      out.push(
        await store.send({
          to: job.to,
          body: `${job.tag}-${i}`,
          type: "fyi",
          threadId: job.fresh ? null : job.threadId ?? null,
          maxHops: job.maxHops ?? 20,
        })
      );
    }
    break;
  case "drain":
    for (;;) {
      const rows = await store.inbox({ limit: job.batch ?? 100 });
      if (!rows.length) break;
      out.push(...rows);
      // like a real agent doing work between reads; lets other readers get the lock
      if (job.pauseMs) await new Promise((r) => setTimeout(r, job.pauseMs));
    }
    break;
  case "drainFor": {
    const end = Date.now() + job.ms;
    while (Date.now() < end) {
      const rows = await store.inbox({ limit: job.batch ?? 100 });
      out.push(...rows);
      if (!rows.length) await new Promise((r) => setTimeout(r, 50));
    }
    break;
  }
  default:
    throw new Error(`unknown op ${job.op}`);
}
await store.close();
process.stdout.write(JSON.stringify(out.map((m) => ({ id: m.id, hop: m.hop, thread_id: m.thread_id }))));
