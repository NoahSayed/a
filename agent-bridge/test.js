// End-to-end test: two MCP clients, each with its own server process, talking via one DB file.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const dir = mkdtempSync(join(tmpdir(), "agent-bridge-test-"));
const db = join(dir, "bridge.db");

async function connect(name) {
  const client = new Client({ name: `test-${name}`, version: "0.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [new URL("./server.js", import.meta.url).pathname],
      env: { ...process.env, AGENT_NAME: name, AGENT_BRIDGE_DB: db, AGENT_BRIDGE_MAX_HOPS: "4" },
      stderr: "ignore",
    })
  );
  const call = async (tool, args = {}) => {
    const r = await client.callTool({ name: tool, arguments: args });
    return { text: r.content.map((c) => c.text).join("\n"), isError: !!r.isError };
  };
  return { client, call };
}

try {
  const fe = await connect("frontend");
  const be = await connect("backend");

  const tools = (await fe.client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(tools, ["check_inbox", "get_thread", "list_agents", "send_message", "wait_for_message", "whoami"]);

  const agents = JSON.parse((await fe.call("list_agents")).text).map((a) => a.name);
  assert.deepEqual(agents, ["backend", "frontend"]);

  // backend starts waiting before frontend sends, to exercise the blocking path
  const beWait = be.call("wait_for_message", { timeout_seconds: 10 });
  const sent = await fe.call("send_message", {
    to: "backend",
    subject: "login endpoint",
    body: "What does POST /api/login return?",
  });
  assert.match(sent.text, /Sent message #1 to backend in thread (\S+) \(hop 1\/4\)/);
  const threadId = sent.text.match(/thread (\S+) /)[1];

  const got = await beWait;
  assert.match(got.text, /from: frontend/);
  assert.match(got.text, /What does POST \/api\/login return\?/);

  // reply in thread; frontend waits only on that thread
  const feWait = fe.call("wait_for_message", { timeout_seconds: 10, thread_id: threadId });
  await be.call("send_message", {
    to: "frontend",
    type: "response",
    thread_id: threadId,
    body: '{ "token": string, "user": { "id": number, "email": string } }',
  });
  const reply = await feWait;
  assert.match(reply.text, /type: response/);
  assert.match(reply.text, /"token": string/);

  // already read -> inbox empty
  assert.equal((await fe.call("check_inbox")).text, "Inbox empty.");

  // full thread history
  const hist = await be.call("get_thread", { thread_id: threadId });
  assert.equal((hist.text.match(/--- message/g) || []).length, 2);

  // loop protection: max hops = 4, thread has 2 so far
  await fe.call("send_message", { to: "backend", thread_id: threadId, body: "thanks", type: "fyi" });
  await be.call("send_message", { to: "frontend", thread_id: threadId, body: "np", type: "fyi" });
  const blocked = await fe.call("send_message", { to: "backend", thread_id: threadId, body: "one more" });
  assert.equal(blocked.isError, true);
  assert.match(blocked.text, /loop protection/);

  // validation errors
  assert.equal((await fe.call("send_message", { to: "frontend", body: "me" })).isError, true);
  assert.equal((await fe.call("send_message", { to: "backend", body: "x", thread_id: "nope" })).isError, true);

  // wait timeout path (drain backend's "np" first)
  assert.match((await fe.call("check_inbox")).text, /np/);
  const t = await fe.call("wait_for_message", { timeout_seconds: 1 });
  assert.match(t.text, /No message after 1s/);

  await fe.client.close();
  await be.client.close();
  console.log("all agent-bridge tests passed");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
