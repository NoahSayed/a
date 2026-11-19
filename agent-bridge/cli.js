#!/usr/bin/env node
// Human-side CLI for the bridge, plus a `peek` mode for a Claude Code hook.
//
//   node cli.js agents                      list connected agents
//   node cli.js log [n]                     last n messages, all agents
//   node cli.js tail                        follow new messages live
//   node cli.js send <from> <to> <text...>  send a message as <from>
//   node cli.js peek <agent>                print an "unread mail" note if any (for hooks)

import { BridgeStore } from "./store.js";

const store = new BridgeStore();
const [cmd, ...args] = process.argv.slice(2);

const line = (m) =>
  `#${m.id} [${m.created_at.slice(11, 19)}] ${m.from_agent} -> ${m.to_agent} (${m.type}, hop ${m.hop}, thread ${m.thread_id.slice(0, 8)})` +
  `${m.read_at ? "" : " *unread*"}\n    ${m.subject ? m.subject + ": " : ""}${m.body.replace(/\n/g, "\n    ")}`;

switch (cmd) {
  case "agents":
    console.table(store.listAgents());
    break;

  case "log":
    store.recent(Number(args[0] || 20)).forEach((m) => console.log(line(m)));
    break;

  case "tail": {
    let last = store.recent(1)[0]?.id ?? 0;
    console.log(`watching ${store.dbPath} (ctrl-c to stop)`);
    setInterval(() => {
      const rows = store.db.prepare(`SELECT * FROM messages WHERE id > ? ORDER BY id`).all(last);
      for (const m of rows) {
        console.log(line(m));
        last = m.id;
      }
    }, 1000);
    break;
  }

  case "send": {
    const [from, to, ...rest] = args;
    if (!from || !to || !rest.length) {
      console.error("usage: send <from> <to> <text...>");
      process.exit(1);
    }
    const m = store.send({ from, to, body: rest.join(" "), type: "request" });
    console.log(`sent #${m.id} (thread ${m.thread_id})`);
    break;
  }

  case "peek": {
    // Used as a Claude Code UserPromptSubmit hook: stdout is added to the agent's context.
    const agent = args[0] || process.env.AGENT_NAME;
    if (!agent) process.exit(0);
    const summary = store.unreadSummary(agent);
    if (summary.length) {
      const who = summary.map((s) => `${s.n} from ${s.from_agent}`).join(", ");
      console.log(`[agent-bridge] You have unread bridge messages (${who}). Call check_inbox when relevant.`);
    }
    break;
  }

  default:
    console.log("commands: agents | log [n] | tail | send <from> <to> <text...> | peek <agent>");
}
