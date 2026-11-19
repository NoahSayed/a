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

  case "init": {
    // Wire a repo up to the bridge: merges a "bridge" server into <repo>/.mcp.json and
    // (with --hook) adds the unread-mail hook to <repo>/.claude/settings.local.json.
    const flags = args.filter((a) => a.startsWith("--"));
    const [repo, name, ...descParts] = args.filter((a) => !a.startsWith("--"));
    if (!repo || !name) {
      console.error('usage: init <repo-path> <agent-name> ["description"] [--hook]');
      process.exit(1);
    }
    const { existsSync, readFileSync, writeFileSync, mkdirSync } = await import("node:fs");
    const { resolve, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const repoDir = resolve(repo);
    if (!existsSync(repoDir)) {
      console.error(`no such directory: ${repoDir}`);
      process.exit(1);
    }
    const here = fileURLToPath(new URL(".", import.meta.url));
    const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : {});

    const mcpPath = join(repoDir, ".mcp.json");
    const mcp = readJson(mcpPath);
    mcp.mcpServers ??= {};
    const env = { AGENT_NAME: name, AGENT_BRIDGE_DB: store.dbPath };
    const prevDesc = mcp.mcpServers.bridge?.env?.AGENT_DESCRIPTION;
    if (descParts.length) env.AGENT_DESCRIPTION = descParts.join(" ");
    else if (prevDesc) env.AGENT_DESCRIPTION = prevDesc;
    mcp.mcpServers.bridge = { command: process.execPath, args: [join(here, "server.js")], env };
    writeFileSync(mcpPath, JSON.stringify(mcp, null, 2) + "\n");
    console.log(`wrote ${mcpPath}  (agent "${name}", db ${store.dbPath})`);

    if (flags.includes("--hook")) {
      const settingsPath = join(repoDir, ".claude", "settings.local.json");
      mkdirSync(join(repoDir, ".claude"), { recursive: true });
      const settings = readJson(settingsPath);
      settings.hooks ??= {};
      settings.hooks.UserPromptSubmit ??= [];
      const command = `"${process.execPath}" "${join(here, "cli.js")}" peek ${name}`;
      const already = JSON.stringify(settings.hooks.UserPromptSubmit).includes("cli.js") &&
        JSON.stringify(settings.hooks.UserPromptSubmit).includes(`peek ${name}`);
      if (!already) {
        settings.hooks.UserPromptSubmit.push({
          hooks: [{ type: "command", command: `AGENT_BRIDGE_DB="${store.dbPath}" ${command}` }],
        });
      }
      writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
      console.log(`wrote ${settingsPath}  (unread-mail hook)`);
    }
    console.log(
      "next: restart Claude Code in that repo and approve the 'bridge' MCP server.\n" +
        "tip: .mcp.json now holds absolute paths for this machine; add it to .gitignore if you don't want to commit it."
    );
    break;
  }

  default:
    console.log(
      "commands: init <repo> <name> [desc] [--hook] | agents | log [n] | tail | send <from> <to> <text...> | peek <agent>"
    );
}
