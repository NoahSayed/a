#!/usr/bin/env node
// agent-bridge CLI: set up repos, watch traffic, and (Supabase) manage agents.
// Run with no arguments for help.

import { existsSync, lstatSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENT_NAME_RE, backendFromEnv, createStore, expandHome, resolveDbPath } from "./store.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const HELP = `agent-bridge CLI

Setup
  init <repo> <name> ["desc"] [--hook] [--supabase] [--token-file <path>]
                                  wire a repo's .mcp.json to the bridge (and optional hook)
Watching (local: all traffic; Supabase: traffic of the agent whose token you use)
  whoami | agents | log [n] | tail
  send <to> <text...>             send as AGENT_NAME (local, default "human") or as the token's agent
  peek [name]                     print an "unread mail" note if any (used by the hook)
Supabase admin (needs SUPABASE_URL + SUPABASE_SECRET_KEY)
  add-agent <name> ["desc"] [--save]   register an agent, print its token (--save: store it locally)
  rotate-token <name> [--save]         issue a new token (old one stops working)
  revoke-agent <name>                  disable an agent
  delete-agent <name>                  remove an agent and all its messages
  limits [--rate N] [--max-unread N] [--max-mb-day N]
                                       show or change the per-agent abuse limits
  purge [days=30]                      delete messages older than N days
  save-token <name>                    read a token from stdin into ~/.agent-bridge/tokens/<name>.token
Slack (needs SLACK_CHANNEL_ID)
  slack-manifest <name> ["desc"]       print a Slack app manifest for this agent (one app per agent)
  save-slack-token <name>              read the app's bot token (xoxb-...) from stdin, store it 0600
  init <repo> <name> --slack [--hook]  wire a repo to the Slack channel

Environment: AGENT_BRIDGE_DB (local), SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY,
AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE (Supabase), SLACK_CHANNEL_ID,
SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_FILE (Slack). See README.md.`;

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith("--")));
const flagValue = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const VALUE_FLAGS = new Set(["--token-file", "--rate", "--max-unread", "--max-mb-day"]);
const positional = argv.filter((a, i) => !a.startsWith("--") && !(i > 0 && VALUE_FLAGS.has(argv[i - 1])));
const [cmd, ...args] = positional;

// POSIX single-quoting: nothing inside is expanded by the shell that runs the hook (R1-06).
const shq = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;

// init writes into the user's repo; never through a symlink that points somewhere else (R1-14).
function refuseSymlink(p) {
  try {
    if (lstatSync(p).isSymbolicLink()) {
      throw new Error(`${p} is a symlink; refusing to write through it. Replace it with a regular file or directory.`);
    }
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}

const slackTokenPath = (name) => expandHome(`~/.agent-bridge/tokens/${name}.slack-token`);
const tokenPath = (name) => expandHome(`~/.agent-bridge/tokens/${name}.token`);
function saveToken(name, token, p = tokenPath(name)) {
  mkdirSync(expandHome("~/.agent-bridge/tokens"), { recursive: true, mode: 0o700 });
  writeFileSync(p, token + "\n", { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}

const line = (m) =>
  `#${m.id} [${String(m.created_at).slice(11, 19)}] ${m.from_agent} -> ${m.to_agent} ` +
  `(${m.type}, hop ${m.hop}, thread ${String(m.thread_id).slice(0, 8)})${m.read_at ? "" : " *unread*"}\n` +
  `    ${m.subject ? m.subject + ": " : ""}${m.body.replace(/\n/g, "\n    ")}`;

// Local mode shows every message on the bridge; Supabase only shows the token's own traffic.
const listRecent = (store, opts) => (store.allRecent ? store.allRecent(opts) : store.recent(opts));

async function admin() {
  const { SupabaseAdmin } = await import("./stores/supabase.js");
  return new SupabaseAdmin({
    url: process.env.SUPABASE_URL,
    secretKey: process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY,
  });
}

async function main() {
  switch (cmd) {
    case "whoami": {
      const store = await createStore({ agentName: process.env.AGENT_NAME || "human" });
      console.log(JSON.stringify({ ...(await store.whoami()), backend: store.describe() }, null, 2));
      break;
    }

    case "agents": {
      const store = await createStore({ agentName: process.env.AGENT_NAME || "human" });
      console.table(await store.listAgents());
      break;
    }

    case "log": {
      const store = await createStore({ agentName: process.env.AGENT_NAME || "human" });
      (await listRecent(store, { limit: Number(args[0] || 20) })).forEach((m) => console.log(line(m)));
      break;
    }

    case "tail": {
      const store = await createStore({ agentName: process.env.AGENT_NAME || "human" });
      let last = (await listRecent(store, { limit: 1 }))[0]?.id ?? 0;
      console.log(`watching ${store.describe()} (ctrl-c to stop)`);
      for (;;) {
        try {
          for (const m of await listRecent(store, { limit: 100, afterId: last })) {
            console.log(line(m));
            last = m.id;
          }
        } catch (e) {
          console.error(`(poll failed: ${e.message})`);
        }
        await new Promise((r) => setTimeout(r, store.pollIntervalMs));
      }
    }

    case "send": {
      const [to, ...rest] = args;
      if (!to || !rest.length) throw new Error("usage: send <to> <text...>");
      const store = await createStore({ agentName: process.env.AGENT_NAME || "human" });
      await store.identify();
      const m = await store.send({ to, body: rest.join(" "), type: "request" });
      console.log(`sent #${m.id} as ${m.from_agent} (thread ${m.thread_id})`);
      break;
    }

    case "peek": {
      // Used as a Claude Code UserPromptSubmit hook: stdout is added to the agent's context.
      // Never fails loudly: a broken bridge must not block the user's prompt.
      try {
        const agent = args[0] || process.env.AGENT_NAME;
        if (backendFromEnv() === "sqlite" && !agent) return;
        // Short busy timeout: on SQLite the read is synchronous, so the race below can't cut it short (R1-08).
        const store = await createStore({ agentName: agent, busyTimeoutMs: 1500 });
        const summary = await Promise.race([
          store.unreadSummary(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 4000)),
        ]);
        if (summary.length) {
          const who = summary.map((s) => `${s.n} from ${s.from_agent}`).join(", ");
          console.log(`[agent-bridge] You have unread bridge messages (${who}). Call check_inbox when relevant.`);
        }
      } catch (e) {
        // stay silent so a broken bridge never blocks the prompt; AGENT_BRIDGE_DEBUG=1 shows why
        if (process.env.AGENT_BRIDGE_DEBUG) console.error(`agent-bridge peek: ${e.message}`);
      }
      process.exit(0);
    }

    case "init": {
      const [repo, name, ...descParts] = args;
      if (!repo || !name) throw new Error('usage: init <repo-path> <agent-name> ["description"] [--hook] [--supabase | --slack]');
      if (!AGENT_NAME_RE.test(name)) throw new Error("agent name: lowercase letters, digits, - and _ (max 40)");
      const repoDir = resolve(repo);
      if (!existsSync(repoDir)) throw new Error(`no such directory: ${repoDir}`);
      const supabase = flags.has("--supabase");
      const slack = flags.has("--slack");
      if (supabase && slack) throw new Error("choose one of --supabase or --slack");
      const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : {});

      let env;
      if (slack) {
        const channel = process.env.SLACK_CHANNEL_ID;
        if (!channel) throw new Error("--slack needs SLACK_CHANNEL_ID (the bridge channel's ID, like C0123ABCDEF) in your shell.");
        const tf = expandHome(flagValue("--token-file") || slackTokenPath(name));
        if (!existsSync(tf)) {
          throw new Error(`no Slack token file at ${tf}. Save this agent's bot token with "save-slack-token ${name}", then re-run init.`);
        }
        // The bot token stays out of the repo: .mcp.json only points at the token file.
        env = { AGENT_NAME: name, AGENT_BRIDGE_BACKEND: "slack", SLACK_CHANNEL_ID: channel, SLACK_BOT_TOKEN_FILE: tf };
        if (process.env.SLACK_API_URL) env.SLACK_API_URL = process.env.SLACK_API_URL;
      } else if (supabase) {
        const url = process.env.SUPABASE_URL;
        const key = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
        if (!url || !key) throw new Error("--supabase needs SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in your shell.");
        const tf = expandHome(flagValue("--token-file") || tokenPath(name));
        if (!existsSync(tf)) {
          throw new Error(
            `no token file at ${tf}. Get a token with "add-agent ${name} --save" (admin) ` +
              `or "save-token ${name}" (token from your admin), then re-run init.`
          );
        }
        // Secrets stay out of the repo: .mcp.json only points at the token file.
        env = {
          AGENT_NAME: name,
          AGENT_BRIDGE_BACKEND: "supabase",
          SUPABASE_URL: url,
          SUPABASE_PUBLISHABLE_KEY: key,
          AGENT_BRIDGE_TOKEN_FILE: tf,
        };
      } else {
        env = { AGENT_NAME: name, AGENT_BRIDGE_DB: resolveDbPath() };
      }

      const mcpPath = join(repoDir, ".mcp.json");
      refuseSymlink(mcpPath);
      if (flags.has("--hook")) {
        refuseSymlink(join(repoDir, ".claude"));
        refuseSymlink(join(repoDir, ".claude", "settings.local.json"));
      }
      const mcp = readJson(mcpPath);
      mcp.mcpServers ??= {};
      const prevDesc = mcp.mcpServers.bridge?.env?.AGENT_DESCRIPTION;
      if (descParts.length) env.AGENT_DESCRIPTION = descParts.join(" ");
      else if (prevDesc) env.AGENT_DESCRIPTION = prevDesc;
      mcp.mcpServers.bridge = { command: process.execPath, args: [join(HERE, "server.js")], env };
      writeFileSync(mcpPath, JSON.stringify(mcp, null, 2) + "\n");
      console.log(`wrote ${mcpPath}  (agent "${name}", ${slack ? "slack " + env.SLACK_CHANNEL_ID : supabase ? "supabase" : "local " + env.AGENT_BRIDGE_DB})`);

      if (flags.has("--hook")) {
        const settingsPath = join(repoDir, ".claude", "settings.local.json");
        mkdirSync(join(repoDir, ".claude"), { recursive: true });
        const settings = readJson(settingsPath);
        settings.hooks ??= {};
        settings.hooks.UserPromptSubmit ??= [];
        const envPrefix = Object.entries(env)
          .filter(([k]) => k !== "AGENT_DESCRIPTION")
          .map(([k, v]) => `${k}=${shq(v)}`)
          .join(" ");
        const command = `${envPrefix} ${shq(process.execPath)} ${shq(join(HERE, "cli.js"))} peek ${shq(name)}`;
        // Drop any earlier agent-bridge hook for this agent (quoted or not) so re-running init doesn't stack them.
        const ours = new RegExp(`cli\\.js["']?\\s+peek\\s+["']?${name}["']?(\\s|$)`);
        settings.hooks.UserPromptSubmit = settings.hooks.UserPromptSubmit.filter(
          (h) => !(h.hooks || []).some((x) => ours.test(String(x.command || "")))
        );
        settings.hooks.UserPromptSubmit.push({ hooks: [{ type: "command", command, timeout: 10 }] });
        writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
        console.log(`wrote ${settingsPath}  (unread-mail hook)`);
      }
      console.log(
        "next: restart Claude Code in that repo and approve the 'bridge' MCP server.\n" +
          "tip: .mcp.json now holds absolute paths for this machine; add it to .gitignore if you don't want to commit it."
      );
      break;
    }

    case "add-agent": {
      const [name, ...descParts] = args;
      if (!name || !AGENT_NAME_RE.test(name)) throw new Error("usage: add-agent <name> [desc] [--save]  (name: a-z 0-9 - _)");
      const token = await (await admin()).createAgent(name, descParts.join(" ") || null);
      if (flags.has("--save")) console.log(`registered "${name}"; token saved to ${saveToken(name, token)}`);
      else console.log(`registered "${name}". Token (shown once, give it only to that agent's machine):\n${token}`);
      break;
    }

    case "rotate-token": {
      const [name] = args;
      if (!name) throw new Error("usage: rotate-token <name> [--save]");
      const token = await (await admin()).rotateToken(name);
      if (flags.has("--save")) console.log(`new token for "${name}" saved to ${saveToken(name, token)}`);
      else console.log(`new token for "${name}" (old one no longer works):\n${token}`);
      break;
    }

    case "revoke-agent": {
      const [name] = args;
      if (!name) throw new Error("usage: revoke-agent <name>");
      await (await admin()).revokeAgent(name);
      console.log(`revoked "${name}"`);
      break;
    }

    case "delete-agent": {
      const [name] = args;
      if (!name) throw new Error("usage: delete-agent <name>");
      const n = await (await admin()).deleteAgent(name);
      console.log(`deleted "${name}" and ${n} message(s)`);
      break;
    }

    case "limits": {
      const num = (f) => (flagValue(f) == null ? null : Number(flagValue(f)));
      const mb = num("--max-mb-day");
      const out = await (await admin()).setLimits({
        ratePerMinute: num("--rate"),
        maxUnreadPerSender: num("--max-unread"),
        maxBytesPerDay: mb == null ? null : Math.round(mb * 1_000_000),
      });
      console.log(JSON.stringify(out, null, 2));
      break;
    }

    case "purge": {
      const days = Number(args[0] || 30);
      if (!(days >= 0)) throw new Error("usage: purge [days]");
      console.log(`deleted ${await (await admin()).purge(days)} message(s) older than ${days} day(s)`);
      break;
    }

    case "save-slack-token": {
      const [name] = args;
      if (!name || !AGENT_NAME_RE.test(name)) throw new Error("usage: save-slack-token <name>  (paste the bot token, then Enter)");
      let input = "";
      for await (const chunk of process.stdin) {
        input += chunk;
        if (input.includes("\n")) break;
      }
      const token = input.trim();
      if (!/^xoxb-[A-Za-z0-9-]{10,}$/.test(token)) throw new Error("that doesn't look like a Slack bot token (xoxb-...)");
      console.log(`saved to ${saveToken(name, token, slackTokenPath(name))}`);
      break;
    }

    case "slack-manifest": {
      // One Slack app per agent: the app's bot user is the agent's identity on the bridge.
      const [name, ...descParts] = args;
      if (!name || !AGENT_NAME_RE.test(name)) throw new Error('usage: slack-manifest <name> ["description"]');
      const manifest = {
        display_information: {
          name,
          description: (descParts.join(" ") || `agent-bridge agent "${name}"`).slice(0, 139),
        },
        features: { bot_user: { display_name: name, always_online: true } },
        oauth_config: {
          scopes: {
            // each scope is for a call stores/slack.js makes:
            bot: [
              "chat:write", // chat.postMessage
              "channels:history", // conversations.history (public channel)
              "groups:history", // conversations.history (private channel)
              "channels:read", // conversations.members (public)
              "groups:read", // conversations.members (private)
              "users:read", // users.info: who posted
              "reactions:write", // reactions.add/remove: claim a message
              "reactions:read", // reading claims
              "metadata.message:read", // message metadata in the channel
            ],
          },
        },
        settings: { org_deploy_enabled: false, socket_mode_enabled: false, token_rotation_enabled: false },
      };
      console.log(JSON.stringify(manifest, null, 2));
      break;
    }

    case "save-token": {
      const [name] = args;
      if (!name || !AGENT_NAME_RE.test(name)) throw new Error("usage: save-token <name>  (paste the token, then Enter)");
      let input = "";
      for await (const chunk of process.stdin) {
        input += chunk;
        if (input.includes("\n")) break;
      }
      const token = input.trim();
      if (!/^abt_[0-9a-f]{64}$/.test(token)) throw new Error("that doesn't look like an agent-bridge token (abt_...)");
      console.log(`saved to ${saveToken(name, token)}`);
      break;
    }

    default:
      console.log(HELP);
  }
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`error: ${e.message}`);
    process.exit(1);
  }
);
