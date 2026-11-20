#!/usr/bin/env node
// agent-bridge CLI: set up repos, watch traffic, and (Supabase) manage agents.
// Run with no arguments for help.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dlpNotice } from "./stores/dlp.js";
import { CA_VAR, maskProxyUrl, nodeSupportsEnvProxy, proxyEnvForConfig, proxyUrlHasCredentials } from "./proxy.js";
import { AGENT_NAME_RE, backendFromEnv, createStore, expandHome, readSecret, resolveDbPath, resolveIdentityEnv } from "./store.js";
import { CLIENTS, FileTx, PEEK_ENV_KEYS, PEEK_PROCESS_KEYS, PEEK_REEXEC_GUARD, isSecretSupabaseKey } from "./clients/common.js";
import * as claudeClient from "./clients/claude.js";
import * as cursorClient from "./clients/cursor.js";
import * as codexClient from "./clients/codex.js";
import { installSkill } from "./clients/skill.js";

const CLIENT_MODULES = { claude: claudeClient, cursor: cursorClient, codex: codexClient };

const HERE = fileURLToPath(new URL(".", import.meta.url));
const HELP = `agent-bridge CLI

Setup
  init <repo> <name> ["desc"] [--client claude|cursor|codex|all] [--hook] [--no-skill]
       [--supabase | --relay | --slack] [--token-file <path>]
                                  wire a repo to the bridge for each client (default claude): its MCP
                                  config, the agent-bridge skill, and with --hook the unread-mail hook
       --hook-form shell|exec     "shell": one POSIX shell command (default on macOS/Linux);
                                  "exec": command + args, no shell (default on Windows)
  managed-config [--node P] [--server P]
                                  print a managed-mcp.json entry for admins: one fixed launch command,
                                  settings in env, each project's agent named after its folder
Watching (local: all traffic; Supabase: traffic of the agent whose token you use)
  whoami | agents | log [n] | tail
  send <to> <text...>             send as AGENT_NAME (local, default "human") or as the token's agent
  peek [name] [--set K=V ...]     print an "unread mail" note if any (used by the hook; --set passes
                                  bridge settings without a shell, for exec-form hooks; proxy and CA
                                  settings (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, ...) make peek re-run itself once
                                  so Node starts with them)
Supabase admin (needs SUPABASE_URL + SUPABASE_SECRET_KEY)
  add-agent <name> ["desc"] [--save]   register an agent, print its token (--save: store it locally)
  rotate-token <name> [--save]         issue a new token (old one stops working)
  revoke-agent <name>                  disable an agent
  delete-agent <name>                  remove an agent and all its messages
  limits [--rate N] [--max-unread N] [--max-mb-day N]
                                       show or change the per-agent abuse limits
  purge [days=30]                      delete messages older than N days
  doctor [repo] [--probe] [--client C] diagnose the setup (this shell, or the repo's .mcp.json, .cursor/mcp.json
                                       or .codex/config.toml); exit 1 on FAIL.
                                       With a repo, the network check needs --probe (it sends the agent's token)
  save-token <name>                    read a token from stdin into ~/.agent-bridge/tokens/<name>.token
Relay admin: the same commands (add-agent ... purge) work against a self-hosted relay.js when
  RELAY_URL + RELAY_ADMIN_KEY (or RELAY_ADMIN_KEY_FILE) are set; "init <repo> <name> --relay" needs RELAY_URL.
  verify-audit <file>                  check a relay audit log's hash chain: prints OK or the first broken line
  export [--from ISO] [--to ISO]       auditor: print the relay's messages as JSON Lines
                                       (needs RELAY_URL + RELAY_AUDITOR_KEY or RELAY_AUDITOR_KEY_FILE)
Slack (needs SLACK_CHANNEL_ID)
  slack-manifest <name> ["desc"]       print a Slack app manifest for this agent (one app per agent)
  save-slack-token <name>              read the app's bot token (xoxb-...) from stdin, store it 0600
  init <repo> <name> --slack [--hook]  wire a repo to the Slack channel

Environment: AGENT_BRIDGE_DB (local), SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY,
AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE (Supabase, relay), RELAY_URL (relay), SLACK_CHANNEL_ID,
SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_FILE (Slack). See README.md.`;

const VALUE_FLAGS = new Set(["--token-file", "--rate", "--max-unread", "--max-mb-day", "--set", "--hook-form", "--from", "--to", "--node", "--server", "--client", "--format", "--event", "--cursor-events"]);
const BOOL_FLAGS = new Set(["--hook", "--no-skill", "--probe", "--relay", "--save", "--slack", "--supabase", "--check"]);
// --name=value is the same as --name value (R4-13): for a value flag, split it in two.
const argv = process.argv.slice(2).flatMap((a) => {
  const m = /^(--[a-z-]+)=(.*)$/s.exec(a);
  return m && VALUE_FLAGS.has(m[1]) ? [m[1], m[2]] : [a];
});
const flags = new Set(argv.filter((a) => a.startsWith("--")));
const flagValue = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const positional = argv.filter((a, i) => !a.startsWith("--") && !(i > 0 && VALUE_FLAGS.has(argv[i - 1])));
const [cmd, ...args] = positional;
// A misspelled or unknown flag is an error, not silently ignored (R4-13). peek is the exception: it runs as a
// hook and must never fail loudly, so it ignores what it doesn't know.
const unknownFlags = argv.filter((a, i) => a.startsWith("--") && !VALUE_FLAGS.has(a) && !BOOL_FLAGS.has(a) && !(i > 0 && VALUE_FLAGS.has(argv[i - 1])));

// Let stdout/stderr drain before process.exit(), which can cut off piped output on some platforms.
const flush = () => new Promise((r) => process.stdout.write("", () => process.stderr.write("", r)));

// --client claude|cursor|codex|all, repeatable or comma-separated. Default: claude.
function clientsFromFlags() {
  const vals = argv.flatMap((a, i) => (a === "--client" && i + 1 < argv.length ? argv[i + 1].split(",") : []));
  if (argv.includes("--client") && !vals.length) throw new Error("--client needs a value: claude, cursor, codex or all");
  const out = new Set();
  for (const v of vals.length ? vals : ["claude"]) {
    const c = v.trim().toLowerCase();
    if (c === "all") CLIENTS.forEach((x) => out.add(x));
    else if (CLIENTS.includes(c)) out.add(c);
    else throw new Error(`--client: unknown client "${v}" (use claude, cursor, codex or all)`);
  }
  return [...out];
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
  // A self-hosted relay speaks the same admin RPCs; its admin key goes where Supabase's secret key does.
  const relayKey = process.env.RELAY_URL ? readSecret(process.env, "RELAY_ADMIN_KEY") : null;
  if (relayKey) return new SupabaseAdmin({ url: process.env.RELAY_URL, secretKey: relayKey, label: "relay" });
  if (process.env.RELAY_URL && !process.env.SUPABASE_URL) {
    throw new Error("Admin commands on a relay need RELAY_ADMIN_KEY (or RELAY_ADMIN_KEY_FILE).");
  }
  return new SupabaseAdmin({
    url: process.env.SUPABASE_URL,
    secretKey: process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY,
  });
}

async function main() {
  if (cmd !== "peek" && unknownFlags.length) {
    throw new Error(`unknown option ${unknownFlags.join(", ")}. Run "cli.js" with no arguments for the list.`);
  }
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
      const notice = dlpNotice(m.dlp);
      if (notice) console.log(notice);
      break;
    }

    case "peek": {
      // Used as a Claude Code UserPromptSubmit hook: stdout is added to the agent's context.
      // Never fails loudly: a broken bridge must not block the user's prompt.
      // --format claude|cursor|codex picks what the client's hook runner expects (plain text or JSON);
      // --event names the hook event for clients whose output differs per event (Cursor).
      let format = flagValue("--format") || "claude";
      let event = flagValue("--event");
      const notes = [];
      // Cursor sends the hook's input as JSON on stdin. Read (bounded, never a terminal) when the format is Cursor's,
      // or when no format was given but Cursor's environment is present: Cursor also runs the Claude hook from
      // .claude/settings*.json, and answers to it must be JSON (see clients/cursor.js).
      let hookInput = null;
      let imported = false;
      if (format === "cursor" || (!flagValue("--format") && cursorClient.looksLikeCursorEnv(process.env))) {
        hookInput = await cursorClient.readHookInput();
        const ev = format === "cursor" ? null : cursorClient.detectCursorInput(hookInput);
        if (ev !== null) {
          format = "cursor";
          event = ev || undefined;
          imported = true;
        }
      }
      const emit = () => {
        const mod = CLIENT_MODULES[format];
        if (mod) process.stdout.write(mod.peekOutput(notes, { event, input: hookInput }));
      };
      try {
        // --set KEY=VALUE (exec-form hooks): the values init wrote into the local, uncommitted
        // .claude/settings.local.json. There is no shell in exec form, so nothing is expanded. Only
        // bridge variables are accepted. Config is never read from the repo's .mcp.json: that file
        // is often committed, and a hook runs on every prompt with no approval step, so a changed
        // .mcp.json could otherwise send this agent's token to another host.
        let env = process.env;
        const sets = argv.flatMap((a, i) => (a === "--set" && i + 1 < argv.length ? [argv[i + 1]] : []));
        const startup = {}; // proxy / CA settings: only effective if Node starts with them
        if (sets.length) {
          env = { ...process.env };
          for (const kv of sets) {
            const eq = kv.indexOf("=");
            const k = eq > 0 ? kv.slice(0, eq) : "";
            if (!PEEK_ENV_KEYS.has(k) && !PEEK_PROCESS_KEYS.has(k)) throw new Error(`peek --set: ${k || kv} is not a bridge setting`);
            env[k] = kv.slice(eq + 1);
            if (PEEK_PROCESS_KEYS.has(k)) startup[k] = env[k];
          }
        }
        if (Object.keys(startup).length && process.env[PEEK_REEXEC_GUARD] !== "1") {
          // Run again, once, with the settings in the child's real environment (R2-12). The guard stops a loop.
          // Cursor wants JSON on stdout whatever happens: the child's answer is passed on only if it is JSON.
          const asCursor = format === "cursor";
          const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...argv, ...(imported ? ["--format", "cursor", ...(event ? ["--event", event] : [])] : [])], {
            env: { ...process.env, ...startup, [PEEK_REEXEC_GUARD]: "1" },
            input: asCursor ? JSON.stringify(hookInput ?? {}) : undefined,
            stdio: [asCursor ? "pipe" : "ignore", asCursor ? "pipe" : "inherit", "inherit"],
            encoding: "utf8",
            timeout: 9000,
            windowsHide: true,
          });
          if (asCursor) {
            let ok = false;
            try {
              ok = typeof child.stdout === "string" && child.stdout.trim() !== "" && JSON.parse(child.stdout) !== null;
            } catch {}
            if (ok) process.stdout.write(child.stdout);
            else emit();
          }
          await flush();
          process.exit(0);
        }
        // As a Cursor hook, the project folder (for AGENT_BRIDGE_NAME_FROM=project) is the absolute workspace
        // folder Cursor names in the hook input, never an inherited CURSOR_PROJECT_DIR (R4-11).
        if (format === "cursor" && !env.AGENT_BRIDGE_PROJECT_DIR) {
          const ws = cursorClient.workspaceOf(hookInput, {});
          if (ws && isAbsolute(ws)) env = { ...env, AGENT_BRIDGE_PROJECT_DIR: ws };
        }
        // The agent's name: the argument, AGENT_NAME, or (AGENT_BRIDGE_NAME_FROM=project) the project folder's name.
        const agent = args[0] || resolveIdentityEnv(env).AGENT_NAME;
        if (backendFromEnv(env) === "sqlite" && !agent) return emit();
        // Short busy timeout: on SQLite the read is synchronous, so the race below can't cut it short (R1-08).
        const store = await createStore({ env, agentName: agent, busyTimeoutMs: 1500 });
        const summary = await Promise.race([
          store.unreadSummary(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 4000)),
        ]);
        if (summary.length) {
          const who = summary.map((s) => `${s.n} from ${s.from_agent}`).join(", ");
          notes.push(`[agent-bridge] You have unread bridge messages (${who}). Call check_inbox when relevant.`);
        }
        // Slack: an incomplete scan means "no unread mail" can't be trusted (R2-07).
        for (const w of store.scanWarnings?.() ?? []) notes.push(`[agent-bridge] WARNING: ${w}`);
        // A Claude hook that Cursor imported, in a repo that also has our native Cursor hook for this event: that hook reports.
        if (imported && cursorClient.hasNativeHook(cursorClient.workspaceOf(hookInput), agent, event)) notes.length = 0;
      } catch (e) {
        // stay silent so a broken bridge never blocks the prompt; AGENT_BRIDGE_DEBUG=1 shows why
        if (process.env.AGENT_BRIDGE_DEBUG) console.error(`agent-bridge peek: ${e.message}`);
      }
      emit();
      await flush();
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
      const relay = flags.has("--relay");
      if (supabase + slack + relay > 1) throw new Error("choose one of --supabase, --relay or --slack");

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
      } else if (relay) {
        const url = process.env.RELAY_URL;
        if (!url) throw new Error("--relay needs RELAY_URL (the relay's address, like https://bridge.internal:8787) in your shell.");
        const tf = expandHome(flagValue("--token-file") || tokenPath(name));
        if (!existsSync(tf)) {
          throw new Error(
            `no token file at ${tf}. Get a token with "add-agent ${name} --save" (admin) ` +
              `or "save-token ${name}" (token from your admin), then re-run init.`
          );
        }
        env = { AGENT_NAME: name, AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: url, AGENT_BRIDGE_TOKEN_FILE: tf };
        // a private CA / client certificate for the relay's TLS: file paths only, never key material
        for (const k of ["NODE_EXTRA_CA_CERTS", "RELAY_TLS_CA", "RELAY_TLS_CLIENT_CERT", "RELAY_TLS_CLIENT_KEY"]) {
          if (process.env[k]) env[k] = expandHome(process.env[k]);
        }
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
        // Secrets stay out of the repo: .mcp.json only points at the token file. The project's secret key gives
        // full access to the database and must never be written into a repo file (R4-03).
        if (isSecretSupabaseKey(key)) {
          throw new Error("SUPABASE_PUBLISHABLE_KEY holds a secret key (sb_secret_... or a service_role JWT); agents get the publishable key (sb_publishable_...). Nothing was written.");
        }
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

      // Claude Code runs shell-form hooks with sh (macOS/Linux) or Git Bash (Windows; PowerShell if Git Bash is
      // missing), and the POSIX single-quoted form is wrong for PowerShell. Windows therefore gets exec form.
      const hookForm = flagValue("--hook-form") || (process.platform === "win32" ? "exec" : "shell");
      if (!["shell", "exec"].includes(hookForm)) throw new Error('--hook-form must be "shell" or "exec"');

      // Corporate proxy / TLS inspection: the server only sees what is in .mcp.json, so carry the
      // shell's settings over, plus the switch that makes Node's fetch() use them. Only the
      // backends that make network calls need this.
      const proxyNotes = [];
      if (slack || supabase || relay) {
        const px = proxyEnvForConfig(process.env);
        // Claude Code starts the server from another directory: make the CA path absolute.
        if (px[CA_VAR]) px[CA_VAR] = resolve(expandHome(px[CA_VAR]));
        Object.assign(env, px);
        for (const [k, v] of Object.entries(px)) {
          proxyNotes.push(`  ${k}=${/^(https?)_proxy$/i.test(k) ? maskProxyUrl(v) : v}`);
        }
        if (px.NODE_USE_ENV_PROXY) {
          if (!nodeSupportsEnvProxy()) {
            proxyNotes.push(`  WARNING: this Node (${process.versions.node}) is too old for NODE_USE_ENV_PROXY (needs 22.21+ or 24+); upgrade Node.`);
          }
          if (Object.entries(px).some(([k, v]) => /^(https?)_proxy$/i.test(k) && proxyUrlHasCredentials(v))) {
            proxyNotes.push("  WARNING: a proxy URL contains credentials; they are now stored in plain text in the generated files. Keep them out of git.");
          }
        }
      }

      // Which coding tools to wire: --client claude|cursor|codex|all (repeatable or comma-separated); default claude.
      const clients = clientsFromFlags();
      const summary = slack ? "slack " + env.SLACK_CHANNEL_ID : relay ? "relay " + env.RELAY_URL : supabase ? "supabase" : "local " + env.AGENT_BRIDGE_DB;
      const notes = proxyNotes.length
        ? [`proxy/TLS settings from your shell were written to the server's env (and the hook):\n${proxyNotes.join("\n")}`]
        : [];
      // Keep a description an earlier init stored (in any client's file) when none is given now. Another tool's
      // file that can't be read or parsed just has no description (R4-05).
      if (descParts.length) env.AGENT_DESCRIPTION = descParts.join(" ");
      else {
        for (const c of CLIENTS) {
          // readServerEnv never throws: a file it can't read or parse comes back with `error` set
          const prev = CLIENT_MODULES[c].readServerEnv(repoDir)?.env?.AGENT_DESCRIPTION;
          if (typeof prev === "string" && prev) {
            env.AGENT_DESCRIPTION = prev;
            break;
          }
        }
      }
      // --cursor-events is validated before any client's files are written
      const cursorEvents = clients.includes("cursor") ? cursorClient.parseEvents(flagValue("--cursor-events")) : undefined;
      // Every tool's files (and skills) are planned first and written only if every step succeeded, so a refusal
      // for one tool leaves the repo exactly as it was (R4-01). The "wrote ..." lines are printed after the writes.
      const tx = new FileTx();
      const out = [];
      const log = (l) => out.push(l);
      for (const c of clients) {
        CLIENT_MODULES[c].writeConfig({ repoDir, name, env: { ...env }, withHook: flags.has("--hook"), hookForm, summary, notes, cursorEvents, tx, log });
        // The skill: plain instructions (when to message, how, safety rules), no paths or secrets, safe to commit.
        if (!flags.has("--no-skill")) {
          const r = installSkill(repoDir, c, tx);
          if (r) log(`wrote ${r.path}  (agent-bridge skill)` + (r.backup ? `\n  the SKILL.md that was there differed from this version; kept as ${r.backup}` : ""));
        }
      }
      tx.commit();
      for (const l of out) console.log(l);
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

    case "verify-audit": {
      const [file] = args;
      if (!file) throw new Error("usage: verify-audit <audit-log-file>");
      const { verifyAuditLog } = await import("./relay-audit.js");
      const r = verifyAuditLog(expandHome(file));
      if (!r.ok) {
        console.log(`BROKEN at line ${r.line}: ${r.reason}`);
        process.exit(1);
      }
      console.log(`OK (${r.lines} line(s); last hash ${r.last})`);
      break;
    }

    case "export": {
      const key = readSecret(process.env, "RELAY_AUDITOR_KEY");
      if (!process.env.RELAY_URL || !key) throw new Error("export needs RELAY_URL and RELAY_AUDITOR_KEY (or RELAY_AUDITOR_KEY_FILE).");
      const { SupabaseAdmin } = await import("./stores/supabase.js");
      const a = new SupabaseAdmin({ url: process.env.RELAY_URL, secretKey: key, label: "relay" });
      let after = 0;
      for (;;) {
        const rows = await a.store.rpc("bridge_admin_export", {
          p_from: flagValue("--from") ?? null,
          p_to: flagValue("--to") ?? null,
          p_after_id: after,
          p_limit: 1000,
        });
        for (const m of rows) console.log(JSON.stringify(m));
        if (rows.length < 1000) break;
        after = rows[rows.length - 1].id;
      }
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

    case "managed-config": {
      // A machine-wide Claude Code managed-mcp.json entry. The launch command is fixed (that is what the
      // allowlist compares); every setting is in env; each project gets its own agent name from its folder
      // (AGENT_BRIDGE_NAME_FROM=project) and its own token file through "{agent}". The managed file is
      // readable by every user on the machine, so no secret may ever be written into it.
      const backend = backendFromEnv(process.env);
      const env = { AGENT_BRIDGE_NAME_FROM: "project" };
      if (backend === "sqlite") {
        env.AGENT_BRIDGE_DB = process.env.AGENT_BRIDGE_DB || "~/.agent-bridge/bridge.db";
      } else if (backend === "supabase") {
        const key = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
        if (!process.env.SUPABASE_URL || !key) throw new Error("managed-config for Supabase needs SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY.");
        if (isSecretSupabaseKey(key)) throw new Error("SUPABASE_PUBLISHABLE_KEY holds a secret key; use the publishable key.");
        Object.assign(env, { AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: process.env.SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY: key });
        env.AGENT_BRIDGE_TOKEN_FILE = "~/.agent-bridge/tokens/{agent}.token";
      } else if (backend === "relay") {
        if (!process.env.RELAY_URL) throw new Error("managed-config for the relay needs RELAY_URL.");
        Object.assign(env, { AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: process.env.RELAY_URL });
        env.AGENT_BRIDGE_TOKEN_FILE = "~/.agent-bridge/tokens/{agent}.token";
        for (const k of ["RELAY_TLS_CA", "RELAY_TLS_CLIENT_CERT", "RELAY_TLS_CLIENT_KEY"]) {
          if (process.env[k]) env[k] = process.env[k].startsWith("~") ? process.env[k] : resolve(process.env[k]);
        }
      } else if (backend === "slack") {
        if (!process.env.SLACK_CHANNEL_ID) throw new Error("managed-config for Slack needs SLACK_CHANNEL_ID.");
        Object.assign(env, { AGENT_BRIDGE_BACKEND: "slack", SLACK_CHANNEL_ID: process.env.SLACK_CHANNEL_ID });
        env.SLACK_BOT_TOKEN_FILE = "~/.agent-bridge/tokens/{agent}.slack-token";
      }
      if (process.env.AGENT_BRIDGE_DLP) env.AGENT_BRIDGE_DLP = process.env.AGENT_BRIDGE_DLP;
      if (backend !== "sqlite") {
        const px = proxyEnvForConfig(process.env);
        if (Object.entries(px).some(([k, v]) => /^(https?)_proxy$/i.test(k) && proxyUrlHasCredentials(v))) {
          throw new Error(
            "a proxy URL contains credentials; the managed file is readable by every user, so they can't go in it. " +
              "Use a proxy that authenticates the machine, or set the proxy per user."
          );
        }
        if (px[CA_VAR]) px[CA_VAR] = resolve(expandHome(px[CA_VAR]));
        Object.assign(env, px);
      }
      const command = flagValue("--node") || process.execPath;
      const server = flagValue("--server") || join(HERE, "server.js");
      console.log(JSON.stringify({ mcpServers: { "agent-bridge": { command, args: [server], env } } }, null, 2));
      console.error(
        [
          "Save the JSON above as Claude Code's managed-mcp.json:",
          "  Linux:   /etc/claude-code/managed-mcp.json",
          "  macOS:   /Library/Application Support/ClaudeCode/managed-mcp.json",
          "  Windows: C:\\Program Files\\ClaudeCode\\managed-mcp.json",
          "If you use an allowlist in managed settings instead, allow exactly this command (env isn't compared):",
          `  ${JSON.stringify({ allowedMcpServers: [{ serverCommand: [command, server] }] })}`,
          "Each project's agent is named after its folder (or AGENT_NAME / CLAUDE_PROJECT_DIR).",
          backend === "sqlite"
            ? "Local backend: all projects of a user share the mailbox above."
            : `Each user needs a token file per project: ${env.AGENT_BRIDGE_TOKEN_FILE || env.SLACK_BOT_TOKEN_FILE} ({agent} = the folder name), mode 0600.`,
        ].join("\n")
      );
      break;
    }

    case "doctor": {
      const { diagnose, envFromRepo, render } = await import("./doctor.js");
      let env = process.env;
      let execArgv = process.execArgv;
      let where = "this shell's environment";
      let fromRepo = false;
      if (args[0]) {
        // --client picks which file to read; default: the first of .mcp.json, .cursor/mcp.json, .codex/config.toml.
        const r = await envFromRepo(args[0], process.env, { client: flagValue("--client") });
        env = r.env;
        execArgv = []; // the coding tool starts the server, not this process
        where = r.path;
        fromRepo = true;
        if (r.ignored.length) console.log(`note: ignored settings in ${r.path} that aren't bridge settings: ${r.ignored.join(", ")}`);
      }
      const checks = await diagnose(env, { execArgv, allowNetwork: !fromRepo || flags.has("--probe"), source: where, dbFromRepo: fromRepo });
      console.log(render(checks, env, `agent-bridge doctor (${where})`));
      process.exitCode = checks.some((c) => c.level === "fail") ? 1 : 0;
      break;
    }

    case "__probe": {
      // internal: run by doctor in a child process so proxy/CA variables apply like in the server
      const { probeBackend } = await import("./doctor.js");
      console.log(JSON.stringify(await probeBackend(process.env)));
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
  () => flush().then(() => process.exit(process.exitCode ?? 0)),
  (e) => {
    console.error(`error: ${e.message}`);
    flush().then(() => process.exit(1));
  }
);
