// Adversary round 3, client-side configuration: proxy credentials, managed installs, doctor, the relay
// client's TLS fetch. One or more tests per finding. See docs/adversary/round-03.md (R3-05, 06, 07, 10, 11, 17).
//   node test/regressions-r3-config.js      (needs openssl for the TLS-through-proxy tests)
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { relayLocalBackend } from "./backends.js";
import { startForwardProxy } from "./forward-proxy.js";
import { IS_WIN, SERVER, baseEnv, homeEnv, rmrf, runCli, runServerExpectExit, skip, summary, test } from "./harness.js";
import { agentNameFromDir, resolveIdentityEnv } from "../store.js";

const px = await import("../proxy.js");

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-r3cfg-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
let n = 0;
const dir = (label = "d", mode = 0o700) => {
  const d = join(tmp, `${label}${++n}`);
  mkdirSync(d, { recursive: true, mode });
  chmodSync(d, mode);
  return d;
};
const file = (path, content, mode = 0o600) => {
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
};
const listFiles = (d) => {
  const out = [];
  const walk = (p, rel) => {
    for (const e of readdirSync(p, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(join(p, e.name), r);
      else out.push(r);
    }
  };
  walk(d, "");
  return out.sort();
};
const TOKEN = "abt_" + "ab".repeat(32);
const tokensDir = join(HOME, ".agent-bridge", "tokens");
mkdirSync(tokensDir, { recursive: true, mode: 0o700 });
const tokenFile = (name = "web") => file(join(tokensDir, `${name}.token`), TOKEN + "\n");
const jwt = (payload) => ["e30", Buffer.from(JSON.stringify(payload)).toString("base64url"), "c2ln"].join(".");
const doctor = (env, args = []) => runCli(["doctor", ...args], { HOME, ...homeEnv(HOME), ...env });
const managed = (env) => runCli(["managed-config"], { ...homeEnv(HOME), ...env });
const has = (out, level, title) => new RegExp(`^  ${level}  ${title}`, "m").test(out);
const RELAY_ENV = { AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: "https://relay.corp.example:8787" };
const posixTest = (name, fn) => (IS_WIN ? skip(name, "POSIX-only (file modes)") : test(name, fn));

const procs = [];
try {
  // ------------------------------------------------------------------------------------------ R3-05
  console.log("\n=== R3-05: proxy credentials are masked everywhere and kept off command lines ===");

  await test("R3-05 maskProxyUrl: a password with @, a user-only (token) URL, no scheme, no credentials", async () => {
    assert.equal(px.maskProxyUrl("http://user:p@ss@proxy.corp:8080"), "http://user:***@proxy.corp:8080");
    assert.equal(px.maskProxyUrl("http://alice:s3cr3t@proxy.corp:8080"), "http://alice:***@proxy.corp:8080");
    const tokenOnly = px.maskProxyUrl("http://SECRETTOKEN123@proxy.corp:8080");
    assert.ok(!tokenOnly.includes("SECRETTOKEN123"), tokenOnly);
    assert.match(tokenOnly, /@proxy\.corp:8080$/);
    // not parseable as a URL with an authority: everything up to the last @ of the authority goes
    for (const bad of ["user:p@ss@proxy.corp:8080", "//tok:en@x@proxy.corp:8080", "http://u:p%40ss@@proxy:1"]) {
      const m = px.maskProxyUrl(bad);
      assert.ok(!/p@ss|ss@|en@x|tok:en|p%40ss/.test(m), `${bad} -> ${m}`);
    }
    assert.equal(px.maskProxyUrl("http://proxy.corp:8080"), "http://proxy.corp:8080");
    assert.equal(px.maskProxyUrl("http://proxy.corp:8080/path"), "http://proxy.corp:8080/path");
  });

  await test("R3-05 proxyUrlHasCredentials: any userinfo counts (user:pass, p@ss, token only), none does not", async () => {
    for (const v of ["http://user:p@ss@proxy:1", "http://TOKEN@proxy:1", "http://:pw@proxy:1", "http://a:b@proxy:1"]) {
      assert.equal(px.proxyUrlHasCredentials(v), true, v);
    }
    for (const v of ["http://proxy:1", "http://proxy:1/a@b", "http://proxy:1?x=a@b"]) assert.equal(px.proxyUrlHasCredentials(v), false, v);
  });

  const initRelay = async (extra, args = []) => {
    const repo = dir("repo");
    tokenFile("web");
    const r = await runCli(["init", repo, "web", "--relay", ...args], { ...homeEnv(HOME), RELAY_URL: "https://relay.corp.example:8787", ...extra });
    return { repo, ...r };
  };

  for (const secret of ["http://user:p@ss@proxy.corp:8080", "http://SECRETTOKEN123@proxy.corp:8080"]) {
    await test(`R3-05 init prints the proxy ${secret.includes("p@ss") ? "with an @ in the password" : "that is a bare token"} masked, and warns about plain text`, async () => {
      const r = await initRelay({ HTTPS_PROXY: secret });
      assert.equal(r.code, 0, r.err);
      assert.ok(!/p@ss|ss@proxy|SECRETTOKEN123/.test(r.out), r.out);
      assert.match(r.out, /HTTPS_PROXY=http:\/\/.*@proxy\.corp:8080/);
      assert.match(r.out, /stored in plain text/, r.out);
    });
  }

  await test("R3-05 doctor prints a proxy URL masked: password with @, and a token-only URL", async () => {
    for (const secret of ["http://user:p@ss@proxy.corp:8080", "http://SECRETTOKEN123@proxy.corp:8080"]) {
      const r = await doctor({ AGENT_BRIDGE_BACKEND: "sqlite", AGENT_NAME: "web", AGENT_BRIDGE_DB: join(dir("db"), "b.db"), HTTPS_PROXY: secret, NODE_USE_ENV_PROXY: "1" });
      const text = r.out + r.err;
      assert.match(text, /Proxy/);
      assert.ok(!/p@ss|ss@proxy|SECRETTOKEN123/.test(text), text);
    }
  });

  for (const form of ["exec", "shell"]) {
    await test(`R3-05 init --hook-form ${form}: a proxy credential never reaches the hook's command line (the server's env still has it)`, async () => {
      const r = await initRelay({ HTTPS_PROXY: "http://user:p@ss@proxy.corp:8080", HTTP_PROXY: "http://SECRETTOKEN123@proxy.corp:8080" }, ["--hook", "--hook-form", form]);
      assert.equal(r.code, 0, r.err);
      const settings = JSON.parse(readFileSync(join(r.repo, ".claude", "settings.local.json"), "utf8"));
      const hook = JSON.stringify(settings.hooks);
      assert.match(hook, /peek/);
      assert.ok(!/p@ss|SECRETTOKEN123|user:/.test(hook), hook);
      assert.match(hook, /NODE_USE_ENV_PROXY/, "the switch that needs no secret is still passed");
      const mcp = JSON.parse(readFileSync(join(r.repo, ".mcp.json"), "utf8"));
      assert.equal(mcp.mcpServers.bridge.env.HTTPS_PROXY, "http://user:p@ss@proxy.corp:8080", "the server still gets its proxy");
      assert.match(r.out, /hook's command line does not carry them/, "init says the hook doesn't carry the credential");
    });
  }

  await test("R3-05 a proxy without credentials is still carried on the hook's command line", async () => {
    const r = await initRelay({ HTTPS_PROXY: "http://proxy.corp:8080" }, ["--hook", "--hook-form", "exec"]);
    const settings = JSON.parse(readFileSync(join(r.repo, ".claude", "settings.local.json"), "utf8"));
    assert.match(JSON.stringify(settings.hooks), /HTTPS_PROXY=http:\/\/proxy\.corp:8080/);
  });

  await test("R3-05 peek's re-run does not repeat --set proxy values in the child's arguments", async () => {
    // a preload that records every node process's argv, so the second (re-exec'd) process can be inspected
    const log = join(dir("argv"), "argv.jsonl");
    const preload = file(join(dir("pre"), "log.cjs"), `require("fs").appendFileSync(${JSON.stringify(log)}, JSON.stringify({ guard: process.env.AGENT_BRIDGE_PEEK_REEXEC || "", argv: process.argv }) + "\\n");\n`);
    const db = join(dir("db"), "b.db");
    const r = await runCli(
      ["peek", "web", "--set", `AGENT_BRIDGE_DB=${db}`, "--set", "HTTPS_PROXY=http://SECRETTOKEN123@127.0.0.1:9", "--set", "NODE_USE_ENV_PROXY=1"],
      { HOME, ...homeEnv(HOME), NODE_OPTIONS: `--require ${preload}` }
    );
    assert.equal(r.code, 0, r.err);
    const rows = readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const child = rows.find((x) => x.guard === "1");
    assert.ok(child, "the re-run did not happen");
    assert.ok(!JSON.stringify(child.argv).includes("SECRETTOKEN123"), JSON.stringify(child.argv));
    assert.ok(JSON.stringify(child.argv).includes("AGENT_BRIDGE_DB"), "settings that are not startup settings still reach the child");
  });

  // ------------------------------------------------------------------------------------------ R3-06
  console.log("\n=== R3-06: a managed install's agent name must not be a lossy function of the folder ===");

  await test("R3-06 agentNameFromDir refuses folder names that are not already agent names (no normalising)", async () => {
    const lossy = [
      ".Billing!", "Billing!!", "billing.", "billing!!", ".billing", "_billing", "my app", "my.app", "\u212Afafka", "billing\u200b",
      "x".repeat(41), "___", "Bill\u0131ng",
    ];
    for (const d of lossy) assert.throws(() => agentNameFromDir(`/work/${d}`), /agent name|folder/i, JSON.stringify(d));
    assert.throws(() => agentNameFromDir("/"), /agent name|folder/i);
  });

  await test("R3-06 agentNameFromDir keeps valid names, folding only ASCII capitals", async () => {
    assert.equal(agentNameFromDir("/work/billing"), "billing");
    assert.equal(agentNameFromDir("/work/Billing"), "billing");
    assert.equal(agentNameFromDir("/work/My-App_2"), "my-app_2");
    assert.equal(agentNameFromDir("/work/" + "a".repeat(40)), "a".repeat(40));
    assert.equal(agentNameFromDir("/work/billing-"), "billing-");
  });

  await test("R3-06 with AGENT_BRIDGE_NAME_FROM=project an AGENT_NAME that differs from the folder is refused, one that matches is fine", async () => {
    const base = { AGENT_BRIDGE_NAME_FROM: "project" };
    assert.throws(() => resolveIdentityEnv({ ...base, AGENT_NAME: "billing" }, "/work/ledger"), /AGENT_NAME.*billing.*ledger/s);
    assert.throws(() => resolveIdentityEnv({ ...base, AGENT_NAME: "billing" }, "/work/.Billing!"));
    assert.equal(resolveIdentityEnv({ ...base, AGENT_NAME: "ledger" }, "/work/ledger").AGENT_NAME, "ledger");
    assert.equal(resolveIdentityEnv({ ...base, AGENT_NAME: " ledger " }, "/work/Ledger").AGENT_NAME, "ledger");
    // without NAME_FROM, AGENT_NAME is just the name
    assert.equal(resolveIdentityEnv({ AGENT_NAME: "anything" }, "/work/ledger").AGENT_NAME, "anything");
  });

  await test("R3-06 the token file chosen by {agent} follows the folder-derived name only", async () => {
    const env = { AGENT_BRIDGE_NAME_FROM: "project", AGENT_BRIDGE_TOKEN_FILE: "~/.agent-bridge/tokens/{agent}.token" };
    assert.equal(resolveIdentityEnv(env, "/work/Billing").AGENT_BRIDGE_TOKEN_FILE, "~/.agent-bridge/tokens/billing.token");
    assert.throws(() => resolveIdentityEnv(env, "/work/Billing!"));
    assert.throws(() => resolveIdentityEnv({ ...env, AGENT_NAME: "billing" }, "/work/ledger"));
  });

  await test("R3-06 a relative AGENT_BRIDGE_PROJECT_DIR / CLAUDE_PROJECT_DIR is refused", async () => {
    const base = { AGENT_BRIDGE_NAME_FROM: "project" };
    assert.throws(() => resolveIdentityEnv({ ...base, AGENT_BRIDGE_PROJECT_DIR: "billing" }, "/work/ledger"), /absolute/);
    assert.throws(() => resolveIdentityEnv({ ...base, CLAUDE_PROJECT_DIR: "../billing" }, "/work/ledger"), /absolute/);
    assert.equal(resolveIdentityEnv({ ...base, AGENT_BRIDGE_PROJECT_DIR: "/work/own" }, "/x").AGENT_NAME, "own");
  });

  await test("R3-06 through the real server: look-alike folders and an inherited AGENT_NAME do not start as 'billing'", async () => {
    const db = join(dir("db"), "b.db");
    const start = async (cwd, extra = {}) => {
      const client = new Client({ name: "r3-06", version: "0" });
      await client.connect(
        new StdioClientTransport({ command: process.execPath, args: [SERVER], env: { ...baseEnv(HOME), AGENT_BRIDGE_NAME_FROM: "project", AGENT_BRIDGE_DB: db, ...extra }, cwd })
      );
      const r = await client.callTool({ name: "whoami", arguments: {} });
      await client.close();
      return JSON.parse(r.content[0].text).agent;
    };
    for (const d of [".Billing!", "Billing!", "billing."]) {
      const f = dir(d.replace(/[^a-z]/gi, "") + "-parent");
      const folder = join(f, d);
      mkdirSync(folder);
      await assert.rejects(() => start(folder), `${d} must not start`);
    }
    const ledger = join(dir("p"), "ledger");
    mkdirSync(ledger);
    await assert.rejects(() => start(ledger, { AGENT_NAME: "billing" }), "an inherited AGENT_NAME must not take over");
    assert.equal(await start(ledger), "ledger");
    assert.equal(await start(ledger, { AGENT_NAME: "ledger" }), "ledger");
  });

  // ------------------------------------------------------------------------------------------ R3-07
  console.log("\n=== R3-07: no service_role key and no URL/proxy userinfo in managed files, doctor or init ===");

  const SUPA = { AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: "https://proj.supabase.co" };
  const SERVICE_ROLE = jwt({ role: "service_role", iss: "supabase" });
  const ANON = jwt({ role: "anon", iss: "supabase" });

  await test("R3-07 managed-config refuses a service_role JWT as the publishable key (and still takes anon, sb_publishable_)", async () => {
    const bad = await managed({ ...SUPA, SUPABASE_PUBLISHABLE_KEY: SERVICE_ROLE });
    assert.notEqual(bad.code, 0);
    assert.ok(!bad.out.includes(SERVICE_ROLE) && !bad.out.includes("service_role"), bad.out);
    assert.match(bad.err, /secret key/);
    const bad2 = await managed({ ...SUPA, SUPABASE_ANON_KEY: SERVICE_ROLE });
    assert.notEqual(bad2.code, 0);
    const bad3 = await managed({ ...SUPA, SUPABASE_PUBLISHABLE_KEY: "sb_secret_abc" });
    assert.notEqual(bad3.code, 0);
    for (const good of [ANON, "sb_publishable_abc"]) {
      const r = await managed({ ...SUPA, SUPABASE_PUBLISHABLE_KEY: good });
      assert.equal(r.code, 0, r.err);
      assert.equal(JSON.parse(r.out).mcpServers["agent-bridge"].env.SUPABASE_PUBLISHABLE_KEY, good);
    }
  });

  await test("R3-07 doctor flags a service_role JWT as a SECRET key (FAIL), takes anon", async () => {
    const env = { ...SUPA, AGENT_BRIDGE_TOKEN: TOKEN };
    const bad = await doctor({ ...env, SUPABASE_PUBLISHABLE_KEY: SERVICE_ROLE });
    assert.equal(bad.code, 1);
    assert.ok(has(bad.out, "FAIL", "SUPABASE_PUBLISHABLE_KEY"), bad.out);
    assert.match(bad.out, /SECRET key/);
    assert.ok(!has(bad.out, "OK  ", "Supabase publishable key"), bad.out);
    const good = await doctor({ ...env, SUPABASE_PUBLISHABLE_KEY: ANON });
    assert.ok(has(good.out, "OK  ", "Supabase publishable key"), good.out);
  });

  await test("R3-07 init --supabase refuses a service_role JWT and writes nothing", async () => {
    const repo = dir("repo");
    tokenFile("web");
    const r = await runCli(["init", repo, "web", "--supabase"], { ...homeEnv(HOME), SUPABASE_URL: "https://proj.supabase.co", SUPABASE_PUBLISHABLE_KEY: SERVICE_ROLE });
    assert.notEqual(r.code, 0);
    assert.deepEqual(listFiles(repo), []);
  });

  const USERINFO_URL = "https://admin:hunter2pw@relay.corp:8787";
  await test("R3-07 managed-config refuses userinfo in RELAY_URL / SUPABASE_URL / SLACK_API_URL and names the variable, never printing the password", async () => {
    const cases = [
      [{ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: USERINFO_URL }, "RELAY_URL"],
      [{ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: "https://tokenonly@relay.corp:8787" }, "RELAY_URL"],
      [{ ...SUPA, SUPABASE_URL: "https://admin:hunter2pw@proj.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_x" }, "SUPABASE_URL"],
      [{ AGENT_BRIDGE_BACKEND: "slack", SLACK_CHANNEL_ID: "C0BRIDGE01", SLACK_API_URL: "https://admin:hunter2pw@slack.corp/api" }, "SLACK_API_URL"],
    ];
    for (const [env, name] of cases) {
      const r = await managed(env);
      assert.notEqual(r.code, 0, name);
      assert.ok(!(r.out + r.err).includes("hunter2pw") && !r.out.includes("tokenonly"), `${name}: ${r.out}${r.err}`);
      assert.match(r.err, new RegExp(name));
      assert.match(r.err, /credentials|user name|userinfo/i);
    }
  });

  await test("R3-07 managed-config refuses a token-only proxy URL (userinfo without a password)", async () => {
    const r = await managed({ ...RELAY_ENV, HTTPS_PROXY: "http://PROXYTOKEN123@proxy:8080" });
    assert.notEqual(r.code, 0);
    assert.ok(!(r.out + r.err).includes("PROXYTOKEN123"), r.out + r.err);
    assert.match(r.err, /credentials/);
    const p = await managed({ ...RELAY_ENV, HTTPS_PROXY: "http://user:p@ss@proxy:8080" });
    assert.notEqual(p.code, 0);
    assert.ok(!(p.out + p.err).includes("p@ss"), p.out + p.err);
  });

  await test("R3-07 doctor: userinfo in RELAY_URL / SUPABASE_URL / SLACK_API_URL is a FAIL and the password is never printed", async () => {
    for (const env of [
      { AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: USERINFO_URL, AGENT_BRIDGE_TOKEN: TOKEN },
      { ...SUPA, SUPABASE_URL: "https://admin:hunter2pw@proj.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_x", AGENT_BRIDGE_TOKEN: TOKEN },
      { AGENT_BRIDGE_BACKEND: "slack", SLACK_CHANNEL_ID: "C0BRIDGE01", SLACK_API_URL: "https://admin:hunter2pw@slack.corp/api", SLACK_BOT_TOKEN: "xoxb-test-token" },
    ]) {
      const r = await doctor(env);
      assert.equal(r.code, 1, r.out);
      assert.ok(!(r.out + r.err).includes("hunter2pw"), r.out + r.err);
      assert.match(r.out, /FAIL  (RELAY_URL|SUPABASE_URL|SLACK_API_URL): .*(credentials|user name|userinfo)/i, r.out);
    }
  });

  await test("R3-07 init --relay / --supabase / --slack refuse userinfo in the URL and write nothing", async () => {
    for (const [flag, env] of [
      ["--relay", { RELAY_URL: USERINFO_URL }],
      ["--supabase", { SUPABASE_URL: "https://admin:hunter2pw@proj.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_x" }],
      ["--slack", { SLACK_CHANNEL_ID: "C0BRIDGE01", SLACK_API_URL: "https://admin:hunter2pw@slack.corp/api" }],
    ]) {
      const repo = dir("repo");
      tokenFile("web");
      file(join(tokensDir, "web.slack-token"), "xoxb-test-token\n");
      const r = await runCli(["init", repo, "web", flag], { ...homeEnv(HOME), ...env });
      assert.notEqual(r.code, 0, flag);
      assert.ok(!(r.out + r.err).includes("hunter2pw"), r.out + r.err);
      assert.deepEqual(listFiles(repo), [], flag);
    }
  });

  // ------------------------------------------------------------------------------------------ R3-10
  console.log("\n=== R3-10: doctor checks the relay backend ===");

  await test("R3-10 no token and a plain-http URL: FAIL on both, exit 1, no success line for the relay", async () => {
    const r = await doctor({ RELAY_URL: "http://relay.corp.example:8787", HTTPS_PROXY: "http://proxy:3128" });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /Backend: relay/);
    assert.match(r.out, /FAIL  RELAY_URL: .*https/s, r.out);
    assert.match(r.out, /FAIL  Agent token: neither AGENT_BRIDGE_TOKEN nor AGENT_BRIDGE_TOKEN_FILE is set/, r.out);
    assert.ok(has(r.out, "WARN", "Reachability"), "no probe while the configuration is broken");
  });

  await test("R3-10 RELAY_URL missing for AGENT_BRIDGE_BACKEND=relay is a FAIL", async () => {
    const r = await doctor({ AGENT_BRIDGE_BACKEND: "relay", AGENT_BRIDGE_TOKEN: TOKEN });
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL  RELAY_URL: not set/);
  });

  posixTest("R3-10 a world-readable token file is a FAIL, a malformed token is a FAIL, a good 0600 file is OK", async () => {
    const wide = file(join(dir("t"), "w.token"), TOKEN + "\n", 0o644);
    const a = await doctor({ ...RELAY_ENV, AGENT_BRIDGE_TOKEN_FILE: wide });
    assert.equal(a.code, 1);
    assert.ok(has(a.out, "FAIL", "Agent token file permissions"), a.out);
    const bad = file(join(dir("t"), "bad.token"), "not-a-token\n");
    const b = await doctor({ ...RELAY_ENV, AGENT_BRIDGE_TOKEN_FILE: bad });
    assert.equal(b.code, 1);
    assert.ok(has(b.out, "FAIL", "Agent token format"), b.out);
    const g = await doctor({ ...RELAY_ENV, AGENT_BRIDGE_TOKEN_FILE: tokenFile("good") });
    assert.ok(has(g.out, "OK  ", "Agent token file"), g.out);
    assert.ok(has(g.out, "FAIL", "Relay reachability") || has(g.out, "FAIL", "Relay"), "an unreachable relay.corp.example is a failure, not a pass: " + g.out);
  });

  await test("R3-10 RELAY_TLS_*: a missing file is a FAIL naming the variable and file, a bad PEM is a FAIL, a cert without its key is a FAIL, ~ is expanded", async () => {
    const t = tokenFile("tls");
    const env = { ...RELAY_ENV, AGENT_BRIDGE_TOKEN_FILE: t };
    const missing = await doctor({ ...env, RELAY_TLS_CA: join(tmp, "nope-ca.pem") });
    assert.equal(missing.code, 1);
    assert.match(missing.out, /FAIL  RELAY_TLS_CA: .*nope-ca\.pem/, missing.out);
    const junk = file(join(dir("t"), "junk.pem"), "hello");
    const j = await doctor({ ...env, RELAY_TLS_CA: junk });
    assert.match(j.out, /FAIL  RELAY_TLS_CA: .*PEM/, j.out);
    const cert = file(join(dir("t"), "c.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    const lone = await doctor({ ...env, RELAY_TLS_CLIENT_CERT: cert });
    assert.match(lone.out, /FAIL  RELAY_TLS_CLIENT_KEY: .*(together|also|needs)/i, lone.out);
    file(join(HOME, "home-ca.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    const tilde = await doctor({ ...env, RELAY_TLS_CA: "~/home-ca.pem" });
    assert.ok(has(tilde.out, "OK  ", "RELAY_TLS_CA"), tilde.out);
  });

  posixTest("R3-10 a group/world-readable RELAY_TLS_CLIENT_KEY is a FAIL", async () => {
    const t = tokenFile("tlsk");
    const d = dir("k");
    const cert = file(join(d, "c.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    const key = file(join(d, "k.pem"), "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n", 0o644);
    const r = await doctor({ ...RELAY_ENV, AGENT_BRIDGE_TOKEN_FILE: t, RELAY_TLS_CLIENT_CERT: cert, RELAY_TLS_CLIENT_KEY: key });
    assert.equal(r.code, 1);
    assert.ok(has(r.out, "FAIL", "RELAY_TLS_CLIENT_KEY"), r.out);
    assert.ok(r.out.includes(`chmod 600 ${key}`), r.out);
  });

  await test("R3-10 with a relay that is up: a good config passes (reachable, token accepted); a wrong token fails; a dead port fails", async () => {
    const b = await relayLocalBackend();
    procs.push(b);
    await b.addAgent("web");
    const tf = file(join(dir("t"), "ok.token"), b.tokens.web + "\n");
    const good = await doctor({ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: b.relay.url, AGENT_BRIDGE_TOKEN_FILE: tf });
    assert.equal(good.code, 0, good.out + good.err);
    assert.ok(has(good.out, "OK  ", "RELAY_URL"), good.out);
    assert.ok(has(good.out, "OK  ", "Relay reachable and token accepted"), good.out);
    assert.match(good.out, /bridge_whoami → agent "web"/);
    assert.ok(!(good.out + good.err).includes(b.tokens.web));
    const wrong = file(join(dir("t"), "wrong.token"), "abt_" + "cd".repeat(32) + "\n");
    const w = await doctor({ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: b.relay.url, AGENT_BRIDGE_TOKEN_FILE: wrong });
    assert.equal(w.code, 1, w.out);
    assert.match(w.out, /FAIL  Relay/);
    const named = await doctor({ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: b.relay.url, AGENT_BRIDGE_TOKEN_FILE: tf, AGENT_NAME: "other" });
    assert.equal(named.code, 1, named.out);
    assert.match(named.out, /FAIL  AGENT_NAME/);
    const dead = await new Promise((res) => {
      const s = net.createServer().listen(0, "127.0.0.1", () => {
        const p = s.address().port;
        s.close(() => res(p));
      });
    });
    const d = await doctor({ AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: `http://127.0.0.1:${dead}`, AGENT_BRIDGE_TOKEN_FILE: tf });
    assert.equal(d.code, 1, d.out);
    assert.match(d.out, /FAIL  Relay reachability/);
  });

  await test("R3-10 doctor <repo> does not send the token to the repo's relay without --probe", async () => {
    const repo = dir("repo");
    tokenFile("web");
    const i = await runCli(["init", repo, "web", "--relay"], { ...homeEnv(HOME), RELAY_URL: "https://relay.corp.example:8787" });
    assert.equal(i.code, 0, i.err);
    const r = await doctor({}, [repo]);
    assert.match(r.out, /WARN  Reachability: skipped/, r.out);
    assert.match(r.out, /--probe/);
    assert.ok(has(r.out, "OK  ", "RELAY_URL"), r.out);
  });

  // ------------------------------------------------------------------------------------------ R3-11 / R3-17
  console.log("\n=== R3-11, R3-17: the relay client's TLS fetch uses the proxy and expands ~ ===");
  let opensslOk = true;
  try {
    execFileSync("openssl", ["version"], { stdio: "pipe" });
  } catch {
    opensslOk = false;
  }
  const { tlsFetchFromEnv } = await import("../stores/tls-fetch.js");

  await test("R3-17 RELAY_TLS_* paths starting with ~ are expanded where they are read; the error names the variable and the file", async () => {
    const script = (env) =>
      `import { tlsFetchFromEnv } from ${JSON.stringify(new URL("../stores/tls-fetch.js", import.meta.url).href)};` +
      `try { const f = tlsFetchFromEnv(${JSON.stringify(env)}); console.log(typeof f); } catch (e) { console.log("ERR " + e.message); }`;
    const run = (env) => execFileSync(process.execPath, ["--input-type=module", "-e", script(env)], { env: { PATH: process.env.PATH, ...homeEnv(HOME) }, encoding: "utf8" }).trim();
    file(join(HOME, "ca-home.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    assert.equal(run({ RELAY_TLS_CA: "~/ca-home.pem" }), "function");
    const err = run({ RELAY_TLS_CA: "~/no-such-ca.pem" });
    assert.match(err, /^ERR /);
    assert.ok(err.includes("RELAY_TLS_CA") && err.includes(join(HOME, "no-such-ca.pem")), err);
    // An absolute path is reported as resolved (on Windows "/x" becomes "D:\\x").
    const err2 = run({ RELAY_TLS_CLIENT_KEY: "/definitely/not/here.key" });
    assert.ok(err2.includes("RELAY_TLS_CLIENT_KEY") && err2.includes(resolve("/definitely/not/here.key")), err2);
  });

  await test("R3-17 the server's startup error for an unreadable RELAY_TLS_* file names the variable and the path", async () => {
    const r = await runServerExpectExit({
      ...baseEnv(HOME), AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: "https://relay.corp.example:8787", AGENT_BRIDGE_TOKEN: TOKEN, AGENT_NAME: "web",
      RELAY_TLS_CA: "~/gone-ca.pem",
    });
    assert.notEqual(r.code, 0);
    assert.ok(r.stderr.includes("RELAY_TLS_CA") && r.stderr.includes(join(HOME, "gone-ca.pem")), r.stderr);
  });

  if (!opensslOk) {
    skip("R3-11 TLS fetch through a proxy", "openssl is not installed");
  } else {
    const pki = dir("pki");
    const openssl = (...a) => execFileSync("openssl", a, { cwd: pki, stdio: "pipe" });
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Test Relay CA",
      "-addext", "subjectAltName=DNS:relay-px.test", "-addext", "basicConstraints=CA:TRUE");
    const CA = join(pki, "ca.pem");
    const origin = https.createServer({ key: readFileSync(join(pki, "key.pem")), cert: readFileSync(CA) }, (req, res) => {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise((r) => origin.listen(0, "127.0.0.1", r));
    const port = origin.address().port;
    const URL_ = `https://relay-px.test:${port}/ping`;
    const proxy = await startForwardProxy();
    try {
      const NOTFOUND = (e) => /ENOTFOUND|EAI_AGAIN/.test(e.cause?.code || e.message);
      const REFUSED = (e) => /ECONNREFUSED/.test(e.cause?.code || e.message);
      const get = async (env) => {
        const f = tlsFetchFromEnv({ RELAY_TLS_CA: CA, ...env });
        const res = await f(URL_, { signal: AbortSignal.timeout(5000) });
        return { status: res.status, body: JSON.parse(await res.text()) };
      };

      await test("R3-11 with HTTPS_PROXY and NODE_USE_ENV_PROXY=1 the TLS fetch goes through the proxy (CONNECT), end to end TLS to the relay", async () => {
        proxy.reset();
        const r = await get({ HTTPS_PROXY: proxy.url, NODE_USE_ENV_PROXY: "1" });
        assert.equal(r.status, 200);
        assert.deepEqual(r.body, { ok: true, path: "/ping" });
        assert.ok(proxy.hits.some((h) => h.kind === "connect" && h.host === "relay-px.test" && h.port === port), JSON.stringify(proxy.hits));
      });

      await test("R3-11 lower-case https_proxy works too, and a client certificate is still presented through the tunnel", async () => {
        proxy.reset();
        const r = await get({ https_proxy: proxy.url, NODE_USE_ENV_PROXY: "1" });
        assert.equal(r.status, 200);
        assert.equal(proxy.hits.filter((h) => h.kind === "connect").length, 1);
      });

      await test("R3-11 without NODE_USE_ENV_PROXY the proxy is not used (same rule as fetch(); doctor says 'not active'): the name can't be resolved", async () => {
        proxy.reset();
        await assert.rejects(() => get({ HTTPS_PROXY: proxy.url }), NOTFOUND);
        assert.equal(proxy.count(), 0);
      });

      await test("R3-11 NO_PROXY exempts the relay's host (so the proxy-only name fails to resolve), and an unrelated NO_PROXY entry does not", async () => {
        proxy.reset();
        await assert.rejects(() => get({ HTTPS_PROXY: proxy.url, NODE_USE_ENV_PROXY: "1", NO_PROXY: "relay-px.test" }), NOTFOUND);
        assert.equal(proxy.count(), 0);
        await assert.rejects(() => get({ HTTPS_PROXY: proxy.url, NODE_USE_ENV_PROXY: "1", no_proxy: ".test" }), NOTFOUND);
        const r = await get({ HTTPS_PROXY: proxy.url, NODE_USE_ENV_PROXY: "1", NO_PROXY: "other.example,10.0.0.0" });
        assert.equal(r.status, 200);
        assert.ok(proxy.count() > 0);
      });

      await test("R3-11 proxy credentials in the URL become Proxy-Authorization (Basic); a refusing proxy is an error, not a hang", async () => {
        const seen = [];
        const tunnels = [];
        const auth = http.createServer((req, res) => res.writeHead(405).end());
        auth.on("connect", (req, socket) => {
          seen.push(req.headers["proxy-authorization"]);
          tunnels.push(socket);
          if (!req.headers["proxy-authorization"]) return socket.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
          const up = net.connect(port, "127.0.0.1", () => {
            socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            up.pipe(socket);
            socket.pipe(up);
          });
          up.on("error", () => socket.destroy());
          socket.on("error", () => up.destroy());
        });
        await new Promise((r) => auth.listen(0, "127.0.0.1", r));
        try {
          const base = `127.0.0.1:${auth.address().port}`;
          const r = await get({ HTTPS_PROXY: `http://user:p%40ss@${base}`, NODE_USE_ENV_PROXY: "1" });
          assert.equal(r.status, 200);
          assert.equal(seen.at(-1), "Basic " + Buffer.from("user:p@ss").toString("base64"));
          await assert.rejects(() => get({ HTTPS_PROXY: `http://${base}`, NODE_USE_ENV_PROXY: "1" }), /407|proxy/i);
        } finally {
          for (const t of tunnels) t.destroy();
          await new Promise((r) => (auth.closeAllConnections?.(), auth.close(r)));
        }
      });

      await test("R3-11 a proxy that is down is a connection error", async () => {
        const dead = await new Promise((res) => {
          const s = net.createServer().listen(0, "127.0.0.1", () => {
            const p = s.address().port;
            s.close(() => res(p));
          });
        });
        await assert.rejects(() => get({ HTTPS_PROXY: `http://127.0.0.1:${dead}`, NODE_USE_ENV_PROXY: "1" }), REFUSED);
      });
    } finally {
      await proxy.close();
      await new Promise((r) => (origin.closeAllConnections?.(), origin.close(r)));
    }
  }
} finally {
  for (const p of procs) await p.cleanup?.();
  rmrf(tmp);
}
process.exit(summary() ? 1 : 0);
