// `cli.js doctor`: good and broken setups on every backend, exit codes, fixes, and no secrets in the output.
//   node test/doctor.js
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import https from "node:https";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { slackLocalBackend, supabaseLocalBackend } from "./backends.js";
import { runCli, summary, test } from "./harness.js";

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-doctor-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
const dir = (n, mode = 0o700) => {
  const d = join(tmp, n);
  mkdirSync(d, { recursive: true, mode });
  chmodSync(d, mode);
  return d;
};
const file = (path, content, mode = 0o600) => {
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
};
// a port nothing listens on (fetch refuses a few well-known ports such as 1 outright)
const closedPort = () =>
  new Promise((res) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
const doctor = (env, args = []) => runCli(["doctor", ...args], { HOME, ...env });
const has = (out, level, title) => new RegExp(`^  ${level}  ${title}`, "m").test(out);
const fixOf = (out, title) => out.match(new RegExp(`^  (?:WARN|FAIL)  ${title}[^\\n]*\\n        fix: ([^\\n]*)`, "m"))?.[1];
const SQ = (name, extra = {}) => ({ AGENT_BRIDGE_BACKEND: "sqlite", AGENT_NAME: name, AGENT_BRIDGE_DB: join(dir("db-" + name), "bridge.db"), ...extra });

console.log("\n=== doctor: local (sqlite) ===");

await test("a good local setup: every line OK, exit 0, summary", async () => {
  const r = await doctor(SQ("alpha"));
  assert.equal(r.code, 0, r.out + r.err);
  for (const t of ["Node.js", "Backend: sqlite", "AGENT_NAME: alpha", "Mailbox open and writable", "DLP: block"]) assert.ok(has(r.out, "OK  ", t), `${t}\n${r.out}`);
  assert.match(r.out, /\n\d+ ok, 0 warning\(s\), 0 failure\(s\)/);
});

await test("AGENT_NAME missing or invalid is a FAIL with a fix, and the exit code is 1", async () => {
  const env = SQ("beta");
  delete env.AGENT_NAME;
  const r = await doctor(env);
  assert.equal(r.code, 1, r.out);
  assert.ok(has(r.out, "FAIL", "AGENT_NAME"), r.out);
  assert.match(fixOf(r.out, "AGENT_NAME"), /AGENT_NAME=<your-agent>/);
  const bad = await doctor({ ...env, AGENT_NAME: "Bad Name!" });
  assert.equal(bad.code, 1);
  assert.match(bad.out, /FAIL  AGENT_NAME: "Bad Name!" is invalid/);
});

await test("a mailbox path that can't exist (parent is a file) is a FAIL", async () => {
  const f = file(join(tmp, "iamafile"), "x");
  const r = await doctor({ ...SQ("gamma"), AGENT_BRIDGE_DB: join(f, "sub", "bridge.db") });
  assert.equal(r.code, 1, r.out);
  assert.ok(has(r.out, "FAIL", "Mailbox directory"), r.out);
  assert.match(r.out, /is not a directory/);
});

await test("a world-readable mailbox is a FAIL (chmod 600), a group-readable one a WARN, a private one OK", async () => {
  const env = SQ("delta");
  await doctor(env); // creates the mailbox
  chmodSync(env.AGENT_BRIDGE_DB, 0o644);
  const bad = await doctor(env);
  assert.equal(bad.code, 1, bad.out);
  assert.ok(has(bad.out, "FAIL", "Mailbox permissions"), bad.out);
  assert.equal(fixOf(bad.out, "Mailbox permissions"), `chmod 600 ${env.AGENT_BRIDGE_DB}`);
  chmodSync(env.AGENT_BRIDGE_DB, 0o640);
  const grp = await doctor(env);
  assert.equal(grp.code, 0, grp.out);
  assert.ok(has(grp.out, "WARN", "Mailbox permissions"), grp.out);
  chmodSync(env.AGENT_BRIDGE_DB, 0o600);
  const good = await doctor(env);
  assert.ok(has(good.out, "OK  ", "Mailbox permissions"), good.out);
});

await test("a world-accessible mailbox directory is a WARN", async () => {
  const d = dir("open-dir", 0o755);
  const r = await doctor({ ...SQ("eps"), AGENT_BRIDGE_DB: join(d, "bridge.db") });
  assert.ok(has(r.out, "WARN", "Mailbox directory permissions"), r.out);
  assert.equal(fixOf(r.out, "Mailbox directory permissions"), `chmod 700 ${d}`);
});

await test("DLP: block/redact OK, warn/off WARN, a typo FAIL", async () => {
  assert.ok(has((await doctor(SQ("p1", { AGENT_BRIDGE_DLP: "redact" }))).out, "OK  ", "DLP: redact"));
  for (const m of ["warn", "off"]) {
    const r = await doctor(SQ("p2", { AGENT_BRIDGE_DLP: m }));
    assert.equal(r.code, 0);
    assert.ok(has(r.out, "WARN", "DLP"), r.out);
    assert.match(fixOf(r.out, "DLP"), /AGENT_BRIDGE_DLP=block/);
  }
  const r = await doctor(SQ("p3", { AGENT_BRIDGE_DLP: "blok" }));
  assert.equal(r.code, 1);
  assert.match(r.out, /FAIL  DLP: AGENT_BRIDGE_DLP must be one of/);
});

await test("an unknown AGENT_BRIDGE_BACKEND is a FAIL", async () => {
  const r = await doctor({ AGENT_BRIDGE_BACKEND: "mysql", AGENT_NAME: "x" });
  assert.equal(r.code, 1);
  assert.match(r.out, /FAIL  Backend: AGENT_BRIDGE_BACKEND must be one of/);
});

await test("proxy: configured but not active is reported (OK for local, it makes no requests); active shows OK", async () => {
  const off = await doctor(SQ("q1", { HTTPS_PROXY: "http://alice:pa55w0rd-Zq@proxy.corp:8080" }));
  assert.match(off.out, /OK    Proxy not active: HTTPS_PROXY=http:\/\/alice:\*\*\*@proxy\.corp:8080/);
  assert.ok(!off.out.includes("pa55w0rd-Zq"), "proxy password printed");
  const on = await doctor(SQ("q2", { HTTPS_PROXY: "http://proxy.corp:8080", NODE_USE_ENV_PROXY: "1" }));
  assert.ok(has(on.out, "OK  ", "Proxy active"), on.out);
});

await test("CA bundle: a missing file is a FAIL, a PEM is OK, a non-PEM file is a FAIL; NODE_USE_SYSTEM_CA is checked against the Node version", async () => {
  const missing = await doctor(SQ("c1", { NODE_EXTRA_CA_CERTS: join(tmp, "nope.pem") }));
  assert.equal(missing.code, 1);
  assert.match(missing.out, /FAIL  Extra CA certificates: .*file not found/);
  const pem = file(join(tmp, "ok.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
  assert.ok(has((await doctor(SQ("c2", { NODE_EXTRA_CA_CERTS: pem }))).out, "OK  ", "Extra CA certificates"));
  const junk = file(join(tmp, "junk.pem"), "hello");
  assert.ok(has((await doctor(SQ("c3", { NODE_EXTRA_CA_CERTS: junk }))).out, "FAIL", "Extra CA certificates"));
  const sys = await doctor(SQ("c4", { NODE_USE_SYSTEM_CA: "1" }));
  assert.ok(has(sys.out, "OK  ", "System CA store"), sys.out); // this container runs Node >= 22.19
});

await test("doctor <repo> diagnoses what init wrote into .mcp.json, not the shell", async () => {
  const repo = dir("repo-local");
  const env = SQ("zeta");
  const i = await runCli(["init", repo, "zeta"], { HOME, AGENT_BRIDGE_DB: env.AGENT_BRIDGE_DB });
  assert.equal(i.code, 0, i.err);
  const r = await doctor({ HTTPS_PROXY: "http://proxy.corp:8080" }, [repo]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /\.mcp\.json\)/);
  assert.ok(has(r.out, "OK  ", "AGENT_NAME: zeta"), r.out);
  const none = await doctor({}, [dir("empty-repo")]);
  assert.equal(none.code, 1);
  assert.match(none.err, /no \.mcp\.json/);
});

// ---------------------------------------------------------------------------------- supabase

console.log("\n=== doctor: supabase (local stand-in) ===");
const sb = await supabaseLocalBackend();
const slack = await slackLocalBackend();
const pki = dir("pki");
let secure;
try {
  await sb.addAgent("frontend");
  const tokens = dir("tokens");
  const tokenFile = (name = "frontend", mode = 0o600, token = sb.tokens.frontend) => file(join(tokens, `${name}-${mode.toString(8)}.token`), token + "\n", mode);
  const SB = (extra = {}) => ({
    AGENT_BRIDGE_BACKEND: "supabase",
    SUPABASE_URL: sb.url,
    SUPABASE_PUBLISHABLE_KEY: sb.publishable,
    AGENT_BRIDGE_TOKEN_FILE: tokenFile(),
    ...extra,
  });
  const noSecret = (r, secret) => assert.ok(!(r.out + r.err).includes(secret), `the output contains ${secret.slice(0, 8)}…`);

  await test("good Supabase config: reachability and auth OK (bridge_whoami), exit 0, token masked", async () => {
    const r = await doctor(SB());
    assert.equal(r.code, 0, r.out + r.err);
    assert.ok(has(r.out, "OK  ", "Supabase reachable and token accepted"), r.out);
    assert.match(r.out, /bridge_whoami → agent "frontend"/);
    assert.ok(has(r.out, "OK  ", "SUPABASE_URL"));
    assert.ok(has(r.out, "OK  ", "Agent token file"), r.out);
    assert.ok(r.out.includes(`${sb.tokens.frontend.slice(0, 6)}…`), "token should appear masked (first 6 chars + …)");
    noSecret(r, sb.tokens.frontend);
  });

  await test("token file permissions: world-readable FAIL (chmod 600), group-readable WARN, missing FAIL", async () => {
    const wide = tokenFile("frontend", 0o644);
    const r = await doctor(SB({ AGENT_BRIDGE_TOKEN_FILE: wide }));
    assert.equal(r.code, 1, r.out);
    assert.ok(has(r.out, "FAIL", "Agent token file permissions"), r.out);
    assert.equal(fixOf(r.out, "Agent token file permissions"), `chmod 600 ${wide}`);
    noSecret(r, sb.tokens.frontend);
    const grp = await doctor(SB({ AGENT_BRIDGE_TOKEN_FILE: tokenFile("frontend", 0o640) }));
    assert.equal(grp.code, 0, grp.out);
    assert.ok(has(grp.out, "WARN", "Agent token file permissions"), grp.out);
    const gone = await doctor(SB({ AGENT_BRIDGE_TOKEN_FILE: join(tokens, "missing.token") }));
    assert.equal(gone.code, 1);
    assert.match(gone.out, /FAIL  Agent token file: .*does not exist/);
    assert.ok(has(gone.out, "WARN", "Reachability"), "no probe without a token");
  });

  await test("no token at all, or a token set inline", async () => {
    const env = SB();
    delete env.AGENT_BRIDGE_TOKEN_FILE;
    const none = await doctor(env);
    assert.equal(none.code, 1);
    assert.match(none.out, /FAIL  Agent token: neither AGENT_BRIDGE_TOKEN nor AGENT_BRIDGE_TOKEN_FILE is set/);
    const inline = await doctor({ ...env, AGENT_BRIDGE_TOKEN: sb.tokens.frontend });
    assert.equal(inline.code, 0, inline.out);
    assert.ok(has(inline.out, "WARN", "Agent token"), inline.out);
    assert.match(fixOf(inline.out, "Agent token"), /AGENT_BRIDGE_TOKEN_FILE/);
    noSecret(inline, sb.tokens.frontend);
  });

  await test("a token the server rejects is a FAIL with a fix, the token masked", async () => {
    const bad = "abt_" + "0".repeat(64);
    const r = await doctor(SB({ AGENT_BRIDGE_TOKEN_FILE: tokenFile("bad", 0o600, bad) }));
    assert.equal(r.code, 1, r.out);
    assert.ok(has(r.out, "FAIL", "Supabase agent token"), r.out);
    assert.match(fixOf(r.out, "Supabase agent token"), /rotate-token|save-token/);
    noSecret(r, bad);
  });

  await test("a wrong publishable key, an unreachable URL, a name mismatch, a secret key in an agent's env", async () => {
    const key = await doctor(SB({ SUPABASE_PUBLISHABLE_KEY: "sb_publishable_wrong" }));
    assert.equal(key.code, 1);
    assert.ok(has(key.out, "FAIL", "Supabase API key"), key.out);
    const down = await doctor(SB({ SUPABASE_URL: `http://127.0.0.1:${await closedPort()}` }));
    assert.equal(down.code, 1);
    assert.ok(has(down.out, "FAIL", "Supabase reachability"), down.out);
    assert.match(down.out, /connection refused/);
    const name = await doctor(SB({ AGENT_NAME: "somebody-else" }));
    assert.equal(name.code, 1);
    assert.match(name.out, /FAIL  AGENT_NAME: .*token belongs to "frontend"/);
    const secret = await doctor(SB({ SUPABASE_PUBLISHABLE_KEY: "sb_secret_" + "k".repeat(24) }));
    assert.equal(secret.code, 1);
    assert.match(secret.out, /FAIL  SUPABASE_PUBLISHABLE_KEY: holds a SECRET key \(sb_sec…\)/);
    assert.ok(!secret.out.includes("k".repeat(24)));
    const admin = await doctor(SB({ SUPABASE_SECRET_KEY: sb.secret }));
    assert.ok(has(admin.out, "WARN", "Admin secret key in this environment"), admin.out);
  });

  await test("a plain-http URL to a real host is a FAIL before any request is made", async () => {
    const r = await doctor(SB({ SUPABASE_URL: "http://db.example.com" }));
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL  SUPABASE_URL: SUPABASE_URL must start with https:\/\//);
    assert.ok(has(r.out, "WARN", "Reachability"), r.out);
    const missing = await doctor({ AGENT_BRIDGE_BACKEND: "supabase" });
    assert.equal(missing.code, 1);
    for (const v of ["SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY"]) assert.ok(has(missing.out, "FAIL", v), v);
  });

  await test("proxy configured but not active on a network backend is a WARN naming the fix (the process still starts)", async () => {
    const r = await doctor(SB({ HTTPS_PROXY: "http://proxy.corp:8080", NO_PROXY: "127.0.0.1" }));
    assert.equal(r.code, 0, r.out);
    assert.ok(has(r.out, "WARN", "Proxy not active"), r.out);
    assert.match(fixOf(r.out, "Proxy not active"), /NODE_USE_ENV_PROXY=1/);
    const on = await doctor(SB({ HTTPS_PROXY: "http://proxy.corp:8080", NO_PROXY: "127.0.0.1", NODE_USE_ENV_PROXY: "1" }));
    assert.equal(on.code, 0, on.out);
    assert.ok(has(on.out, "OK  ", "Proxy active"), on.out);
    assert.ok(has(on.out, "OK  ", "Supabase reachable"), "probe honours NO_PROXY");
  });

  await test("a dead proxy makes the probe fail with a proxy-aware message", async () => {
    const dead = `http://127.0.0.1:${await closedPort()}`;
    const r = await doctor(SB({ HTTP_PROXY: dead, HTTPS_PROXY: dead, NODE_USE_ENV_PROXY: "1" }));
    assert.equal(r.code, 1, r.out);
    assert.ok(has(r.out, "FAIL", "Supabase reachability"), r.out);
  });

  await test("TLS inspection: an untrusted company CA is diagnosed with the NODE_EXTRA_CA_CERTS fix; with the CA it passes", async () => {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Corp Root", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=CA:TRUE"], { cwd: pki, stdio: "pipe" });
    secure = https.createServer({ key: readFileSync(join(pki, "key.pem")), cert: readFileSync(join(pki, "ca.pem")) }, (req, res) => {
      req.resume();
      if (req.url.endsWith("bridge_whoami")) res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ agent: "frontend", unread: 0 }));
      else res.writeHead(204).end();
    });
    await new Promise((r) => secure.listen(0, "127.0.0.1", r));
    const url = `https://localhost:${secure.address().port}`;
    const bad = await doctor(SB({ SUPABASE_URL: url }));
    assert.equal(bad.code, 1, bad.out);
    assert.ok(has(bad.out, "FAIL", "Supabase reachability"), bad.out);
    assert.match(bad.out, /TLS certificate isn't trusted/);
    assert.match(fixOf(bad.out, "Supabase reachability"), /NODE_EXTRA_CA_CERTS=.*Never disable TLS verification/);
    const good = await doctor(SB({ SUPABASE_URL: url, NODE_EXTRA_CA_CERTS: join(pki, "ca.pem") }));
    assert.equal(good.code, 0, good.out);
    assert.ok(has(good.out, "OK  ", "Supabase reachable"), good.out);
  });

  // ---------------------------------------------------------------------------------- slack

  console.log("\n=== doctor: slack (local stand-in) ===");
  const bot = slack.slack.addUser({ name: "frontend" });
  slack.tokens.frontend = bot.token;
  const outsider = slack.slack.addUser({ name: "stranger", member: false });
  const stokens = dir("slack-tokens");
  const sfile = (token, mode = 0o600, name = "t") => file(join(stokens, `${name}-${mode.toString(8)}`), token + "\n", mode);
  const SL = (extra = {}) => ({
    AGENT_BRIDGE_BACKEND: "slack",
    SLACK_API_URL: slack.slack.url,
    SLACK_CHANNEL_ID: slack.slack.channel.id,
    SLACK_BOT_TOKEN_FILE: sfile(bot.token),
    ...extra,
  });

  await test("good Slack config: auth.test and channel membership OK, exit 0, token masked", async () => {
    const r = await doctor(SL());
    assert.equal(r.code, 0, r.out + r.err);
    assert.ok(has(r.out, "OK  ", "Slack auth.test"), r.out);
    assert.match(r.out, /bot "frontend" \(UB\d+\) is authenticated/);
    assert.ok(has(r.out, "OK  ", "Slack channel"), r.out);
    assert.ok(r.out.includes(`${bot.token.slice(0, 6)}…`), r.out);
    noSecret(r, bot.token);
  });

  await test("an invalid Slack token is a FAIL at auth.test; the token never printed", async () => {
    const wrong = "xoxb-9999999999-revoked-token-value";
    const r = await doctor(SL({ SLACK_BOT_TOKEN_FILE: sfile(wrong, 0o600, "wrong") }));
    assert.equal(r.code, 1, r.out);
    assert.ok(has(r.out, "FAIL", "Slack bot token"), r.out);
    assert.match(fixOf(r.out, "Slack bot token"), /save-slack-token/);
    noSecret(r, wrong);
  });

  await test("a bot that isn't in the channel, and a wrong channel id, are FAILs that say what to do", async () => {
    const notIn = await doctor(SL({ SLACK_BOT_TOKEN_FILE: sfile(outsider.token, 0o600, "out") }));
    assert.equal(notIn.code, 1, notIn.out);
    assert.ok(has(notIn.out, "OK  ", "Slack auth.test"), "auth itself works");
    assert.ok(has(notIn.out, "FAIL", "Slack channel membership"), notIn.out);
    assert.match(fixOf(notIn.out, "Slack channel membership"), /Invite the bot/);
    const wrong = await doctor(SL({ SLACK_CHANNEL_ID: "C0WRONG0000" }));
    assert.equal(wrong.code, 1);
    assert.ok(has(wrong.out, "FAIL", "Slack channel membership"), wrong.out);
  });

  await test("Slack token file permissions, missing channel id, plain-http API URL, unreachable API", async () => {
    const wide = sfile(bot.token, 0o666, "wide");
    const w = await doctor(SL({ SLACK_BOT_TOKEN_FILE: wide }));
    assert.equal(w.code, 1);
    assert.ok(has(w.out, "FAIL", "Slack token file permissions"), w.out);
    assert.equal(fixOf(w.out, "Slack token file permissions"), `chmod 600 ${wide}`);
    noSecret(w, bot.token);
    const env = SL();
    delete env.SLACK_CHANNEL_ID;
    const nochan = await doctor(env);
    assert.equal(nochan.code, 1);
    assert.ok(has(nochan.out, "FAIL", "SLACK_CHANNEL_ID"), nochan.out);
    const http = await doctor(SL({ SLACK_API_URL: "http://slack.example.com/api" }));
    assert.equal(http.code, 1);
    assert.match(http.out, /FAIL  SLACK_API_URL: SLACK_API_URL must start with https:\/\//);
    const down = await doctor(SL({ SLACK_API_URL: `http://127.0.0.1:${await closedPort()}/api` }));
    assert.equal(down.code, 1);
    assert.ok(has(down.out, "FAIL", "Slack auth.test"), down.out);
    assert.match(down.out, /connection refused/);
  });

  await test("a token pasted into the config (inline) is a WARN; a malformed one is a FAIL about its format (it would never be sent)", async () => {
    const env = SL();
    delete env.SLACK_BOT_TOKEN_FILE;
    const r = await doctor({ ...env, SLACK_BOT_TOKEN: bot.token });
    assert.equal(r.code, 0, r.out);
    assert.ok(has(r.out, "WARN", "Slack token"), r.out);
    noSecret(r, bot.token);
    const odd = await doctor(SL({ SLACK_BOT_TOKEN_FILE: sfile("not-a-slack-token-123456", 0o600, "odd") }));
    assert.ok(has(odd.out, "FAIL", "Slack token format"), odd.out); // the server would refuse it (R2-11)
    assert.equal(odd.code, 1);
  });
} finally {
  if (secure) await new Promise((r) => (secure.closeAllConnections?.(), secure.close(r)));
  await sb.cleanup();
  await slack.cleanup();
  rmSync(tmp, { recursive: true, force: true });
}

process.exit(summary() ? 1 : 0);
