// Corporate proxy / TLS inspection / transport-security suite.
//   node test/proxy.js
//
// Node's fetch() only uses HTTP(S)_PROXY when the process starts with NODE_USE_ENV_PROXY=1, and
// reads the variables once, at startup. So every scenario starts a real server process with an
// explicit environment (the harness strips this machine's own proxy variables first).
//
// The forward proxy below is a real one: it speaks absolute-URI HTTP and CONNECT, and it
// RESOLVES NAMES ITSELF, like a corporate proxy does. Every ".test" host name maps to 127.0.0.1
// inside the proxy and nowhere else, so a request for "http://bridge-slack.test:PORT" can only
// succeed if it went through the proxy (a direct attempt fails with ENOTFOUND). That makes the
// results unambiguous even though Node proxies loopback addresses like any other address
// (it does: only NO_PROXY exempts them; a test below shows both).
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { slackLocalBackend, supabaseLocalBackend } from "./backends.js";
import { cleanEnv, connectAgent, runCli, runServerExpectExit, summary, test } from "./harness.js";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const px = await import("../proxy.js").catch(() => null);
const common = await import("../stores/common.js");

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-proxy-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);

// ---------------------------------------------------------------------------------- forward proxy

// `inspect` maps a host name to the local port of the plain-HTTP stand-in behind it: for those hosts
// the proxy terminates TLS itself with its own certificate, like a TLS-inspecting corporate proxy.
function startForwardProxy({ inspect = new Map(), key, cert } = {}) {
  const hits = []; // { kind: "http" | "connect", host, port }
  const target = (host) => (host.endsWith(".test") || host === "127.0.0.1" || host === "localhost" ? "127.0.0.1" : null);
  const server = http.createServer((req, res) => {
    // absolute-URI request: http://host:port/path
    let u;
    try {
      u = new URL(req.url);
    } catch {
      return res.writeHead(400).end();
    }
    hits.push({ kind: "http", host: u.hostname, port: Number(u.port) || 80 });
    const to = target(u.hostname);
    if (!to) return res.writeHead(502).end("proxy: unknown host");
    const out = http.request({ host: to, port: u.port || 80, path: u.pathname + u.search, method: req.method, headers: { ...req.headers, host: u.host } }, (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    });
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  });
  server.on("connect", (req, socket, head) => {
    const [host, port] = req.url.split(":");
    hits.push({ kind: "connect", host, port: Number(port) });
    const to = target(host);
    if (!to) return socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    if (inspect.has(host)) {
      const inner = net.connect(inspect.get(host), "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const clear = new tls.TLSSocket(socket, { isServer: true, key, cert });
        // keep-alive reuses one tunnel for many requests: count the requests inside it
        clear.on("data", (d) => {
          for (const _ of String(d).matchAll(/^(?:GET|POST|PUT|DELETE|PATCH) \S+ HTTP\/1\.1/gm)) hits.push({ kind: "request", host, port: Number(port) });
        });
        clear.pipe(inner);
        inner.pipe(clear);
        clear.on("error", () => inner.destroy());
      });
      inner.on("error", () => socket.destroy());
      socket.on("error", () => inner.destroy());
      return;
    }
    const up = net.connect(Number(port), to, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    up.on("error", () => socket.destroy());
    socket.on("error", () => up.destroy());
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        hits,
        count: (host) => hits.filter((h) => !host || h.host === host).length,
        requests: (host) => hits.filter((h) => h.kind === "request" && h.host === host).length,
        reset: () => (hits.length = 0),
        close: () => new Promise((r) => (server.closeAllConnections?.(), server.close(r))),
      })
    )
  );
}

const portOf = (url) => new URL(url).port;
const who = async (a) => JSON.parse((await a.call("whoami")).text);

// ---------------------------------------------------------------------------------- unit

console.log("\n=== proxy: detection ===");

await test("Node version support: env proxy from 22.21 and 24.0 (not 23.x, not 22.20)", async () => {
  assert.ok(px, "proxy.js does not exist");
  for (const [v, ok] of [["22.13.0", false], ["22.20.9", false], ["22.21.0", true], ["22.23.5", true], ["23.11.0", false], ["24.0.0", true], ["24.5.0", true], ["26.0.0", true]]) {
    assert.equal(px.nodeSupportsEnvProxy(v), ok, v);
  }
  for (const [v, ok] of [["22.18.0", false], ["22.19.0", true], ["24.5.0", false], ["24.6.0", true], ["25.0.0", true]]) {
    assert.equal(px.nodeSupportsSystemCa(v), ok, `system CA ${v}`);
  }
});

await test("proxyStatus: configured needs a proxy URL; active needs the switch AND a new enough Node", async () => {
  const S = (env, version = "22.23.5", execArgv = []) => px.proxyStatus({ env, execArgv, version });
  assert.deepEqual(S({}), { configured: false, active: false, supported: true, requested: false });
  assert.equal(S({ NO_PROXY: "x", NODE_USE_ENV_PROXY: "1" }).configured, false, "NO_PROXY alone is not a proxy");
  assert.equal(S({ HTTPS_PROXY: "http://p:1" }).configured, true);
  assert.equal(S({ http_proxy: "http://p:1" }).configured, true, "lower case");
  assert.equal(S({ HTTPS_PROXY: "http://p:1" }).active, false);
  assert.equal(S({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "1" }).active, true);
  assert.equal(S({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "0" }).active, false);
  assert.equal(S({ HTTPS_PROXY: "http://p:1" }, "22.23.5", ["--use-env-proxy"]).active, true);
  assert.equal(S({ HTTPS_PROXY: "http://p:1", NODE_OPTIONS: "--use-openssl-ca --use-env-proxy" }).active, true);
  const old = S({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "1" }, "22.20.0");
  assert.equal(old.active, false, "the switch does nothing on a Node without support");
  assert.equal(old.supported, false);
});

await test("proxyWarning: silent unless a proxy is configured but unused; says what to do, or that Node is too old", async () => {
  const W = (env, version) => px.proxyWarning(px.proxyStatus({ env, execArgv: [], version }));
  assert.equal(W({}, "22.23.5"), null);
  assert.equal(W({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "1" }, "22.23.5"), null);
  assert.match(W({ HTTPS_PROXY: "http://p:1" }, "22.23.5"), /NODE_USE_ENV_PROXY=1.*\.mcp\.json|--use-env-proxy/);
  assert.match(W({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "1" }, "22.20.0"), /too old.*22\.21.*24/);
  assert.match(W({ HTTPS_PROXY: "http://p:1" }, "20.11.0"), /too old/);
});

await test("proxy credentials are masked for display", async () => {
  assert.equal(px.maskProxyUrl("http://alice:s3cr3t@proxy.corp:8080"), "http://alice:***@proxy.corp:8080");
  assert.equal(px.maskProxyUrl("http://proxy.corp:8080"), "http://proxy.corp:8080");
  assert.equal(px.proxyUrlHasCredentials("http://alice:s3cr3t@proxy.corp:8080"), true);
  assert.equal(px.proxyUrlHasCredentials("http://proxy.corp:8080"), false);
});

// ---------------------------------------------------------------------------------- through a proxy

console.log("\n=== proxy: the server through a forward proxy (TLS-inspecting, company CA) ===");
const pki = join(tmp, "pki");
mkdirSync(pki);
const openssl = (...a) => execFileSync("openssl", a, { cwd: pki, stdio: "pipe" });
openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Test Corp Root CA",
  "-addext", "subjectAltName=DNS:bridge-tls.test,DNS:bridge-slack.test,DNS:bridge-db.test", "-addext", "basicConstraints=CA:TRUE");
const CA = join(pki, "ca.pem");
const inspect = new Map();
const proxy = await startForwardProxy({ inspect, key: readFileSync(join(pki, "key.pem")), cert: readFileSync(CA) });
const slack = await slackLocalBackend();
const supa = await supabaseLocalBackend();
const procs = [];
const agent = async (backend, name, env) => {
  const a = await connectAgent({ envFor: () => env }, name, {});
  procs.push(a);
  return a;
};

try {
  for (const a of ["frontend", "backend"]) {
    await slack.addAgent(a);
    await supa.addAgent(a);
  }
  // URLs whose host name only the proxy can resolve
  inspect.set("bridge-slack.test", Number(portOf(slack.slack.url)));
  inspect.set("bridge-db.test", Number(portOf(supa.url)));
  const slackUrl = `https://bridge-slack.test:${portOf(slack.slack.url)}/api`;
  const supaUrl = `https://bridge-db.test:${portOf(supa.url)}`;
  const slackEnv = (name, extra = {}) => ({ ...slack.envFor(name), SLACK_API_URL: slackUrl, ...extra });
  const supaEnv = (name, extra = {}) => ({ ...supa.envFor(name), SUPABASE_URL: supaUrl, ...extra });
  const THROUGH = { NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url, NODE_EXTRA_CA_CERTS: CA };

  for (const [label, envFn, host] of [
    ["Slack (https, TLS inspected)", slackEnv, "bridge-slack.test"],
    ["PostgREST (https, TLS inspected)", supaEnv, "bridge-db.test"],
  ]) {
    await test(`${label}: with NODE_USE_ENV_PROXY=1 and HTTP_PROXY, every request goes through the proxy`, async () => {
      proxy.reset();
      const fe = await agent(null, "frontend", envFn("frontend", THROUGH));
      const be = await agent(null, "backend", envFn("backend", THROUGH));
      const startup = proxy.requests(host);
      assert.ok(startup > 0, "the server's startup calls bypassed the proxy");
      const me = await who(fe);
      assert.deepEqual(me.proxy, { configured: true, active: true });
      const sent = await fe.call("send_message", { to: "backend", body: "through the proxy" });
      assert.equal(sent.isError, false, sent.text);
      assert.match((await be.call("check_inbox")).text, /through the proxy/);
      assert.ok(proxy.requests(host) > startup, "send/read did not use the proxy");
      assert.ok(proxy.hits.every((h) => h.host === host), `unexpected destinations: ${JSON.stringify(proxy.hits.map((h) => h.host))}`);
      assert.equal(stderrOf(fe).includes("WARNING"), false, stderrOf(fe));
    });

    await test(`${label}: without NODE_USE_ENV_PROXY the proxy is ignored (direct lookup fails), and the server says why`, async () => {
      proxy.reset();
      const r = await runServerExpectExit(envFn("frontend", { HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url, NODE_EXTRA_CA_CERTS: CA }));
      assert.notEqual(r.code, 0);
      assert.equal(proxy.count(), 0, "a request reached the proxy although env proxy support was off");
      assert.match(r.stderr, /Can't reach/);
      assert.match(r.stderr, /WARNING: HTTP\(S\)_PROXY is set, but this process wasn't started with proxy support/);
      assert.match(r.stderr, /NODE_USE_ENV_PROXY=1/);
    });

    await test(`${label}: NO_PROXY matching the host bypasses the proxy (and so can't resolve the name)`, async () => {
      proxy.reset();
      const r = await runServerExpectExit(envFn("frontend", { ...THROUGH, NO_PROXY: host }));
      assert.notEqual(r.code, 0);
      assert.equal(proxy.count(), 0, "NO_PROXY was ignored");
      assert.match(r.stderr, /Can't reach.*ENOTFOUND/);
      assert.ok(!/WARNING/.test(r.stderr), "the proxy is active, no warning expected");
    });
  }

  await test("loopback addresses ARE proxied unless NO_PROXY exempts them (so a container's NO_PROXY matters)", async () => {
    const direct = { ...slack.envFor("frontend") }; // http://127.0.0.1:PORT
    proxy.reset();
    const viaProxy = await agent(null, "frontend", { ...direct, ...THROUGH });
    assert.ok(proxy.count("127.0.0.1") > 0, "loopback bypassed the proxy without NO_PROXY");
    assert.equal((await who(viaProxy)).proxy.active, true);
    proxy.reset();
    const bypass = await agent(null, "frontend", { ...direct, ...THROUGH, NO_PROXY: "localhost,127.0.0.1,::1" });
    assert.equal(proxy.count(), 0, "NO_PROXY=127.0.0.1 was not honoured");
    assert.equal((await who(bypass)).agent, "frontend");
    proxy.reset();
    const lower = await agent(null, "frontend", { ...direct, NODE_USE_ENV_PROXY: "1", http_proxy: proxy.url, no_proxy: "127.0.0.1" });
    assert.equal(proxy.count(), 0, "lower-case no_proxy was not honoured");
    assert.deepEqual((await who(lower)).proxy, { configured: true, active: true }, "lower-case http_proxy counts as configured");
    proxy.reset();
    await agent(null, "frontend", { ...direct, NODE_USE_ENV_PROXY: "1", http_proxy: proxy.url });
    assert.ok(proxy.count("127.0.0.1") > 0, "lower-case http_proxy was ignored");
  });

  await test("a proxy that is down is reported as unreachable, not hung", async () => {
    const r = await runServerExpectExit(slackEnv("frontend", { NODE_USE_ENV_PROXY: "1", HTTPS_PROXY: "http://127.0.0.1:9" }), 40000);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /Can't reach Slack/);
  });

  await test("configured but inactive: whoami says so and the startup warning is on stderr (network backends only)", async () => {
    const a = await agent(null, "frontend", { ...slack.envFor("frontend"), HTTPS_PROXY: proxy.url, NO_PROXY: "127.0.0.1" });
    assert.deepEqual((await who(a)).proxy, { configured: true, active: false });
    await new Promise((r) => setTimeout(r, 200));
    assert.match(stderrOf(a), /WARNING: HTTP\(S\)_PROXY is set/);
    const none = await agent(null, "backend", slack.envFor("backend"));
    assert.deepEqual((await who(none)).proxy, { configured: false, active: false });
    assert.ok(!/WARNING/.test(stderrOf(none)));
  });

  await test("the local SQLite backend makes no requests, so it doesn't warn about proxies", async () => {
    const dir = mkdtempSync(join(tmp, "sq-"));
    const a = await agent(null, "frontend", { AGENT_BRIDGE_BACKEND: "sqlite", AGENT_NAME: "frontend", AGENT_BRIDGE_DB: join(dir, "b.db"), HTTPS_PROXY: proxy.url });
    assert.deepEqual((await who(a)).proxy, { configured: true, active: false });
    assert.ok(!/WARNING/.test(stderrOf(a)), stderrOf(a));
  });

  // ------------------------------------------------------------------------------ init

  console.log("\n=== proxy: init carries the settings into .mcp.json and the hook ===");
  const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
  const repo = (n) => {
    const d = join(tmp, n);
    mkdirSync(d, { recursive: true });
    return d;
  };
  const slackTokenFile = join(HOME, ".agent-bridge", "tokens", "frontend.slack-token");
  mkdirSync(join(HOME, ".agent-bridge", "tokens"), { recursive: true });
  writeFileSync(slackTokenFile, slack.tokens.frontend + "\n", { mode: 0o600 });
  const initEnv = (extra = {}) => ({ HOME, SLACK_CHANNEL_ID: slack.slack.channel.id, SLACK_API_URL: slackUrl, ...extra });
  const SECRET_PW = "pa55w0rd-Zq";

  await test("init --slack writes proxy, NO_PROXY (both cases), CA and system-CA settings, plus NODE_USE_ENV_PROXY=1, and says so", async () => {
    const r = repo("init-proxy");
    const ca = join(tmp, "corp-ca.pem");
    writeFileSync(ca, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    const env = initEnv({
      HTTPS_PROXY: `http://alice:${SECRET_PW}@proxy.corp:8080`,
      http_proxy: "http://proxy.corp:3128",
      NO_PROXY: "localhost,.corp.example,10.0.0.0/8",
      no_proxy: "localhost",
      NODE_EXTRA_CA_CERTS: ca,
      NODE_USE_SYSTEM_CA: "1",
    });
    const res = await runCli(["init", r, "frontend", "--slack", "--hook"], env);
    assert.equal(res.code, 0, res.err);
    const e = readJson(join(r, ".mcp.json")).mcpServers.bridge.env;
    assert.equal(e.HTTPS_PROXY, env.HTTPS_PROXY);
    assert.equal(e.http_proxy, env.http_proxy);
    assert.equal(e.NO_PROXY, env.NO_PROXY);
    assert.equal(e.no_proxy, "localhost");
    assert.equal(e.NODE_EXTRA_CA_CERTS, ca);
    assert.equal(e.NODE_USE_SYSTEM_CA, "1");
    assert.equal(e.NODE_USE_ENV_PROXY, "1");
    assert.match(res.out, /proxy\/TLS settings from your shell were written/);
    assert.match(res.out, /HTTPS_PROXY=http:\/\/alice:\*\*\*@proxy\.corp:8080/);
    assert.ok(!res.out.includes(SECRET_PW), "init printed the proxy password");
    assert.match(res.out, /contains credentials/);
    // the hook carries the same environment, single-quoted like the rest of it
    const cmd = readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.at(-1).hooks[0].command;
    assert.ok(cmd.includes(`NODE_USE_ENV_PROXY='1'`), cmd);
    assert.ok(cmd.includes(`NO_PROXY='localhost,.corp.example,10.0.0.0/8'`), cmd);
    assert.ok(cmd.includes(`HTTPS_PROXY='http://alice:${SECRET_PW}@proxy.corp:8080'`), cmd);
    assert.ok(cmd.includes(`NODE_EXTRA_CA_CERTS='${ca}'`), cmd);
  });

  await test("init: a relative NODE_EXTRA_CA_CERTS becomes an absolute path (Claude starts the server elsewhere)", async () => {
    const r = repo("init-ca-only");
    const res = await runCli(["init", r, "frontend", "--slack"], initEnv({ NODE_EXTRA_CA_CERTS: "./certs/ca.pem" }));
    assert.equal(res.code, 0, res.err);
    const e = readJson(join(r, ".mcp.json")).mcpServers.bridge.env;
    assert.match(e.NODE_EXTRA_CA_CERTS, /^\/.*certs\/ca\.pem$/);
    assert.equal(e.NODE_USE_ENV_PROXY, undefined, "no proxy URL, so no proxy switch");
  });

  await test("init writes nothing proxy-related when the shell has none, and re-running init drops stale settings", async () => {
    const r = repo("init-none");
    await runCli(["init", r, "frontend", "--slack"], initEnv({ HTTPS_PROXY: proxy.url }));
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.NODE_USE_ENV_PROXY, "1");
    const res = await runCli(["init", r, "frontend", "--slack"], initEnv());
    const e = readJson(join(r, ".mcp.json")).mcpServers.bridge.env;
    for (const k of Object.keys(e)) assert.ok(!/proxy|CA_CERTS|SYSTEM_CA/i.test(k), k);
    assert.ok(!/proxy\/TLS/.test(res.out));
  });

  await test("init for the local backend ignores proxy variables (no network calls)", async () => {
    const r = repo("init-local");
    const res = await runCli(["init", r, "frontend"], { HOME, HTTPS_PROXY: proxy.url, NODE_EXTRA_CA_CERTS: "/x.pem" });
    assert.equal(res.code, 0, res.err);
    const e = readJson(join(r, ".mcp.json")).mcpServers.bridge.env;
    assert.deepEqual(Object.keys(e).sort(), ["AGENT_BRIDGE_DB", "AGENT_NAME"]);
  });

  await test("init --supabase carries the settings too", async () => {
    const r = repo("init-supa");
    const tf = join(HOME, ".agent-bridge", "tokens", "frontend.token");
    writeFileSync(tf, supa.tokens.frontend + "\n", { mode: 0o600 });
    const res = await runCli(["init", r, "frontend", "--supabase"], {
      HOME,
      SUPABASE_URL: supaUrl,
      SUPABASE_PUBLISHABLE_KEY: supa.publishable,
      HTTP_PROXY: proxy.url,
      NO_PROXY: "localhost",
    });
    assert.equal(res.code, 0, res.err);
    const e = readJson(join(r, ".mcp.json")).mcpServers.bridge.env;
    assert.equal(e.HTTP_PROXY, proxy.url);
    assert.equal(e.NO_PROXY, "localhost");
    assert.equal(e.NODE_USE_ENV_PROXY, "1");
  });

  await test("the generated config really works through the proxy (init → server → Slack, all via the proxy)", async () => {
    const r = repo("init-e2e");
    const res = await runCli(["init", r, "frontend", "--slack", "--hook"], initEnv({ HTTPS_PROXY: proxy.url, NODE_EXTRA_CA_CERTS: CA }));
    assert.equal(res.code, 0, res.err);
    const cfg = readJson(join(r, ".mcp.json")).mcpServers.bridge;
    proxy.reset();
    const client = new Client({ name: "init-e2e", version: "0" });
    await client.connect(new StdioClientTransport({ command: cfg.command, args: cfg.args, env: { PATH: process.env.PATH, HOME, ...cfg.env }, cwd: r }));
    const out = JSON.parse((await client.callTool({ name: "whoami", arguments: {} })).content[0].text);
    await client.close();
    assert.equal(out.agent, "frontend");
    assert.deepEqual(out.proxy, { configured: true, active: true });
    assert.ok(proxy.requests("bridge-slack.test") > 0, "the generated config did not use the proxy");
    // the hook (a bash one-liner) uses it too
    proxy.reset();
    const hook = readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.at(-1).hooks[0].command;
    await promisify(execFile)("bash", ["-c", hook], { cwd: r, env: { PATH: process.env.PATH, HOME, AGENT_BRIDGE_DEBUG: "1" } });
    assert.ok(proxy.requests("bridge-slack.test") > 0, "the hook did not use the proxy");
  });

  // ------------------------------------------------------------------------------ TLS inspection

  console.log("\n=== proxy: the company CA ===");
  const secure = https.createServer({ key: readFileSync(join(pki, "key.pem")), cert: readFileSync(CA) }, (req, res) => {
    const fn = req.url.split("/").pop();
    const json = (o) => res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(o));
    req.resume();
    if (fn === "bridge_whoami") return json({ agent: "tlsagent", description: null, project_dir: null, unread: 0 });
    if (fn === "bridge_heartbeat") return res.writeHead(204).end();
    return json([]);
  });
  await new Promise((r) => secure.listen(0, "127.0.0.1", r));
  const tlsEnv = (extra) => ({
    AGENT_BRIDGE_BACKEND: "supabase",
    SUPABASE_URL: `https://bridge-tls.test:${secure.address().port}`,
    SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test",
    AGENT_BRIDGE_TOKEN: "abt_" + "ab".repeat(32),
    NODE_USE_ENV_PROXY: "1",
    HTTPS_PROXY: proxy.url,
    ...extra,
  });
  try {
    await test("HTTPS through the proxy (CONNECT) fails on the company CA until NODE_EXTRA_CA_CERTS is set", async () => {
      proxy.reset();
      const bad = await runServerExpectExit(tlsEnv({}));
      assert.notEqual(bad.code, 0);
      assert.match(bad.stderr, /Can't reach Supabase.*(SELF_SIGNED|DEPTH_ZERO|UNABLE_TO_VERIFY|CERT)/);
      assert.ok(proxy.hits.some((h) => h.kind === "connect" && h.host === "bridge-tls.test"), "no CONNECT seen");
      const good = await agent(null, "x", tlsEnv({ NODE_EXTRA_CA_CERTS: CA }));
      const me = await who(good);
      assert.equal(me.agent, "tlsagent");
      assert.deepEqual(me.proxy, { configured: true, active: true });
    });
  } finally {
    await new Promise((r) => (secure.closeAllConnections?.(), secure.close(r)));
  }

  // ------------------------------------------------------------------------------ transport security

  console.log("\n=== transport security: tokens only travel over https ===");

  await test("assertSecureUrl: https and loopback are fine; plain http to anywhere else is refused", async () => {
    const A = (u, o) => common.assertSecureUrl(u, "SUPABASE_URL", o);
    for (const u of ["https://x.supabase.co", "https://x.supabase.co/", "http://127.0.0.1:54321", "http://127.8.9.10", "http://localhost:3000", "http://[::1]:8000", "HTTP://LOCALHOST"]) {
      assert.doesNotThrow(() => A(u, { allowInsecure: false }), u);
    }
    for (const u of ["http://x.supabase.co", "http://10.0.0.5", "http://localhost.evil.com", "http://127.0.0.1.evil.com", "http://evil.com/127.0.0.1", "ftp://x.co", "x.supabase.co", "", "javascript:alert(1)", "http://128.0.0.1"]) {
      assert.throws(() => A(u, { allowInsecure: false }), /SUPABASE_URL (must start with https:\/\/|is not a valid URL)/, u);
    }
    assert.doesNotThrow(() => A("http://10.0.0.5", { allowInsecure: true }), "the explicit escape hatch");
    assert.throws(() => A("ftp://x.co", { allowInsecure: true }), /must start with https/, "the hatch only allows http");
  });

  const refusing = { SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test", AGENT_BRIDGE_TOKEN: "abt_" + "ab".repeat(32) };
  await test("the server refuses a plain-http SUPABASE_URL and a plain-http SLACK_API_URL, naming the variable", async () => {
    const s = await runServerExpectExit({ AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: "http://db.example.com", ...refusing });
    assert.notEqual(s.code, 0);
    assert.match(s.stderr, /SUPABASE_URL must start with https:\/\//);
    const k = await runServerExpectExit({ AGENT_BRIDGE_BACKEND: "slack", SLACK_API_URL: "http://slack.example.com/api", SLACK_CHANNEL_ID: "C0123456789", SLACK_BOT_TOKEN: "xoxb-123456789012-abc" });
    assert.notEqual(k.code, 0);
    assert.match(k.stderr, /SLACK_API_URL must start with https:\/\//);
    assert.ok(!k.stderr.includes("xoxb-123456789012"), "the token must not be printed");
  });

  await test("the CLI admin commands are covered by the same rule", async () => {
    const r = await runCli(["limits"], { SUPABASE_URL: "http://db.example.com", SUPABASE_SECRET_KEY: "sb_secret_" + "x".repeat(20) });
    assert.notEqual(r.code, 0);
    assert.match(r.err, /SUPABASE_URL must start with https:\/\//);
  });

  await test("AGENT_BRIDGE_ALLOW_INSECURE_HTTP=1 lets a lab use plain http (the failure is then just 'can't reach')", async () => {
    const r = await runServerExpectExit({ AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: "http://bridge-db.invalid", ...refusing, AGENT_BRIDGE_ALLOW_INSECURE_HTTP: "1" }, 60000);
    assert.notEqual(r.code, 0);
    assert.ok(!/must start with https/.test(r.stderr), r.stderr);
    assert.match(r.stderr, /Can't reach Supabase/);
  });
} finally {
  for (const a of procs) await a.close().catch(() => {});
  await proxy.close();
  await slack.cleanup();
  await supa.cleanup();
  rmSync(tmp, { recursive: true, force: true });
}

// stderr of a server started with agent(): connectAgent exposes it
function stderrOf(a) {
  return a.stderr();
}

process.exit(summary() ? 1 : 0);
