// Tiny test runner + MCP client helpers shared by the suites.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const SERVER = fileURLToPath(new URL("../server.js", import.meta.url));
export const CLI = fileURLToPath(new URL("../cli.js", import.meta.url));

const results = [];
export async function test(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    results.push({ name, ok: true, ms: Date.now() - t0 });
    console.log(`  ok   ${name} (${Date.now() - t0}ms)`);
  } catch (e) {
    results.push({ name, ok: false, ms: Date.now() - t0, error: e });
    console.log(`  FAIL ${name}\n       ${String(e.stack || e).split("\n").slice(0, 6).join("\n       ")}`);
  }
}
export function summary() {
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  return failed.length;
}

// Starts a real MCP server process for `agent` with the backend's env and connects a client.
export async function connectAgent(backend, agent, extraEnv = {}) {
  const client = new Client({ name: `test-${agent}`, version: "0.0.0" });
  let stderr = "";
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { ...cleanEnv(), ...backend.envFor(agent), AGENT_BRIDGE_MAX_HOPS: "4", ...extraEnv },
    stderr: "pipe",
  });
  transport.stderr?.on("data", (d) => (stderr += d));
  await client.connect(transport);
  const call = async (tool, args = {}) => {
    const r = await client.callTool({ name: tool, arguments: args });
    return { text: r.content.map((c) => c.text).join("\n"), isError: !!r.isError };
  };
  return { client, call, close: () => client.close(), stderr: () => stderr };
}

// Runs the server expecting it to exit at startup; resolves { code, stderr }.
export function runServerExpectExit(env, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [SERVER], { env: { ...cleanEnv(), ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    p.stderr.on("data", (d) => (stderr += d));
    const t = setTimeout(() => {
      p.kill();
      reject(new Error(`server did not exit; stderr: ${stderr}`));
    }, timeoutMs);
    p.on("close", (code) => {
      clearTimeout(t);
      resolve({ code, stderr });
    });
  });
}

export function runCli(args, env, { input } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...args], { env: { ...cleanEnv(), ...env } });
    let out = "",
      err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    if (input != null) p.stdin.end(input);
    else p.stdin.end();
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

// Strip bridge-related vars from the parent env so tests can't leak config into each other.
function cleanEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (/^(AGENT_|SUPABASE_)/.test(k)) delete env[k];
  }
  return env;
}

// Thread ids are UUIDs (SQLite, Supabase) or message timestamps (Slack).
export const threadOf = (text) => text.match(/in thread (\S+) \(/)?.[1];
