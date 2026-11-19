// Corporate proxy support.
//
// Node's built-in fetch() ignores HTTP_PROXY / HTTPS_PROXY / NO_PROXY unless the process was
// started with NODE_USE_ENV_PROXY=1 (or --use-env-proxy). That support exists in Node >= 24.0
// and in the 22.x line from 22.21.0 (v23 never got it; the node:http/https clients need 24.5). It must be on at process start: the
// environment is read once, when the process boots, so it can't be switched on from inside.
// NODE_EXTRA_CA_CERTS (also read at startup) adds the company's TLS-inspection CA.
//
// `cli.js init` therefore writes the shell's proxy variables, plus NODE_USE_ENV_PROXY=1, into
// the generated .mcp.json (and the hook command), and the server and `doctor` report whether
// the proxy is actually in effect.

export const PROXY_URL_VARS = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"];
export const PROXY_VARS = [...PROXY_URL_VARS, "NO_PROXY", "no_proxy"];
export const CA_VAR = "NODE_EXTRA_CA_CERTS";
export const SYSTEM_CA_VAR = "NODE_USE_SYSTEM_CA"; // trust the OS certificate store (Node >= 22.19 / 24.6)

export function nodeSupportsSystemCa(version = process.versions.node) {
  const [major, minor] = version.split(".").map(Number);
  return major >= 25 || (major === 24 && minor >= 6) || (major === 22 && minor >= 19);
}

export function nodeSupportsEnvProxy(version = process.versions.node) {
  const [major, minor] = version.split(".").map(Number);
  return major >= 24 || (major === 22 && minor >= 21);
}

// The proxy-related variables present in `env`, as written (either case).
export function proxyEnvFrom(env = process.env) {
  const out = {};
  for (const k of PROXY_VARS) if (env[k] && env[k].trim()) out[k] = env[k].trim();
  if (env[CA_VAR] && env[CA_VAR].trim()) out[CA_VAR] = env[CA_VAR].trim();
  if (env[SYSTEM_CA_VAR] && env[SYSTEM_CA_VAR].trim()) out[SYSTEM_CA_VAR] = env[SYSTEM_CA_VAR].trim();
  return out;
}

// What init puts into the generated config: the shell's proxy settings, and the switch that
// makes Node use them. Returns {} when there is nothing to carry over.
export function proxyEnvForConfig(env = process.env) {
  const out = proxyEnvFrom(env);
  if (PROXY_URL_VARS.some((k) => out[k])) out.NODE_USE_ENV_PROXY = "1";
  return out;
}

// { configured, active, supported, ... } for a process started with `env`.
export function proxyStatus({
  env = process.env,
  execArgv = process.execArgv,
  version = process.versions.node,
} = {}) {
  const configured = PROXY_URL_VARS.some((k) => env[k] && env[k].trim());
  const supported = nodeSupportsEnvProxy(version);
  const flagged =
    env.NODE_USE_ENV_PROXY === "1" ||
    execArgv.includes("--use-env-proxy") ||
    /(^|\s)--use-env-proxy(\s|$)/.test(env.NODE_OPTIONS || "");
  return { configured, active: configured && supported && flagged, supported, requested: flagged };
}

// The stderr warning for "a proxy is configured but fetch() won't use it", or null.
export function proxyWarning(status) {
  if (!status.configured || status.active) return null;
  if (!status.supported) {
    return (
      `HTTP(S)_PROXY is set, but Node ${process.versions.node} is too old to use it: proxy variables are honoured only from ` +
      `Node 22.21 (22 line) or 24.0 onwards (24.5 for node:http). Upgrade Node, otherwise requests go direct and a firewall will block them.`
    );
  }
  return (
    `HTTP(S)_PROXY is set, but this process wasn't started with proxy support, so requests will go direct ` +
    `(and a corporate firewall will probably block them). Fix: add NODE_USE_ENV_PROXY=1 to the "env" of this server in ` +
    `.mcp.json (re-running "cli.js init" does it), or start node with --use-env-proxy.`
  );
}

// Proxy URL with any credentials hidden, for display.
export function maskProxyUrl(value) {
  return String(value).replace(/\/\/([^/@\s]*)@/, (_, cred) => {
    const user = cred.split(":")[0];
    return `//${user}${cred.includes(":") ? ":***" : ""}@`;
  });
}

export const proxyUrlHasCredentials = (value) => /\/\/[^/@\s]*:[^/@\s]*@/.test(String(value));
