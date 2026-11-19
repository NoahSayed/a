# Hardening for corporate and regulated environments

What was added on top of `b87e49c` (Slack backend): DLP on outgoing messages, corporate proxy / TLS-inspection support,
https-only backend URLs, and `cli.js doctor`. README.md and docs/TESTING.md were not touched; this note is the record.

## 1. DLP (`stores/dlp.js`)

Hooked into `validateOutgoing()` in `stores/common.js`, which SQLite, Supabase and Slack all call. It now returns
`{ body, subject, dlp }` and each store sends *those* values (the redacted text), so no backend can forget to apply it.
`AGENT_BRIDGE_DLP`: `block` (default), `redact`, `warn`, `off`. Anything else is an error (the server refuses to start,
`doctor` FAILs): a typo must not silently turn protection off. `whoami` reports `dlp: "<mode>"`; `send_message` appends a
`DLP: redacted ...` or `DLP warning: ...` line to its result; the `cli.js send` command prints it too.

**Block** names the kinds and the field, never the data: `Message not sent: it appears to contain sensitive data:
1 AWS access key id (body), 2 payment card numbers (body), 1 GitHub token (subject). Remove or replace it ...`.
**Redact** replaces each match with `[REDACTED:<kind>]` (kinds: `private-key aws-access-key aws-secret-key github-token
slack-token stripe-key google-api-key jwt bridge-token supabase-secret-key secret-assignment payment-card iban`); for a
`password = "x"` assignment only the value is replaced. If redaction makes the body longer than the backend's limit the
send is refused (a 16-digit card becomes 23 characters).

Detectors (all linear-time; a 50,000-character body of worst-case shapes scans in well under 100 ms):

| Kind | Rule |
|---|---|
| private key | `-----BEGIN [... ]PRIVATE KEY[ BLOCK]-----` (header alone is enough; the body up to `-----END` or the following base64 lines is redacted). Public keys and certificates are not flagged |
| AWS | `AKIA`/`ASIA` + 16 `[A-Z0-9]`; `aws...secret...[:=] <40 base64 chars>` |
| GitHub | `ghp_ gho_ ghs_ ghu_ ghr_` + 36+, `github_pat_` + 22+ |
| Slack | `xox[abprs]-`, `xapp-` + 10+ |
| Stripe | `sk_live_`, `rk_live_` + 16+ |
| Google | `AIza` + exactly 35 |
| JWT | three base64url segments whose header **decodes to JSON with a string `alg`** |
| this project | `abt_` + exactly 64 hex (`abt_` + fewer is not flagged), `sb_secret_` + 16+ |
| assignment | `password/passwd/secret(_key)/api_key/private_key/token (+access_/auth_/refresh_ prefixes) = value`, see below |
| payment card | 13-19 digits, contiguous or 4-4-4-4 / 4-6-5 with one kind of separator; **Luhn-valid and in an issuer range**: Visa, Mastercard (51-55, 2221-2720), Amex, Discover (6011, 65, 644-649, 622126-622925), JCB (3528-3589), UnionPay (62), Diners (300-305, 3095, 36, 38, 39) with the scheme's lengths. Not when glued to letters, `_` or `-` (identifiers, UUID/date fragments) |
| IBAN | country code + check digits + BBAN, **the country's exact length** (SWIFT registry table, 75 countries), **mod-97 = 1**, either compact or in groups of four |

The assignment rule is the false-positive-prone one. The value must be at least 8 characters, no whitespace, not a
placeholder (`xxx`, `***`, `<...>`, `your_...`, `changeme`, `null`, `true`, ...), not a variable reference (`$X`,
`${X}`), not a property chain (`process.env.KEY`), and, if unquoted, not a call or index (`getToken()`, `tokens[0]`), not
followed by `;` (a code statement), and it must contain a digit or a symbol. Quoted values may instead be mixed-case. So
`const token = getToken()`, `token: Optional[str]`, `password = $DB_PASSWORD` and `X.MD5Password = Name;` pass, while
`password=hunter2hunter2`, `"api_key": "abcd1234efgh5678"` and `export GITHUB_TOKEN=Tok3nValue99` are caught.

**False-positive list** (all asserted in `test/dlp.js`): UUIDs, 40/7-char git SHAs, Slack timestamps
(`1700000000.123456`), epoch milliseconds, ISO dates and times, phone numbers (US, UK, DE formats and bare digits), order
numbers that fail Luhn or have no issuer range, 13-digit order numbers, `ORD-`/`tx_`/`ref` prefixed numbers, 32-digit
runs, version strings (`1.2.3`, `10.20.30-beta.1+build.5`, `v22.13.0`), a base64 PNG data URI containing `AKIA`,
`abt_` + 63 hex or + 10 hex, `sb_publishable_...` (public by design), the word "password"/"token" in prose, a JWT-shaped
string whose header has no `alg`, `eyJ.not.jwt`, public keys and certificates, `AKIA`/`ghp_`/`xoxb-` mentioned as prefixes,
`DE89`-style fragments, and these code shapes: `const token = getToken()`, `await getToken();`, `getToken2()`,
`refreshToken;`, `password = prompt`, `password: string`, `token: Optional[str] = None`, `process.env.SECRET_KEY`,
`os.environ['API_KEY']`, `$DB_PASSWORD`, `${DB_PASSWORD}`, `<your password here>`, `********`, `token=changeme`,
`req.headers.authorization`, `tokens[0]`, `max_tokens = 4096`, `password == 'abcdefgh1'`, `secretary: ...`,
`password_hash = 'x'`, `AGENT_BRIDGE_TOKEN_FILE=/path`, SQL snippets and JSON like the e2e suite's.
Also scanned: 13.5 million characters of real text (this project's `node_modules`, 2,929 files). 46 findings, all genuine: 22
test card numbers and 21 test IBANs in zod's test files, 1 literal `-----BEGIN PRIVATE KEY-----` in jose, 2 JWT
examples. One real false positive turned up there (`MD5Password = AuthenticationMD5Password;` in pg-protocol); it is fixed
and now a fixture.

## 2. Corporate proxy and TLS inspection

Findings (Node here: v22.23.5; docs checked by web search, https://nodejs.org/en/learn/http/enterprise-network-configuration):
- `fetch()` ignores `HTTP(S)_PROXY`/`NO_PROXY` unless the process starts with `NODE_USE_ENV_PROXY=1` (or `--use-env-proxy`).
  Documented for `fetch()` from **22.21.0 and 24.0.0**, for `node:http`/`https` from 22.21.0 and 24.5.0. v23 never got it.
  The orchestrator brief said "22.21 and 24.5"; 24.5 is the `node:http` bound, and this project only uses `fetch()`, so
  `proxy.js` accepts 24.0+. If you want the stricter bound it is one line (`nodeSupportsEnvProxy`).
- The environment is read **at bootstrap**: setting `process.env.HTTP_PROXY` inside a running script has no effect (I
  tried), which is why `init` writes it into `.mcp.json` and why the server can only warn, not fix itself.
- Even for `http://` targets, Node's env proxy uses **CONNECT** (not absolute-URI requests).
- **Loopback is proxied like any other address** unless `NO_PROXY` exempts it (shown in a test). This container's own
  `NO_PROXY` contains `127.0.0.1`/`localhost`, so a naive test would silently bypass the proxy. The harness now strips
  `*_proxy`, `NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA` and `SLACK_*` from child environments, and
  every proxy test sets exactly the variables it means to test.
- `NODE_USE_ENV_PROXY=1` makes Node print `ExperimentalWarning: EnvHttpProxyAgent is experimental` on stderr. Harmless.
- Node 22.19+/24.6+ also has `NODE_USE_SYSTEM_CA=1` (trust the OS store); `init` passes it through and `doctor` checks the version.

Design of the test (`test/proxy.js`): a real forward proxy written in the test, speaking absolute-URI HTTP and CONNECT, that
**resolves names itself** (any `*.test` host name maps to 127.0.0.1 only inside the proxy) and counts requests. The fake Slack
and the PostgREST stand-in are reached as `https://bridge-slack.test:PORT` / `https://bridge-db.test:PORT`: a direct attempt fails
with `ENOTFOUND`, so success proves the traffic went through the proxy. For those two hosts the proxy also terminates TLS with
its own certificate (made with `openssl` in the test), like a TLS-inspecting corporate proxy, and the server trusts it via
`NODE_EXTRA_CA_CERTS`; requests inside the keep-alive tunnel are counted individually. Scenarios: through the proxy (both
stand-ins); proxy variables without `NODE_USE_ENV_PROXY` (direct lookup fails, 0 proxy hits, stderr explains the fix);
`NO_PROXY` matching the host bypasses; loopback with and without `NO_PROXY`, upper and lower case; dead proxy; the
company CA missing/present (cert error before, working after); inactive-proxy warning on network backends only (SQLite
makes no requests, so it stays quiet; `whoami.proxy` is still reported).

`init` (supabase and slack only): copies `HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NO_PROXY no_proxy NODE_EXTRA_CA_CERTS
NODE_USE_SYSTEM_CA` from the shell into the server `env`, adds `NODE_USE_ENV_PROXY=1` when a proxy URL is present, makes a
relative CA path absolute, and prints what it wrote (proxy passwords masked, plus a warning that credentials are now in
plain text in the generated files). The hook command carries the same variables with the existing `shq` quoting. Re-running
`init` without them removes stale settings. The server warns on stderr at startup (network backends) and `whoami` has
`proxy: {configured, active}`. When Node is too old for the switch, both say so explicitly.

## 3. https-only backends (addendum)

`assertSecureUrl()` in `stores/common.js`, called from the `SupabaseStore` and `SlackStore` constructors, so the server,
the admin CLI, `doctor`, and any backend reusing `SupabaseStore` (the relay) get it. `http://` is allowed only for loopback
(`127.0.0.0/8`, `::1`, `localhost`, matched exactly: `localhost.evil.com` and `127.0.0.1.evil.com` are refused) or with
`AGENT_BRIDGE_ALLOW_INSECURE_HTTP=1`, which allows only `http:` (not `ftp:` etc.).

## 4. `cli.js doctor [repo]`

OK/WARN/FAIL checklist, a `fix:` line under every WARN/FAIL, exit 1 if any FAIL. With a repo path it reads that repo's
`.mcp.json` `bridge` env over the shell's, which is what Claude Code will launch. Checks: Node >= 22.13; backend and why;
required variables; https-only URL; publishable key is not a secret key; admin secret key present in an agent's env (WARN);
token inline (WARN) / file exists / mode (world-readable FAIL, group WARN, owner-only OK) / owner / directory / format;
SQLite path, directory writable, mailbox private (world-readable FAIL), open + write lock test (`BEGIN IMMEDIATE`/`ROLLBACK`);
proxy variables (passwords masked), active or not, Node version; `NODE_EXTRA_CA_CERTS` exists and is PEM;
`NODE_USE_SYSTEM_CA` vs Node version; DLP mode; reachability and auth: Supabase `bridge_whoami` (agent name, name
mismatch), Slack `auth.test` then channel membership. Network checks run in a **child process with the effective
environment** so proxy/CA variables apply exactly as in the server. Failures are explained by cause (cert errors point to
`NODE_EXTRA_CA_CERTS`, DNS/refused/timeouts to the proxy switch, wrong key/token/scopes/membership to their fix).
Tokens appear only as first six characters + `…`; known secret values are replaced, and the DLP scanner runs over the final
text as a second net.

## Test results

Commit under test: see the final commit of this branch. Every suite was run twice in a row, all green both times:

| Suite | Run 1 | Run 2 |
|---|---|---|
| `node test/e2e.js sqlite supabase-local slack-local` | 60/60 | 60/60 |
| `node test/security.js supabase-local` | 19/19 | 19/19 |
| `node test/slack.js` | 17/17 | 17/17 |
| `node test/concurrency.js sqlite supabase-local slack-local` | 9/9 | 9/9 |
| `node test/cli.js` | 24/24 | 24/24 |
| `node test/regressions-r1.js` | 29/29 | 29/29 |
| `node test/dlp.js` (new) | 37/37 | 37/37 |
| `node test/proxy.js` (new) | 25/25 | 25/25 |
| `node test/doctor.js` (new) | 24/24 | 24/24 |

**Fail before, pass after.** The three new suites run against a pristine copy of `b87e49c` (plus only the new test files and the
harness env-stripping change): `dlp.js` **3/37**, `proxy.js` **5/25**, `doctor.js` **0/24**. The 3 that pass in `dlp.js` are
"clean messages still go through" on each backend. The 5 in `proxy.js` are behaviours that were already true (init for the
local backend writes nothing; a dead proxy is reported unreachable; `NO_PROXY`-excluded hosts fail to resolve directly;
the `ALLOW_INSECURE_HTTP` hatch is harmless where there is no check). The existing suites passed unchanged on the new code
with DLP in its default `block` mode: no existing test needed editing and nothing they send was flagged.

## Mutations

`node test/mutations.js "HD "`: **61 of 61 killed** (32 DLP, 21 proxy/https, 12 doctor... see list in `test/mutations.js`, names start with `HD `).
The full run on the final code killed 60 and one survived: `HD DLP assignment: bare identifiers flagged`. Cause: I had just
added the "followed by `;` is a code statement" rule, and the only fixture for the digit-or-symbol requirement
(`const token = refreshToken;`) ended in `;`, so the new rule hid it. Fixtures without `;` were added
(`token = refreshToken`, `secret: loadedSecretValue`); re-running `node test/mutations.js "HD DLP assignment"`: 5/5 killed.
Mutations with two guards remove both (the file's existing convention): `HD DLP IBAN length not checked` (the length check
in `isIban` and the scanner stopping at the country's length; the test uses numbers whose mod-97 is valid so only the length
can reject them) and `HD doctor prints tokens unmasked` (the masking and the DLP net over the output). Earlier, mid-run, one
batch was cut off by my own tool timeout with a mutated `doctor.js` left on disk; I restored it with `git checkout` and re-ran
the two mutations that had not finished.

## Decisions

- DLP returns the text to send instead of mutating in place, so a store that ignores the return value is caught by a test
  per backend (`HD DLP SQLite/Slack/Supabase ... unredacted`).
- Detectors are precise, not broad: checksum + issuer for cards, checksum + length for IBANs, decoded header for JWTs.
  The cost is false negatives (below), which I judged better than a gate that cries wolf and gets set to `off`.
- Default is `block`, per the brief. In `redact` mode the sender is told; the recipient only sees the placeholder.
- The server only *warns* about a missing `NODE_USE_ENV_PROXY`; it does not enable env-proxy itself, as briefed. Node 22.21+
  has `http.setGlobalProxyFromEnv()` that could do it at runtime; not used (it would also change behaviour for people who set
  a proxy for other tools in the same shell).
- The server's proxy warning is skipped for SQLite: no network, no need.
- Group-readable token files are a WARN, world-readable a FAIL (the brief said "not world-readable").
- `doctor` reachability for Slack uses `auth.test` and `conversations.members` (membership) only; missing scopes are
  reported when a call fails, not by inspecting the token's scopes.

## Open issues and known false negatives

- DLP is a **client-side** control. Anyone with an agent token can call the Supabase RPC directly, or post to Slack as the
  bot, and skip it. Server-side enforcement would need a check in `bridge_send` (not possible for card/IBAN checksums in
  plain SQL without writing them there too) or a gateway. Also not scanned: messages typed by humans in the Slack channel,
  and everything `get_thread` / `check_inbox` returns (inbound).
- False negatives by design: IBANs in lower case or with other separators; cards with separators other than one space or
  dash, or split over lines; card numbers stuck to letters/hyphens/underscores; all-letter passwords (`password = correcthorse`
  unquoted; quoted all-lowercase too); `Authorization: Bearer ...` with an opaque token; Azure/other cloud key formats not
  in the brief; base64/hex-encoded secrets; a secret split across two messages.
- Residual false positive: an unquoted `token = refreshToken2` style identifier containing a digit and no call/index/`;`,
  and any Luhn-valid number that happens to start with a card prefix (about 1 in 10 of arbitrary 16-digit numbers starting
  with 4 or 51-55; order numbers are the usual source).
- Proxy: only basic credentials in the proxy URL (stored in plain text in the generated files); NTLM/Kerberos proxies need a
  local helper (cntlm, px). `ALL_PROXY` and SOCKS are not supported by Node's env proxy. PAC files are not supported.
- Node 24.0-24.4: `fetch()` supports the env proxy per the docs, `node:http` does not; this project only uses `fetch()`.
- The "active" detection trusts `NODE_USE_ENV_PROXY=1` / `--use-env-proxy` plus the version; it cannot observe Node's internal
  state. The tests prove the actual behaviour on this Node.
- `doctor` does not check the Supabase migration version beyond "function not found", and its SQLite write test does not
  perform a real insert. The probe has a 45 s ceiling. Windows file permissions are not checked (reported as a WARN).
- This container's harness change (stripping `SLACK_*` and proxy variables in `cleanEnv`) applies to all suites.
- The worktree was created from a commit that predated `agent-bridge/`; it was fast-forwarded to `b87e49c` before any work.
