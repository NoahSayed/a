# Round 3 triage

Round 3 was run by a fresh-context agent against commit `6804043`, in a separate clean checkout. It covered DLP, proxy and
TLS handling, `doctor`, managed installs, and the round-2 fixes. Findings: [round-03.md](round-03.md), **19, all confirmed
by running them**: 0 critical, 2 high, 7 medium, 10 low.

The two high findings were fixed in the round itself; the other 17 were left open and **fixed in a later pass**, in
three groups that touch different code (DLP; client config, managed installs, doctor and proxy; relay server and message
display). Every finding has fail-first tests and mutations.

## Fixed in the round

| id | severity | fix | test | mutations |
|---|---|---|---|---|
| R3-01 | high | The DLP assignment scanner reads each value at most 512 characters, so a body of repeated `token=` can't make the scan quadratic. A 50,000-character adversarial body took 3,083 ms before the fix and takes about 40 ms after it; the relay could be stalled with such bodies. Long quoted secrets are still judged by their first 512 characters | `test/regressions-r3.js`: four adversarial bodies under 300 ms; real assignments, including long quoted values, still found | value read to the end of the text |
| R3-04 | high | `doctor <repo>` takes only bridge settings from the repo's `.mcp.json` (an allowlist; `NODE_OPTIONS` and anything else are ignored and reported). It doesn't run the network check, which sends the agent's token, unless `--probe` is given. It prints the host it would contact | hostile `.mcp.json` with `NODE_OPTIONS=--require` and an attacker URL: no code runs (with or without `--probe`), no token is sent without `--probe`, and a local-mailbox repo is still fully checked | every variable taken; probe without `--probe` |

Fail-first: on commit `80dccd3` the round-3 suite scored 2 of 5. The two passes are the "still works" guards, which
should pass before and after. Now it scores 5 of 5.

## Fixed later

Tests: `test/regressions-r3-dlp.js` (**9/24 on the attacked code**, all 9 "still works" guards; **25/25 now**),
`test/regressions-r3-config.js` (**4/37 → 37/37**), `test/regressions-r3-relay.js` (**3/25 → 26/26**). Mutations:
`test/mutations-r3-dlp.js`, `test/mutations-r3-config.js`, `test/mutations-r3-relay.js`, one or more per guard.

| id | severity | fix |
|---|---|---|
| R3-02 | medium | The private-key detector reads the key body (real newlines or escaped `\n`, `\r\n`, `%0A`), with no length cap, through the END marker or to the end of the base64 when the key is cut short; `Proc-Type`/`DEK-Info` and PuTTY keys too |
| R3-13 | medium | More card ranges (Maestro, Mir, Dankort, Elo, Troy, Uzcard/Humo, more JCB and UnionPay, 19-digit Visa/Mastercard), about 40 more IBAN countries, and Anthropic, OpenAI, GitLab, npm, SendGrid, Slack webhook, Azure, Google OAuth, Twilio and Stripe webhook secrets. Passwords in `scheme://user:pass@host` and `Authorization: Bearer/Basic/Token` headers; only the secret part is redacted |
| R3-19 | medium | The assignment heuristic catches values starting with `$` (but `$VAR`, `${VAR}`, `$(cmd)` stay references), placeholders only when the whole value is one (`fake-Xk39sLq02mZ!` is caught), backticks, JSON-escaped quotes, `--password X`, `--db-token X`, `sshpass -p X`, `-pX`, and the keys `pwd`, `pass`, `passphrase`, `credentials` |
| R3-14 | low | Scanning runs on a normalised view (NFKC; zero-width, format and combining characters dropped; every Unicode digit read as 0-9), mapped back so redaction removes exactly what was sent. Cards in any grouping with one or two separators; IBANs in any case and grouping; subject and body also scanned as one text |
| R3-15 | low | Fewer false positives: a bare BEGIN line in prose, digit-only values after non-password keys, paths and snake_case identifiers, numbers right after an id/ts/time key, all-digit UUIDs (thread ids). A grouped card number is always checked |
| R3-03 | low | A redacted subject is cut to 200 characters with "…", never inside a `[REDACTED:...]` marker, and the agent is told |
| R3-05 | low | Proxy credentials are masked with URL parsing (an `@` in the password, a user-only token URL). A credentialed proxy URL is no longer written into the hook command; the hook uses the `HTTPS_PROXY` it inherits, and `init` says so. `peek`'s re-run passes proxy and CA values in its environment, not its arguments |
| R3-06 | medium | With `AGENT_BRIDGE_NAME_FROM=project` the folder name must already be a valid agent name (capitals are lower-cased; nothing else is cleaned up, so two spellings can't collapse into one agent). An `AGENT_NAME` that differs from the folder, and a relative project-dir variable, are refused |
| R3-07 | medium | `managed-config`, `init` and `doctor` refuse a service_role JWT (round 4's `isSecretSupabaseKey`) and refuse user:pass@ in `SUPABASE_URL`, `RELAY_URL` and `SLACK_API_URL`; `managed-config` also refuses a token-only proxy URL |
| R3-10 | medium | `doctor` checks the relay: `RELAY_URL` (missing, userinfo, https), the token (present, shape, file mode), the `RELAY_TLS_*` files (exist, PEM, cert with key, private key not readable by others), and a `bridge_whoami` probe through the same TLS and proxy code the server uses |
| R3-11 | low | The relay client's TLS fetch tunnels through `HTTPS_PROXY` (CONNECT, `Proxy-Authorization` from the URL, `NO_PROXY` honoured) when `NODE_USE_ENV_PROXY=1`, the same rule as `fetch()` |
| R3-17 | low | `~` is expanded in `RELAY_TLS_*` paths, and the error names the variable and the file |
| R3-08 | low | The auth-failure audit limiter has no shared "(many)" bucket: a new source always gets its own entry, and when the table is full the oldest entry is evicted with its own summary line. A spray of 10,500 addresses no longer hides a later attacker |
| R3-09 | low | `RELAY_MAX_CONNECTIONS_PER_IP` (default 32; IPv6 per /64): one address can't take every connection. Shown in the startup line |
| R3-12 | low | CR, VT, FF, U+0085, U+2028, U+2029 and FS/GS/RS are line breaks for the `\| ` body prefix (CRLF stays one break); subjects with them are refused on send and flattened when shown; `log`/`tail` output too |
| R3-16 | medium | When an admin change was applied but its outcome line couldn't be written, the relay answers `AB001` "the change was applied ... do not repeat the request", with the result (a new token is not lost). A failed intent line is still a refusal and nothing changes |
| R3-18 | low | The relay's own DLP mode is `RELAY_DLP` (default `block`), validated at startup and shown in its posture line. The relay ignores `AGENT_BRIDGE_DLP` and says so |

### Behaviour changes

- A managed install whose project folder isn't a valid agent name (spaces, punctuation, over 40 characters) now refuses
  to start: rename the folder or give that project its own `init` entry.
- URLs with `user:pass@` are refused by `init` and `managed-config`, and are a FAIL in `doctor`.
- The relay reads `RELAY_DLP`, not `AGENT_BRIDGE_DLP`.
- Subjects containing unusual line breaks (VT, FF, U+2028 ...) are refused.

### What is left

- DLP is pattern-based. Still not caught: a bare password with no label or known prefix, a 40-character AWS secret
  without an `aws ... secret` label, base64 of a card, a key body pasted without its BEGIN line, `-p123456` (reads like a
  port), curl `-u user:pass`, credentials in vendor formats it doesn't know, and a contiguous card number written right
  after `id:` (read as an id).
- R3-06: an absolute `AGENT_BRIDGE_PROJECT_DIR` placed in the server's own environment still chooses the agent (Cursor
  needs that variable); `Billing` and `billing` are one agent.
- R3-16: the admin change and its audit line aren't one transaction; the answer is now truthful instead.

## What the trend says

| Round | Critical | High | Medium | Low |
|---|---|---|---|---|
| 1 | 0 | 2 | 4 | 9 |
| 2 | 0 | 0 | 5 | 10 |
| 3 (new code: DLP, proxy, doctor, managed) | 0 | 2 | 7 | 10 |
| 4 (new code: Cursor, Codex, skill) | 0 | 0 | 5 | 8 |

Both round-3 highs were in code written after round 2 and never attacked before. The parts that had been attacked held up:
`assertSecureUrl`, the `peek --set` allowlist, the re-exec guard, forged `chain.repair` entries, strict booleans, export
timestamps, Slack sender limits, and `{agent}` traversal. Code that has been through a round gets more solid; fresh code
needs its own round. All 19 round-3 findings are now fixed; the next round should attack this new code (the DLP rewrite, the relay's CONNECT tunnel, the new doctor relay checks) first.
