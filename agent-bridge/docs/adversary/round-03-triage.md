# Round 3 triage

Round 3 was run by a fresh-context agent against commit `6804043`, in a separate clean checkout. It covered DLP, proxy and
TLS handling, `doctor`, managed installs, and the round-2 fixes. Findings: [round-03.md](round-03.md), **19, all confirmed
by running them**: 0 critical, 2 high, 7 medium, 10 low.

The user asked to stop at about 60% of their session usage. So this round fixed the **two high findings** (with
fail-first tests and mutations) and records the rest here as open work, in priority order.

## Fixed

| id | severity | fix | test | mutations |
|---|---|---|---|---|
| R3-01 | high | The DLP assignment scanner reads each value at most 512 characters, so a body of repeated `token=` can't make the scan quadratic. A 50,000-character adversarial body took 3,083 ms before the fix and takes about 40 ms after it; the relay could be stalled with such bodies. Long quoted secrets are still judged by their first 512 characters | `test/regressions-r3.js`: four adversarial bodies under 300 ms; real assignments, including long quoted values, still found | value read to the end of the text |
| R3-04 | high | `doctor <repo>` takes only bridge settings from the repo's `.mcp.json` (an allowlist; `NODE_OPTIONS` and anything else are ignored and reported). It doesn't run the network check, which sends the agent's token, unless `--probe` is given. It prints the host it would contact | hostile `.mcp.json` with `NODE_OPTIONS=--require` and an attacker URL: no code runs (with or without `--probe`), no token is sent without `--probe`, and a local-mailbox repo is still fully checked | every variable taken; probe without `--probe` |

Fail-first: on commit `80dccd3` the round-3 suite scored 2 of 5. The two passes are the "still works" guards, which
should pass before and after. Now it scores 5 of 5.

## Open (prioritised)

| id | severity | what's left |
|---|---|---|
| R3-02, R3-19, R3-13, R3-14 | medium/low | DLP gaps. Redact mode lets the body of an escaped or truncated key through. Values that start with placeholder-looking words get through, and so do backtick quoting, `--password X`, `-pX`, `sk-ant-` keys, passwords inside connection URLs, Bearer headers, a few card and IBAN ranges, zero-width and full-width tricks, and secrets split between subject and body. DLP is pattern-based; treat it as a safety net, not a guarantee |
| R3-06 | medium | Managed installs: different folder spellings can collapse to one agent name, and an inherited `AGENT_NAME` or `AGENT_BRIDGE_PROJECT_DIR` picks that agent's token file. Path traversal through `{agent}` is not possible |
| R3-07 | medium | `managed-config` and `doctor` accept a legacy `service_role` JWT as the publishable key, and they copy URL or proxy userinfo into the managed file |
| R3-10 | medium | `doctor` has no relay-specific checks |
| R3-16 | medium | With `RELAY_AUDIT_REQUIRED`, a failed audit write *after* an admin rotate or delete reports 503, but the change already happened |
| R3-03, R3-05, R3-08, R3-09, R3-11, R3-12, R3-15, R3-17, R3-18 | low | A redacted subject can exceed 200 characters. Proxy credentials aren't always masked (a password containing `@`, a user-only URL). Spraying many source addresses defeats the audit limiter. There's no per-address share of the connection cap. The mTLS client ignores the proxy. CR, U+2028 and U+0085 aren't treated as line breaks by the `\| ` body prefix. DLP false positives. `managed-config` writes `~/` paths for the relay's TLS files. The relay's DLP mode isn't in its posture line |

## What the trend says

| Round | Critical | High | Medium | Low |
|---|---|---|---|---|
| 1 | 0 | 2 | 4 | 9 |
| 2 | 0 | 0 | 5 | 10 |
| 3 (new code: DLP, proxy, doctor, managed) | 0 | 2 | 7 | 10 |

Both round-3 highs were in code written after round 2 and never attacked before. The parts that had been attacked held up:
`assertSecureUrl`, the `peek --set` allowlist, the re-exec guard, forged `chain.repair` entries, strict booleans, export
timestamps, Slack sender limits, and `{agent}` traversal. Code that has been through a round gets more solid; fresh code
needs its own round. The next round, if there is one, should start with the DLP gaps above.
