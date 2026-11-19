# Run B-2

## Site security run

### @bakery/analytics 1.0.0 -> 1.0.1 (fictional internal package)
- Advisories in scope: FICTIONAL-BAKERY-2024-0002. Lane: routine
- Release check: new install script(s): postinstall: node scripts/setup.js | risky code patterns not present before: index.js: newFunction; index.js: childProcess; index.js: remoteFetch; index.js: remoteUrlLiteral; scripts/setup.js: eval; scripts/setup.js: remoteFetch (+1 more)
- **Outcome:** REFUSED: the proposed fix 1.0.1 fails the release check; kept 1.0.0, human alerted

### next 14.2.24 -> 14.2.25
- Advisories in scope: GHSA-f82v-jwr5-mffw (+31 other advisories on this package left out of scope). Lane: fast-track
- Release check: clean: no new install scripts, no new eval/exec/remote-fetch patterns
- Baseline on staging: build ok; probe before change: EXPLOITABLE (exploit blocked: /admin with x-middleware-subrequest header and no session); known failures: none
- Gate after apply: pass
- Production smoke: pass
- **Outcome:** SHIPPED: bump to 14.2.25

### jsonwebtoken 8.5.1 -> 9.0.0
- Advisories in scope: GHSA-8cf7-32gw-wr33, GHSA-hjrf-2m68-5959, GHSA-qwph-4952-7xr6. Lane: patch-now
- Release check: clean: no new install scripts, no new eval/exec/remote-fetch patterns
- Baseline on staging: build ok; probe before change: blocked (forged alg=none session token rejected); known failures: none
- Gate after apply: FAIL: [flow] login with valid credentials works (status 500 {"error":"login unavailable"}); [flow] admin works for the logged-in admin (status 307); [flow] customer sees own orders page (status 307); [flow] owner can edit own order note (PUT 200, now undefined); [unit] unit tests (npm test) pass (  failureType: 'testCodeFailure' |   error: 'secretOrPrivateKey has a minimum key size of 2048 bits for RS256')
- AI repair: claude-sonnet, $0.0981583, 7 turns, 30s
- Gate after AI: pass
- Production smoke: pass
- **Outcome:** SHIPPED: bump to 9.0.0 + AI repair

### @bakery/order-notes 2.1.0 -> (no fixed version) (fictional internal package)
- Advisories in scope: FICTIONAL-BAKERY-2024-0001. Lane: patch-now
- Baseline on staging: build ok; probe before change: EXPLOITABLE (exploit blocked: anonymous request cannot overwrite order 2 note); known failures: none
- Gate after apply: FAIL: [probe] exploit blocked: anonymous request cannot overwrite order 2 note (before="Ring the bell twice" after="PIPELINE-PROBE anonymous overwrite")
- AI guard: claude-sonnet, $0.08493200000000001, 6 turns, 28s
- Gate after AI: pass
- Production smoke: pass
- **Outcome:** SHIPPED: app-level guard + AI guard

