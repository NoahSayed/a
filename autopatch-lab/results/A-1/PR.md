## Security update

### minimist 1.2.5 → 1.2.6 
- **Lane:** fast-track (critical and reachable from app code). Auto-merge eligible: yes
- [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h) CVE-2021-44906 — Prototype Pollution in minimist (critical, CVSS 9.8). KEV: no. EPSS: n/a. Reachable: yes
- **Result:** bumped, tests pass

### lodash 4.17.20 → 4.18.0 
- **Lane:** patch-now (high and reachable from app code). Auto-merge eligible: yes
- [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) CVE-2021-23337 — Command Injection in lodash (high, CVSS 7.2). KEV: no. EPSS: n/a. Reachable: yes
- [GHSA-29mw-wpgm-hmr9](https://github.com/advisories/GHSA-29mw-wpgm-hmr9) CVE-2020-28500 — Regular Expression Denial of Service (ReDoS) in lodash (moderate, CVSS 5.3). KEV: no. EPSS: n/a. Reachable: no (advisory names toNumber, trim, trimEnd; app calls none of them)
- [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) CVE-2026-4800 — lodash vulnerable to Code Injection via `_.template` imports key names (high, CVSS 8.1). KEV: no. EPSS: n/a. Reachable: no (advisory names template, assignInWith, assignWith; app calls none of them)
- [GHSA-xxjr-mmjv-4gpg](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg) CVE-2025-13465 — Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions (moderate, CVSS 6.5). KEV: no. EPSS: n/a. Reachable: no (advisory names unset, omit, pullAt; app calls none of them)
- **Result:** bumped, tests pass

### marked 2.0.0 → 4.0.10 (major)
- **Lane:** patch-now (high and reachable from app code). Auto-merge eligible: no
- [GHSA-rrrm-qjm4-v8hf](https://github.com/advisories/GHSA-rrrm-qjm4-v8hf) CVE-2022-21680 — Inefficient Regular Expression Complexity in marked (high, CVSS 7.5). KEV: no. EPSS: n/a. Reachable: yes
- [GHSA-5v2h-r2cx-5xgj](https://github.com/advisories/GHSA-5v2h-r2cx-5xgj) CVE-2022-21681 — Inefficient Regular Expression Complexity in marked (high, CVSS 7.5). KEV: no. EPSS: n/a. Reachable: yes
- **Result:** needs human: bump breaks tests

### Gate
- ✅ testsPass
- ✅ vulnsCleared
- ✅ onlyAllowedFilesChanged
- ✅ noDependencySetChange
- ✅ scriptsUnchanged

_Advisory text is treated as untrusted data. A human merges this PR._