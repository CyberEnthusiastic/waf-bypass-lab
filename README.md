# 🛡️ WAF Bypass Lab

> **Defensive WAF coverage assessment — replay 95+ OWASP Top 10 attack payloads against your WAF and measure how many it actually blocks.**
> A free, self-hosted alternative to commercial WAF assessment tools like GoTestWAF Pro, WAFBench, and Rapid7 tCell for security teams that want to validate Akamai, Fastly NG-WAF, Cloudflare, AWS WAF, and Imperva without a five-figure license.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Defensive](https://img.shields.io/badge/use-DEFENSIVE%20ONLY-critical)](#-authorized-use-only)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20covered-A14241)](https://owasp.org/Top10/)

---

## ⚠️ Authorized use only

This is a **defensive** security tool. You MUST have **explicit written authorization** from the target's owner before running it. The tool refuses to run without the `--i-am-authorized-to-test` flag.

Running this against systems you do not own is illegal in most jurisdictions (CFAA in the US, Article 8 of the EU Cybercrime Convention, etc.). The author disclaims all liability for misuse.

**Intended use cases:**
- Validate your own WAF's coverage before a PCI/SOC 2 audit
- Regression-test your WAF after a rule change
- Benchmark Akamai vs. Fastly vs. Cloudflare vs. AWS WAF before a migration
- CI/CD gate on staging environments owned by your team
- Authorized penetration testing engagements

---

## What it does (one screenshot of terminal output)

```
============================================================
   WAF BYPASS LAB  v1.0
   Defensive WAF coverage assessment
============================================================
[*] Loaded 95 payloads
[*] Target : http://127.0.0.1:8088
[*] Delay  : 200ms between requests

  [  1/95] BLOCKED  403   SQLI-001   Basic UNION SELECT
  [  2/95] BLOCKED  403   SQLI-002   OR 1=1 authentication bypass
  [  3/95] BLOCKED  403   SQLI-003   INFORMATION_SCHEMA enumeration
  ...
  [ 42/95] ALLOWED  200   XSS-012    Expression evasion (older IE)  <-- GAP!
  ...

============================================================
  Target coverage : 92.6%  (88/95 blocked)
  Blocked         : 88
  Allowed         : 7  <-- GAPS, investigate these
  Errors          : 0
============================================================

Coverage by category:
  SQL Injection                       18/18  100.0%
  Cross-Site Scripting                11/12   91.7%
  Log4Shell                           11/11  100.0%
  LFI / Path Traversal                13/13  100.0%
  Remote File Inclusion                6/6   100.0%
  Command Injection                   12/12  100.0%
  SSRF (cloud metadata)                9/9   100.0%
  Scanner / Attack Tool Detection     17/17  100.0%
  Web Protocol Attack                  1/7    14.3%
```

And a **dark-mode HTML report** with per-category coverage bars, a letter grade (A–F), and a clickable drill-down for every single payload showing the exact URL, response status, response body snippet, and CWE reference.

---

## Why you want this

| | **WAF Bypass Lab** | GoTestWAF | WAFBench | Burp Suite Pro + extensions |
|---|---|---|---|---|
| **Price** | Free (MIT) | Free (basic) / Paid Pro | Free | $449/yr + extensions |
| **Runtime deps** | **None** — pure stdlib | Go + Docker | Go | Java + JDK |
| **Install** | `git clone` | Docker pull + config | Compile from source | Installer + license key |
| **Payloads bundled** | 95+ OWASP Top 10 | ~500 | ~60 | Varies by extension |
| **CWE per payload** | Yes | No | No | Scanner-dependent |
| **Letter-grade report** | A–F with HTML | Console only | Console only | No |
| **CI/CD integration** | Built-in | Supported | Limited | Complex |
| **Offline / air-gapped** | Yes (mock_target.py) | Partial | Yes | No (licensing calls home) |
| **Authorization check** | Required flag | Informational | None | None |
| **Learn how it works** | Read 400 lines of Python | Read Go source | Read Go source | Closed source |

---

## 60-second quickstart

```bash
# 1. Clone
git clone https://github.com/CyberEnthusiastic/waf-bypass-lab.git
cd waf-bypass-lab

# 2. (Offline demo) start the bundled mock WAF target
python mock_target.py &

# 3. Run the lab against it
python waf_lab.py http://127.0.0.1:8088 --i-am-authorized-to-test

# 4. Open the HTML report
start reports/waf_report.html      # Windows
open  reports/waf_report.html      # Mac
xdg-open reports/waf_report.html   # Linux
```

### One-command installer

```bash
./install.sh       # Linux / macOS / WSL / Git Bash
.\install.ps1      # Windows PowerShell
```

### Docker

```bash
docker build -t waf-bypass-lab .
docker run --rm -v "$PWD/reports:/app/reports" waf-bypass-lab \
  waf_lab.py https://staging.your-company.com --i-am-authorized-to-test
```

---

## Open in VS Code (2 clicks)

```bash
code .
```

The repo ships with `.vscode/launch.json` with 4 debug profiles:

1. **Mock target run** — runs the mock WAF + the full test suite locally, zero network
2. **Dry run** — loads all payloads without sending requests (useful for validation)
3. **Custom target** — prompts for a URL and runs the full suite
4. **Single category** — prompts for a category and runs only those payloads

Plus `tasks.json` with one-click commands for: start mock target, list categories, open report.

---

## Payload library (95+ payloads across 9 categories)

| Category | Payloads | CWE | Source inspiration |
|----------|---------:|-----|----|
| SQL Injection | 18 | CWE-89 | OWASP + Akamai/Fastly prod tests |
| Cross-Site Scripting | 12 | CWE-79 | OWASP XSS cheatsheet |
| Log4Shell (CVE-2021-44228) | 11 | CWE-74 | Original CVE + huntress research |
| LFI / Path Traversal | 13 | CWE-22 | OWASP + PortSwigger research |
| Remote File Inclusion | 6 | CWE-98 | Modsecurity CRS rules |
| Command Injection | 12 | CWE-78 | OWASP cmd injection cheatsheet |
| SSRF (AWS/GCP cloud metadata) | 9 | CWE-918 | Cloud provider docs + Capital One postmortem |
| Scanner / Attack Tool UA | 17 | CWE-200 | Known scanner fingerprints |
| Web Protocol Attack | 7 | CWE-444 | Portswigger request smuggling research |

All payloads live in `payloads/*.json` and are fully declarative. Add new categories or payloads by dropping a new JSON file in.

### Payload schema

```json
{
  "category": "SQL Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "description": "...",
  "payloads": [
    {
      "id": "SQLI-001",
      "name": "Basic UNION SELECT",
      "method": "GET",
      "path": "/products",
      "query": "id=1' UNION SELECT * FROM users--",
      "severity": "HIGH",
      "expected": "block"
    },
    {
      "id": "SQLI-006",
      "name": "LOAD_FILE via POST body",
      "method": "POST",
      "path": "/api/wishlist",
      "body": {"filter": "1' AND LOAD_FILE('/etc/passwd') IS NOT NULL--"},
      "content_type": "application/json",
      "severity": "CRITICAL",
      "expected": "block"
    }
  ]
}
```

---

## How the WAF detector works

For each request sent, the lab records:
1. HTTP response status code
2. First 800 bytes of the response body
3. Latency in milliseconds

A request is marked **BLOCKED** if either:
- The status code is in `{403, 406, 409, 418, 429, 451, 503}`, **or**
- The response body contains any of these WAF signatures:
  - `Access Denied`
  - `AK_REFERENCE_ID` (Akamai)
  - `x-sigsci-agentresponse` (Fastly NG-WAF)
  - `Cloudflare Ray ID`
  - `Incapsula incident`
  - `403 Forbidden`
  - ...and 7 more (see `WAF_BLOCK_SIGNATURES` in `waf_lab.py`)

Otherwise it's **ALLOWED** — meaning the WAF let the attack through, which is either a genuine gap or a tuned false negative.

---

## CLI reference

```bash
python waf_lab.py TARGET_URL --i-am-authorized-to-test [options]

Options:
  -p, --payloads DIR       Path to payloads directory (default: payloads/)
  -c, --category CAT       Only run this category (repeat to combine)
  -n, --max-tests N        Cap total tests (useful for smoke tests)
  --delay-ms MS            Delay between requests in ms (default: 200)
  --timeout N              Per-request timeout in seconds (default: 10)
  --insecure               Skip TLS certificate verification
  -H, --header HEADER      Custom header to add (e.g. -H "X-Test: 1")
  --dry-run                Print plan without sending requests
  --list-categories        List available payload categories and exit
  -o, --output FILE        JSON output path (default: reports/waf_report.json)
  --html FILE              HTML output path (default: reports/waf_report.html)
```

### Examples

```bash
# Only test SQLi + XSS against staging
python waf_lab.py https://staging.myco.com \
  --i-am-authorized-to-test \
  -c "SQL Injection" \
  -c "Cross-Site Scripting"

# Smoke test: 10 payloads, fast, no TLS verification (internal staging)
python waf_lab.py https://internal-staging.myco.com \
  --i-am-authorized-to-test \
  --insecure \
  -n 10 \
  --delay-ms 50

# Dry run — validate payload files without sending anything
python waf_lab.py --dry-run --list-categories

# Add an auth header required by your staging env
python waf_lab.py https://staging.myco.com \
  --i-am-authorized-to-test \
  -H "X-Auth-Token: $STAGING_TOKEN"
```

---

## CI/CD integration — WAF regression guard

See `.github/workflows/waf-regression.yml`. Every PR that modifies WAF rules
runs the lab against a dedicated staging environment and fails if coverage
drops below 90%.

```yaml
- name: Run WAF Bypass Lab
  run: |
    python waf_lab.py https://staging.myco.com \
      --i-am-authorized-to-test \
      --timeout 15
- name: Fail if coverage below threshold
  run: |
    python -c "
    import json, sys
    r = json.load(open('reports/waf_report.json'))
    if r['summary']['coverage_percent'] < 90:
        print(f'Coverage dropped to {r[\"summary\"][\"coverage_percent\"]}%')
        sys.exit(1)
    "
```

---

## Architecture

```
waf-bypass-lab/
├── waf_lab.py              # main CLI + orchestrator (400 LoC)
├── report_generator.py     # HTML report generator
├── mock_target.py          # offline mock WAF for local demos
├── payloads/               # 9 JSON files, 95+ payloads
│   ├── sqli.json
│   ├── xss.json
│   ├── log4j.json
│   ├── lfi_traversal.json
│   ├── rfi.json
│   ├── cmdexe.json
│   ├── ssrf.json
│   ├── scanners.json
│   └── wpa.json
├── reports/                # output (gitignored)
├── .vscode/                # launch.json, tasks.json, extensions.json
├── .github/workflows/
│   └── waf-regression.yml  # CI regression guard
├── Dockerfile
├── install.sh / install.ps1
├── requirements.txt        # empty — pure stdlib
├── LICENSE                 # MIT
├── NOTICE                  # attribution
├── SECURITY.md             # vuln disclosure
└── CONTRIBUTING.md
```

---

## Roadmap

- [ ] HTTP/2 smuggling payloads
- [ ] GraphQL injection payloads
- [ ] gRPC payload support
- [ ] More scanners fingerprints (Nuclei, Checkmarx, etc.)
- [ ] Parallel request execution (with per-target rate limit)
- [ ] SARIF output
- [ ] Diff report: compare two runs (before vs after WAF rule change)

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Security

Responsible disclosure: see [SECURITY.md](./SECURITY.md).

## Contributing

PRs welcome — especially new payload categories. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

Built by **[Adithya Vasamsetti (CyberEnthusiastic)](https://github.com/CyberEnthusiastic)** as part of the [AI Security Projects](https://github.com/CyberEnthusiastic?tab=repositories) suite.
