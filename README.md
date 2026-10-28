# VulnScout

**A small, honest web vulnerability scanner — CLI + local web dashboard.**

VulnScout is a focused, dependency-light scanner for web applications. It crawls a target,
tests it for a handful of high-signal issues, and produces a clean HTML/JSON report. It is not
a replacement for Burp Suite or Nuclei; it is a good first pass and a readable codebase to
extend.

```text
$ vulnscout scan https://example.com --authorized

VulnScout
https://example.com/
Risk score: 42.3/100   Findings: 9
1 critical · 2 high · 3 medium · 2 low · 1 info
Requests: 61   Pages: 12   Duration: 8.4s
Report: ~/.vulnscout/scans/4f1c9a2d8b31.html
```

> ⚠️ **Authorized testing only.** You must own the target or have written permission.
> Unauthorized scanning is illegal in most jurisdictions.

---

## Features

| Module      | What it checks                                                                 |
| ----------- | ------------------------------------------------------------------------------ |
| `headers`   | Missing/weak CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, info leaks   |
| `cookies`   | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure`             |
| `cors`      | Reflected origin, wildcard + credentials, `null` origin                        |
| `jwt`       | `alg:none`, HMAC secret brute-force, missing/expired `exp`, injectable `kid`   |
| `xss`       | Reflected XSS in GET parameters                                                |
| `sqli`      | Error-based SQL injection (+ opt-in time-based)                                |
| `redirect`  | Open redirects in `next`, `url`, `return`, … parameters                        |
| `files`     | Exposed `.git`, `.env`, backups, `phpinfo`, Actuator, Swagger, …               |
| `tls`       | Certificate validity/expiry, TLS 1.0/1.1 support                               |
| `forms`     | POST forms without anti-CSRF tokens                                            |
| `tech`      | Technology fingerprinting and secrets in HTML comments                         |

* **Fast to run, easy to read** — ~2k lines of plain Python, no plugin magic.
* **Polite by default** — rate limiting, retries, capped crawl, conservative payloads.
* **Two outputs** — self-contained HTML report and machine-readable JSON.
* **Local dashboard** — browse scans, filter findings, launch new scans.
* **CI friendly** — `--fail-on high` exits non-zero, so it slots into a pipeline.

## Install

```bash
git clone https://github.com/YoussefCyber12/vulnscout.git
cd vulnscout
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -e .
```

Python 3.9+ is required. `pip install -e ".[dev]"` adds the test/lint tooling.

## Usage

```bash
# Scan a site (asks for authorization confirmation unless -y is passed)
vulnscout scan https://example.com

# Non-interactive / CI
vulnscout scan https://example.com --authorized --fail-on high

# Only run selected modules
vulnscout scan https://example.com -m jwt,headers,cors --authorized

# Write a specific report
vulnscout scan https://example.com --authorized -o reports/example.html

# Verbose findings (description + evidence + remediation)
vulnscout scan https://example.com --authorized --verbose

# List / inspect saved scans
vulnscout list
vulnscout show 4f1c9a2d8b31

# Start the dashboard
vulnscout dashboard --port 8000
```

### Options

| Flag                 | Default      | Description                                              |
| -------------------- | ------------ | -------------------------------------------------------- |
| `-y, --authorized`   | off          | Skip the interactive authorization prompt                |
| `-m, --modules`      | all          | Comma-separated module list (`vulnscout modules`)        |
| `--no-crawl`         | off          | Only test the given URL                                  |
| `--max-pages`        | `25`         | Crawl page limit                                         |
| `--max-depth`        | `2`          | Crawl depth                                              |
| `--timeout`          | `10`         | Request timeout (seconds)                                |
| `--delay`            | `0.15`       | Delay between requests (seconds)                         |
| `--insecure`         | off          | Disable TLS verification                                 |
| `--time-based`       | off          | Enable slow time-based SQLi checks                       |
| `--proxy`            | –            | Route traffic through a proxy (e.g. Burp at `:8080`)     |
| `-H, --header`       | –            | Extra request header, repeatable                         |
| `-o, --output`       | –            | Report path (`.html` or `.json`)                         |
| `--json`             | off          | Print JSON to stdout                                     |
| `-v, --verbose`      | off          | Print description, evidence and remediation per finding  |
| `--fail-on`          | `none`       | Exit 1 on findings at/above `low\|medium\|high\|critical` |
| `-q, --quiet`        | off          | No progress output                                       |
| `--data-dir`         | `~/.vulnscout` | Where scans are stored                                 |

### Try it locally

The repo ships a deliberately vulnerable demo app, so you can see the scanner in action without
touching a real target:

```bash
# terminal 1
python examples/vulnerable_app.py

# terminal 2
vulnscout scan http://127.0.0.1:8080 --authorized -o demo-report.html
```

The demo server is intentionally insecure and must never be exposed to a network.

## Dashboard

```bash
vulnscout dashboard
# open http://127.0.0.1:8000
```

The dashboard is a **local** tool: it stores results on disk and has **no authentication**.
It binds to `127.0.0.1` by default — do not expose it to the internet.

API endpoints:

```text
GET    /api/scans              list saved scans
GET    /api/scans/{id}         full scan JSON
DELETE /api/scans/{id}         delete a scan
GET    /api/modules            available modules
POST   /api/scan               start a scan  {"target": "...", "authorized": true}
GET    /api/jobs/{job_id}      scan progress
GET    /docs                   OpenAPI UI
```

## Project layout

```text
vulnscout/
├── cli.py                 # argparse + rich CLI
├── config.py              # severity weights, defaults
├── core/
│   ├── http.py            # throttled requests session
│   ├── crawler.py         # stdlib HTML crawler (links + forms)
│   ├── models.py          # Finding / ScanResult
│   ├── scanner.py         # orchestration
│   ├── report.py          # HTML/JSON rendering
│   ├── storage.py         # JSON-per-scan storage
│   └── utils.py           # URL helpers + SQL error signatures
├── modules/               # one file per check
└── web/                   # FastAPI dashboard + Jinja templates
tests/                     # local deliberately-vulnerable test server
```

Adding a module is intentionally boring:

```python
# vulnscout/modules/example.py
from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding


class ExampleModule:
    name = "example"
    description = "What this module checks"

    def run(self, ctx: ScanContext) -> list[Finding]:
        response = ctx.client.get(ctx.base_url)
        if response and "X-Debug" in response.headers:
            return [Finding(
                name="Debug header enabled",
                severity="low",
                url=response.url,
                module=self.name,
                description="...",
            )]
        return []
```

Register it in `vulnscout/modules/__init__.py` and, if it should run by default, add it to
`DEFAULT_MODULES`.

## Development

```bash
pip install -e ".[dev]"
pytest                 # runs against a local in-process test server
ruff check .
```

The test suite spins up a deliberately vulnerable HTTP server on `127.0.0.1` — no external
network access is required.

## Roadmap

- [ ] JS-aware crawling (headless browser) and SPA support
- [ ] POST parameter and JSON body testing
- [ ] Blind SSRF / XXE / SSTI checks
- [ ] Wordlist-based content discovery
- [ ] SARIF output for GitHub code scanning
- [ ] Scan comparison / diffing between runs

## Disclaimer

VulnScout is provided for **authorized security testing and education**. The authors accept no
liability for misuse or damage caused by this tool. The scanner sends active payloads; some
checks can create noise or trigger WAFs. Always get written permission first.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in VulnScout itself.

## License

MIT — see [LICENSE](LICENSE).

---

## بالعربية

**VulnScout** أداة فحص ثغرات ويب مكتوبة بـ Python، بواجهة سطر أوامر ولوحة تحكم محلية.

```bash
vulnscout scan https://example.com --authorized
vulnscout dashboard
```

تفحص: ترويسات الأمان، الكوكيز، CORS، ثغرات JWT، XSS المنعكس، SQLi، التحويل المفتوح،
ملفات حساسة مكشوفة، شهادات TLS، ونماذج بدون CSRF.

⚠️ **استعملها فقط على أنظمة تملكها أو لديك إذن كتابي بفحصها.**
