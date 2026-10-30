# AtlasScan

[![CI](https://github.com/YoussefCyber12/atlasscan/actions/workflows/ci.yml/badge.svg)](https://github.com/YoussefCyber12/atlasscan/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A small, honest web vulnerability scanner — CLI + local web dashboard.**

AtlasScan is a focused, dependency-light scanner for web applications. It crawls a target,
tests it for a handful of high-signal issues, and produces a clean HTML/JSON report. It is not
a replacement for Burp Suite or Nuclei; it is a good first pass and a readable codebase to
extend.

```text
$ atlasscan scan https://example.com --authorized

AtlasScan
https://example.com/
Risk score: 42.3/100   Findings: 9
1 critical · 2 high · 3 medium · 2 low · 1 info
Requests: 61   Pages: 12/25   Duration: 8.4s
Coverage: 18 parameter(s) found, 18 tested · 4 form(s)
Report: ~/.atlasscan/scans/4f1c9a2d8b31.html
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
| `xss`       | Reflected XSS in GET parameters, POST forms and JSON bodies                    |
| `sqli`      | Error-based SQLi (incl. POST/JSON, opt-in time-based)                          |
| `redirect`  | Open redirects in `next`, `url`, `return`, … parameters                        |
| `files`     | Exposed `.git`, `.env`, backups, `phpinfo`, Actuator, Swagger, …               |
| `tls`       | Certificate validity/expiry, TLS 1.0/1.1 support                               |
| `forms`     | POST forms without anti-CSRF tokens                                            |
| `methods`   | Dangerous methods (`PUT`/`DELETE`/`PATCH`) and TRACE/XST                      |
| `tech`      | Technology fingerprinting and secrets in HTML comments                         |

* **Fast to run, easy to read** — ~2k lines of plain Python, no plugin magic.
* **Polite by default** — rate limiting, retries, capped crawl, conservative payloads.
* **Three outputs** — self-contained HTML, machine-readable JSON and SARIF 2.1.0.
* **Local dashboard** — browse scans, filter findings, launch new scans.
* **CI friendly** — `--fail-on high`, `--baseline` for "only new issues", SARIF upload.

## Install

**Option A — one command (no clone)**

```bash
pip install git+https://github.com/YoussefCyber12/atlasscan.git
atlasscan --help
```

**Option B — clone + editable install (recommended for development)**

```bash
git clone https://github.com/YoussefCyber12/atlasscan.git
cd atlasscan                     # <- repository root
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
atlasscan --help
```

Python 3.9+ is required. `pip install -e ".[dev]"` adds the test/lint tooling.

### ⚠️ Run pip from the repository root

`pip install -e .` must run in the folder that contains `pyproject.toml`:

```text
atlasscan/            <- repository root: run pip HERE (pyproject.toml lives here)
├── pyproject.toml
├── README.md
├── atlasscan/        <- Python package: do NOT run pip here
│   ├── cli.py
│   └── ...
├── tests/
└── examples/
```

A very common mistake is cloning and then `cd atlasscan` twice. If you see:

```text
ERROR: file:///home/you/atlasscan/atlasscan does not appear to be a Python project:
neither 'setup.py' nor 'pyproject.toml' found
```

you are one level too deep. Fix it with:

```bash
cd ..                 # or: cd ~/atlasscan
ls pyproject.toml     # this must exist
pip install -e .
```

### Verify the install

```bash
which atlasscan       # should point inside your virtualenv
atlasscan modules     # lists all 12 modules
```

### Update / uninstall

```bash
# update
cd atlasscan && git pull && pip install -e .

# remove
pip uninstall atlasscan
```

## Usage

```bash
# Scan a site (asks for authorization confirmation unless -y is passed)
atlasscan scan https://example.com

# Non-interactive / CI
atlasscan scan https://example.com --authorized --fail-on high

# Only run selected modules
atlasscan scan https://example.com -m jwt,headers,cors --authorized

# Write a specific report (HTML, JSON or SARIF by extension)
atlasscan scan https://example.com --authorized -o reports/example.html
atlasscan scan https://example.com --authorized -o reports/example.sarif

# Only report findings that are new since the previous scan
atlasscan scan https://example.com --authorized \
  --baseline reports/example.json --fail-on high -o reports/example.html

# Scan behind a login with a session cookie
atlasscan scan https://app.example.com/dashboard --authorized \
  --cookie "session=abc123; csrf=xyz" -o reports/private.html

# Actively test discovered POST forms
atlasscan scan https://example.com --authorized --post-forms

# Fuzz a JSON API body (one FUZZ marker per value to test)
atlasscan scan https://api.example.com/search --authorized \
  --data '{"q":"FUZZ","limit":10}' -o reports/api.html

# Verbose findings (description + evidence + remediation)
atlasscan scan https://example.com --authorized --verbose

# List / inspect saved scans
atlasscan list
atlasscan show 4f1c9a2d8b31

# Start the dashboard
atlasscan dashboard --port 8000
```

### Options

| Flag                 | Default      | Description                                              |
| -------------------- | ------------ | -------------------------------------------------------- |
| `-y, --authorized`   | off          | Skip the interactive authorization prompt                |
| `-m, --modules`      | all          | Comma-separated module list (`atlasscan modules`)        |
| `--no-crawl`         | off          | Only test the given URL                                  |
| `--max-pages`        | `25`         | Crawl page limit                                         |
| `--max-depth`        | `2`          | Crawl depth                                              |
| `--timeout`          | `10`         | Request timeout (seconds)                                |
| `--delay`            | `0.15`       | Delay between requests (seconds)                         |
| `--insecure`         | off          | Disable TLS verification                                 |
| `--time-based`       | off          | Enable slow time-based SQLi checks                       |
| `--post-forms`       | off          | Actively test POST forms (skips login/delete/payment)    |
| `--data`             | –            | Body template with `FUZZ` markers, or `@file`             |
| `--content-type`     | auto         | Content-Type for `--data` (JSON auto-detected)            |
| `--proxy`            | –            | Route traffic through a proxy (e.g. Burp at `:8080`)     |
| `--cookie`           | –            | Session cookies: `name=value; name2=value2`              |
| `--cookie-jar`       | –            | Netscape `cookies.txt` or JSON cookie export file        |
| `-H, --header`       | –            | Extra request header, repeatable                         |
| `-o, --output`       | –            | Report path (`.html`, `.json` or `.sarif`)               |
| `--baseline`         | –            | JSON report or scan id; only new findings are reported   |
| `--json`             | off          | Print JSON to stdout                                     |
| `-v, --verbose`      | off          | Print description, evidence and remediation per finding  |
| `--fail-on`          | `none`       | Exit 1 on findings at/above `low\|medium\|high\|critical` |
| `-q, --quiet`        | off          | No progress output                                       |
| `--data-dir`         | `~/.atlasscan` | Where scans are stored                                 |

### Scanning behind a login

Most of an application lives behind authentication. AtlasScan does **not** automate login forms
(that would mean handling your credentials and invite account lockouts); instead you give it a
session cookie, and every crawl and module request reuses that session.

1. Log in to the target with a **dedicated test account** that has the least privilege needed.
2. Copy the session cookie from your browser: DevTools → **Application → Cookies** → the
   cookie name/value (or copy the whole `Cookie:` request header from the Network tab).
3. Pass it to the scanner:

```bash
# Inline, straight from the Cookie header
atlasscan scan https://app.example.com/dashboard --authorized \
  --cookie "session=abc123; csrf=xyz"

# Or load a cookie file (Netscape cookies.txt, or a JSON export from
# Playwright / a browser extension)
atlasscan scan https://app.example.com/dashboard --authorized \
  --cookie-jar ./cookies.txt --fail-on high -o reports/private.html
```

JSON cookie files may be a bare list or a Playwright storage-state object:

```json
{"cookies": [{"name": "session", "value": "abc123", "domain": "app.example.com", "path": "/"}]}
```

Things to keep in mind:

- **Start the scan on an authenticated URL** (e.g. `/dashboard`), not the login page.
- **Cookies expire.** If the start page still looks like a login screen, AtlasScan adds a
  coverage warning instead of reporting a false "clean" result.
- **Use one session per scan**, and log out / rotate the token when you are done.
- You can combine this with `--proxy http://127.0.0.1:8080` to review the traffic in Burp.
- Only ever do this on accounts and systems you are authorized to test.

### Testing POST forms and JSON APIs

GET parameters are only half of an application. `--post-forms` makes the `xss` and `sqli`
modules submit payloads to forms discovered during the crawl, and `--data` does the same for a
request body you provide.

```bash
# Discovered forms: hidden/CSRF default values are reused, each field is tested in turn
atlasscan scan https://example.com --authorized --post-forms

# JSON API: every FUZZ inside a JSON string becomes an injection point
atlasscan scan https://api.example.com/search --authorized \
  --data '{"q":"FUZZ","filters":{"category":"FUZZ"}}' \
  --cookie "session=abc" -o reports/api.html

# Form-encoded body or a body saved in a file
atlasscan scan https://example.com/search --authorized --data "q=FUZZ&page=1"
atlasscan scan https://example.com/search --authorized --data @body.json
```

> Active POST testing sends real payloads and may create data. Only use it on a test account or
> staging environment you are authorized to modify.

Safety rules built into the scanner:

- `--post-forms` is **off by default**; nothing is submitted unless you ask for it.
- Forms with password fields, and actions that look like login/signup/delete/payment/checkout,
  are skipped so testing cannot lock accounts out or destroy data.
- One `FUZZ` marker is injected at a time; the other markers get a harmless value.
- JSON templates are handled structurally, so payload quotes are escaped and the body stays
  valid JSON.
- `--max-params` caps how many fields/markers are tested in total.
- Payloads for error-based SQLi are the same conservative quote characters used for GET;
  `--time-based` still applies to GET parameters only.
- Only send `--data` bodies you are allowed to test: they hit the exact URL you scanned.

### Try it locally

The repo ships a deliberately vulnerable demo app, so you can see the scanner in action without
touching a real target:

```bash
# terminal 1
python examples/vulnerable_app.py

# terminal 2
atlasscan scan http://127.0.0.1:8080 --authorized -o demo-report.html
```

The demo server is intentionally insecure and must never be exposed to a network.

## CI and automation

### Only fail on new issues (baseline)

```bash
# First run: save a baseline
atlasscan scan https://staging.example.com --authorized -o baseline.json

# Later runs: report and fail only on findings that are new since the baseline
atlasscan scan https://staging.example.com --authorized \
  --baseline baseline.json --fail-on high -o reports/latest.html
```

Findings are matched by module + name + URL, so line/order changes do not resurrect them.
`--fail-on` evaluates only the reported (new) findings, and the HTML report shows a
"Baseline applied" panel with the count of hidden findings. Passing a saved scan id works too:
`--baseline 4f1c9a2d8b31`.

### GitHub code scanning (SARIF)

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - run: pip install git+https://github.com/YoussefCyber12/atlasscan.git
  - name: Scan
    run: atlasscan scan https://staging.example.com --authorized --fail-on high -o atlasscan.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: atlasscan.sarif
```

The SARIF output maps severities to `error`/`warning`/`note`, sets `security-severity` for
GitHub's ranking, and uses stable partial fingerprints so results do not duplicate between runs.

### Docker

```bash
docker build -t atlasscan .
docker run --rm atlasscan scan https://example.com --authorized

# keep reports on the host
docker run --rm -v "$PWD/reports:/home/atlasscan/.atlasscan" \
  atlasscan scan https://example.com --authorized -o /home/atlasscan/.atlasscan/report.html
```

Inside the container `127.0.0.1` is the container itself; use `--network host` (Linux) or
`host.docker.internal` (Docker Desktop) to reach a service on your machine.

## Reading the report

### Coverage

A clean scan is only meaningful if the scanner actually reached the interesting parts of the
app. Every report contains a **coverage** block (JSON) and section (HTML):

```json
"coverage": {
  "pages_crawled": 25,
  "pages_limit": 25,
  "pages_truncated": true,
  "parameters_discovered": 0,
  "parameters_tested": 0,
  "forms_discovered": 3,
  "modules_failed": [],
  "warnings": [
    "No URL parameters were discovered, so these modules had nothing to test: redirect, sqli, xss. This is NOT evidence that the application is free of those issues.",
    "Crawl stopped at the --max-pages limit (25); findings may be incomplete."
  ]
}
```

If `parameters_discovered` is `0`, the XSS/SQLi/redirect modules had nothing to attack. The CLI
prints `! Coverage warning:` lines and the HTML report shows a yellow "Coverage limitations"
panel for exactly this reason — a missing finding is not a proof of safety.

### Risk score

The score is **not** hand-tuned per finding; it is computed from severity weights:

| Severity | Weight |
| -------- | ------ |
| critical | 10.0   |
| high     | 7.5    |
| medium   | 5.0    |
| low      | 2.0    |
| info     | 0.0    |

`score = 100 × (1 − e^(−total_weight / 25))`

The exponential curve saturates, so ten low findings never look worse than one critical. The
JSON exposes the full maths under `risk`, and the HTML report renders it as a table:

```json
"risk": {
  "score": 58.5,
  "formula": "100 × (1 − e^(−total_weight / 25))",
  "total_weight": 22.5,
  "contributions": [
    {"severity": "critical", "count": 1, "weight": 10.0, "points": 10.0, "share": 44.4}
  ]
}
```

### Known-benign forms

The CSRF heuristic ignores forms that are not authenticated state changes: WordPress
`wp-login.php?action=postpass`, `wp-comments-post.php`, signup pages and search-only fields.
Those produce noise, not findings.

## Dashboard

```bash
atlasscan dashboard
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
atlasscan/
├── cli.py                 # argparse + rich CLI
├── config.py              # severity weights, defaults
├── core/
│   ├── http.py            # throttled requests session
│   ├── crawler.py         # stdlib HTML crawler (links + forms)
│   ├── models.py          # Finding / ScanResult
│   ├── scanner.py         # orchestration
│   ├── report.py          # HTML/JSON/SARIF rendering
│   ├── sarif.py           # SARIF 2.1.0 exporter
│   ├── baseline.py        # report only findings new since a previous scan
│   ├── cookies.py         # session cookie parsing (inline, cookies.txt, JSON)
│   ├── body.py            # POST/JSON body templates with FUZZ markers
│   ├── storage.py         # JSON-per-scan storage
│   └── utils.py           # URL helpers + SQL error signatures
├── modules/               # one file per check
└── web/                   # FastAPI dashboard + Jinja templates
tests/                     # local deliberately-vulnerable test server
Dockerfile                 # slim non-root image
```

Adding a module is intentionally boring:

```python
# atlasscan/modules/example.py
from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding


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

Register it in `atlasscan/modules/__init__.py` and, if it should run by default, add it to
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
- [x] POST parameter and JSON body testing
- [ ] Blind SSRF / XXE / SSTI checks
- [ ] Wordlist-based content discovery
- [x] SARIF output for GitHub code scanning
- [x] Scan comparison / diffing between runs (`--baseline`)
- [x] Authenticated scans with a cookie jar
- [ ] Publish to PyPI and GHCR

## Disclaimer

AtlasScan is provided for **authorized security testing and education**. The authors accept no
liability for misuse or damage caused by this tool. The scanner sends active payloads; some
checks can create noise or trigger WAFs. Always get written permission first.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in AtlasScan itself.

## License

MIT — see [LICENSE](LICENSE).

---

## بالعربية

**AtlasScan** أداة فحص ثغرات ويب مكتوبة بـ Python، بواجهة سطر أوامر ولوحة تحكم محلية.

```bash
atlasscan scan https://example.com --authorized
atlasscan dashboard
```

تفحص: ترويسات الأمان، الكوكيز، CORS، ثغرات JWT، XSS المنعكس، SQLi، التحويل المفتوح،
ملفات حساسة مكشوفة، شهادات TLS، نماذج بدون CSRF، وطرق HTTP الخطيرة (TRACE/PUT/DELETE).

كتقدر تخرج التقرير بـ HTML أو JSON أو SARIF، وتستعمل `--baseline` باش تبان غير الثغرات الجديدة
من بعد أول فحص:

```bash
atlasscan scan https://example.com --authorized --baseline baseline.json --fail-on high -o out.sarif
```

⚠️ **استعملها فقط على أنظمة تملكها أو لديك إذن كتابي بفحصها.**
