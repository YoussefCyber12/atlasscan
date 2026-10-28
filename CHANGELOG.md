# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coverage` block in JSON reports and a Coverage section in the HTML report: pages crawled vs
  limit, parameters discovered/tested, forms, failed modules and explicit warnings.
- `risk` breakdown in JSON and a "How the risk score is calculated" table in HTML.
- `--verbose` now prints the risk score breakdown table.
- `stats.params_tested` is populated (was always `0`).

### Fixed

- Clean results no longer imply safety when no parameters were discovered; the CLI and report
  now say so explicitly.
- CSRF heuristic skips known-benign forms (WordPress post-password, comments, signup, search).
- 403 on sensitive paths now recommends removing the file from the production docroot instead
  of cosmetic `404` advice.

## [0.1.0] - 2026-10-28

### Added

- Initial release.
- CLI: `scan`, `dashboard`, `list`, `show`, `modules` commands.
- Modules: `headers`, `cookies`, `cors`, `jwt`, `xss`, `sqli`, `redirect`, `files`, `tls`,
  `forms`, `tech`.
- Polite HTTP client with throttling, retries and proxy support.
- HTML + JSON reports with severity, evidence and remediation.
- Local FastAPI dashboard with scan history, live scan log and JSON API.
- `--fail-on` exit codes for CI usage.
- Test suite against an in-process deliberately vulnerable server.
