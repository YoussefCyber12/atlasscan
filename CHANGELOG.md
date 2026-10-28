# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

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
