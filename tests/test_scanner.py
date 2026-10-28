from __future__ import annotations

import pytest

from atlasscan.core.context import ScanOptions
from atlasscan.core.scanner import run_scan

MODULES = [
    "headers",
    "cookies",
    "cors",
    "jwt",
    "xss",
    "sqli",
    "redirect",
    "tech",
    "forms",
    "files",
]


@pytest.fixture(scope="module")
def result(server_url):
    options = ScanOptions(delay=0.0, max_pages=10, max_depth=2, timeout=5)
    return run_scan(server_url, options=options, module_names=MODULES)


def names(result) -> set[str]:
    return {finding.name for finding in result.findings}


def modules(result) -> set[str]:
    return {finding.module for finding in result.findings}


def test_scan_collects_findings(result):
    assert result.findings, "expected the scan to report at least one issue"
    assert result.stats.requests > 0
    assert result.stats.pages_crawled >= 4
    assert result.finished_at


def test_headers_module(result):
    assert "Missing Content-Security-Policy" in names(result)
    assert "Missing clickjacking protection" in names(result)


def test_cookies_module(result):
    # The test server is plain HTTP, so the `Secure` check is intentionally skipped.
    assert "Cookie without HttpOnly flag" in names(result)
    assert "Cookie without SameSite attribute" in names(result)


def test_cors_module(result):
    finding = next(f for f in result.findings if f.name == "CORS misconfiguration with credentials")
    assert finding.severity == "high"


def test_jwt_module_finds_weak_secret(result):
    finding = next(f for f in result.findings if f.name == "JWT signed with a weak secret")
    assert finding.severity == "critical"
    assert "secret" in finding.evidence


def test_xss_module(result):
    assert "Reflected XSS" in names(result)


def test_sqli_module(result):
    assert "SQL injection (error-based)" in names(result)


def test_redirect_module(result):
    assert "Open redirect" in names(result)


def test_forms_module(result):
    assert "POST form without an anti-CSRF token" in names(result)


def test_risk_score_and_counts(result):
    assert 0 <= result.risk_score() <= 100
    assert result.counts()["critical"] >= 1
    assert result.risk_score() > 0


def test_json_roundtrip(result):
    from atlasscan.core.models import ScanResult

    clone = ScanResult.from_dict(result.to_dict())
    assert clone.target == result.target
    assert len(clone.findings) == len(result.findings)
    assert clone.counts() == result.counts()
