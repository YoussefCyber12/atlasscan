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
    "methods",
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


def test_methods_module(result):
    assert "TRACE method enabled (cross-site tracing)" in names(result)
    assert "Dangerous HTTP methods advertised" in names(result)


def test_risk_score_and_counts(result):
    assert 0 <= result.risk_score() <= 100
    assert result.counts()["critical"] >= 1
    assert result.risk_score() > 0


def test_coverage_counts_parameters_and_forms(result):
    coverage = result.coverage
    assert coverage.parameters_discovered >= 3
    assert coverage.parameters_tested >= 3
    assert coverage.parameters_tested <= coverage.parameters_discovered
    assert coverage.forms_discovered >= 2
    assert coverage.modules_run
    assert not coverage.modules_failed


def test_coverage_does_not_emit_false_no_params_warning(result):
    assert not any("No URL parameters" in warning for warning in result.coverage.warnings)


def test_no_parameters_produces_explicit_warning(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5)
    empty = run_scan(server_url, options=options, module_names=["xss"])
    assert empty.coverage.parameters_discovered == 0
    assert empty.coverage.parameters_tested == 0
    assert any("No URL parameters" in warning for warning in empty.coverage.warnings)


def test_no_parameters_warning_only_mentions_modules_that_ran(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5)
    headers_only = run_scan(server_url, options=options, module_names=["headers"])
    assert headers_only.coverage.modules_run == ["headers"]
    assert not any("No URL parameters" in warning for warning in headers_only.coverage.warnings)


def test_risk_breakdown_explains_the_score(result):
    breakdown = result.risk_breakdown()
    assert breakdown["score"] == result.risk_score()
    assert breakdown["formula"]
    assert sum(row["points"] for row in breakdown["contributions"]) == pytest.approx(
        breakdown["total_weight"]
    )
    assert sum(row["share"] for row in breakdown["contributions"]) == pytest.approx(100, abs=0.3)
    assert breakdown["total_weight"] > 0


def test_json_exposes_coverage_and_risk(result):
    data = result.to_dict()
    assert data["coverage"]["parameters_tested"] > 0
    assert data["risk"]["score"] == data["risk_score"]
    assert data["stats"]["params_tested"] == data["coverage"]["parameters_tested"]


def test_forms_module_skips_wordpress_postpass(result):
    form_findings = [f for f in result.findings if f.module == "forms"]
    assert form_findings, "the real login form should still be reported"
    assert not any("wp-login.php" in f.url for f in form_findings)


def test_protected_git_uses_real_remediation(result):
    finding = next(f for f in result.findings if ".git/HEAD" in f.url)
    assert finding.name == "Sensitive path exists (403)"
    assert "Remove the file/directory from the production docroot" in finding.remediation


def test_json_roundtrip(result):
    from atlasscan.core.models import ScanResult

    clone = ScanResult.from_dict(result.to_dict())
    assert clone.target == result.target
    assert len(clone.findings) == len(result.findings)
    assert clone.counts() == result.counts()
