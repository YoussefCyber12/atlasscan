from __future__ import annotations

import json

import pytest

from atlasscan.core.baseline import BaselineError, apply_baseline, load_baseline
from atlasscan.core.models import Finding, ScanResult
from atlasscan.core.report import write_report
from atlasscan.core.sarif import build_sarif, render_sarif
from atlasscan.core.storage import Storage


def make_result(target: str = "https://example.test/") -> ScanResult:
    result = ScanResult(target=target, started_at="2026-01-01T00:00:00+00:00")
    result.modules = ["xss", "headers"]
    result.add(
        Finding(
            "Reflected XSS",
            "high",
            "https://example.test/search?q=x",
            "xss",
            "The parameter is reflected unsafely.",
            evidence="<svg/onload=alert(1)>",
            remediation="Encode output.",
            cwe="CWE-79",
            owasp="A03:2021",
        )
    )
    result.add(
        Finding(
            "Missing Content-Security-Policy",
            "medium",
            "https://example.test/",
            "headers",
            "No CSP header.",
            remediation="Add a CSP.",
        )
    )
    return result


# --------------------------------------------------------------------- SARIF
def test_sarif_has_required_shape():
    data = build_sarif(make_result())
    assert data["version"] == "2.1.0"
    assert data["$schema"]
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "AtlasScan"
    assert driver["version"]
    assert len(run["results"]) == 2
    assert len(driver["rules"]) == 2


def test_sarif_rules_are_deduplicated():
    result = make_result()
    for _ in range(3):
        result.add(Finding("Reflected XSS", "high", "https://example.test/a?q=1", "xss", "d"))
    data = build_sarif(result)
    rule_ids = [rule["id"] for rule in data["runs"][0]["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert len(data["runs"][0]["results"]) == 5


def test_sarif_severity_mapping_and_fingerprints():
    data = build_sarif(make_result())
    results = {item["properties"]["severity"]: item for item in data["runs"][0]["results"]}
    assert results["high"]["level"] == "error"
    assert results["medium"]["level"] == "warning"
    assert results["high"]["partialFingerprints"]["atlasscanFindingId/v1"]
    assert results["high"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert results["high"]["ruleId"].startswith("atlasscan/xss/")


def test_sarif_rule_security_severity_is_numeric():
    data = build_sarif(make_result())
    for rule in data["runs"][0]["tool"]["driver"]["rules"]:
        assert float(rule["properties"]["security-severity"]) >= 0


def test_write_report_supports_sarif_extension(tmp_path):
    path = write_report(make_result(), tmp_path / "scan.sarif")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert render_sarif(make_result())


# ------------------------------------------------------------------ baseline
def test_apply_baseline_hides_known_findings():
    old = make_result()
    new = make_result()
    new.add(Finding("Open redirect", "medium", "https://example.test/go?next=x", "redirect", "d"))

    suppressed = apply_baseline(new, old)

    assert suppressed == 2
    assert new.suppressed == 2
    assert new.baseline_scan_id == old.scan_id
    assert [f.name for f in new.findings] == ["Open redirect"]


def test_apply_baseline_keeps_everything_when_nothing_is_known():
    old = make_result()
    new = ScanResult(target=old.target, started_at="2026-01-02T00:00:00+00:00")
    new.add(Finding("New thing", "low", "https://example.test/x", "headers", "d"))

    assert apply_baseline(new, old) == 0
    assert len(new.findings) == 1
    assert new.baseline_scan_id == old.scan_id


def test_apply_baseline_warns_on_target_mismatch():
    old = make_result("https://old.example.test/")
    new = make_result("https://new.example.test/")

    apply_baseline(new, old)

    assert any("different hosts" in warning for warning in new.coverage.warnings)


def test_finding_id_ignores_payload_values():
    first = Finding("Reflected XSS", "high", "https://e.test/search?q=%3Csvg%3E", "xss", "d")
    second = Finding("Reflected XSS", "high", "https://e.test/search?q=other", "xss", "d")
    assert first.id == second.id


def test_finding_id_distinguishes_parameter_names():
    first = Finding("Reflected XSS", "high", "https://e.test/search?q=1", "xss", "d")
    second = Finding("Reflected XSS", "high", "https://e.test/search?id=1", "xss", "d")
    assert first.id != second.id


def test_baseline_suppresses_randomised_payload_findings(server_url):
    from atlasscan.core.context import ScanOptions
    from atlasscan.core.scanner import run_scan

    options = ScanOptions(delay=0.0, crawl=True, max_pages=3, timeout=5)
    baseline = run_scan(server_url, options=options, module_names=["xss", "headers"])
    current = run_scan(server_url, options=options, module_names=["xss", "headers"])

    assert any(f.name == "Reflected XSS" for f in current.findings)
    suppressed = apply_baseline(current, baseline)

    assert suppressed >= 2
    assert not any(f.name == "Reflected XSS" for f in current.findings)


def test_load_baseline_from_json_file(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(make_result().to_json(), encoding="utf-8")

    loaded = load_baseline(str(path))

    assert loaded.target == "https://example.test/"
    assert len(loaded.findings) == 2


def test_load_baseline_from_storage(tmp_path):
    storage = Storage(tmp_path)
    stored = make_result()
    storage.save(stored)

    loaded = load_baseline(stored.scan_id, storage)

    assert loaded.scan_id == stored.scan_id


def test_load_baseline_missing_raises(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline("does-not-exist", Storage(tmp_path))


def test_load_baseline_invalid_json_raises(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(str(path))


def test_baseline_fields_survive_json_roundtrip():
    old = make_result()
    new = make_result()
    apply_baseline(new, old)

    clone = ScanResult.from_dict(new.to_dict())

    assert clone.baseline_scan_id == old.scan_id
    assert clone.suppressed == new.suppressed
