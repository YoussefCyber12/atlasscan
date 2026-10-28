from __future__ import annotations

from atlasscan.core.models import Finding, ScanResult
from atlasscan.core.report import render_html, write_report
from atlasscan.core.storage import Storage


def sample_result() -> ScanResult:
    result = ScanResult(target="https://example.test/", started_at="2026-01-01T00:00:00+00:00")
    result.add(
        Finding(
            name="Reflected XSS",
            severity="medium",
            url="https://example.test/?q=1",
            module="xss",
            description="Input is reflected unencoded.",
            evidence="q=<svg/onload=alert(1)>",
            remediation="Encode output.",
            cwe="CWE-79",
        )
    )
    result.add(
        Finding(
            name="Missing CSP",
            severity="low",
            url="https://example.test/",
            module="headers",
            description="No CSP.",
        )
    )
    return result


def test_storage_roundtrip(tmp_path):
    storage = Storage(tmp_path)
    result = sample_result()
    path = storage.save(result)
    assert path.exists()

    loaded = storage.load(result.scan_id)
    assert loaded is not None
    assert loaded.target == result.target
    assert len(loaded.findings) == 2

    listed = storage.list()
    assert listed[0]["scan_id"] == result.scan_id
    assert listed[0]["findings"] == 2


def test_storage_delete(tmp_path):
    storage = Storage(tmp_path)
    result = sample_result()
    storage.save(result)
    assert storage.delete(result.scan_id)
    assert storage.load(result.scan_id) is None


def test_render_html_escapes_and_contains_findings():
    html = render_html(sample_result())
    assert "Reflected XSS" in html
    assert "https://example.test/" in html
    assert "&lt;svg/onload=alert(1)&gt;" in html
    assert "Risk score" in html


def test_write_report_dispatch(tmp_path):
    result = sample_result()
    json_path = write_report(result, tmp_path / "out.json")
    html_path = write_report(result, tmp_path / "out.html")
    assert json_path.read_text(encoding="utf-8").startswith("{")
    assert html_path.read_text(encoding="utf-8").lstrip().startswith("<!doctype html>")


def test_risk_score_ordering():
    low = ScanResult(target="https://a/", started_at="now")
    low.add(Finding("a", "low", "https://a/", "m", "d"))
    high = ScanResult(target="https://a/", started_at="now")
    high.add(Finding("b", "critical", "https://a/", "m", "d"))
    assert high.risk_score() > low.risk_score()
