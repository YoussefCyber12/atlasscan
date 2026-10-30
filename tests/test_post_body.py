from __future__ import annotations

import json

import pytest

from atlasscan.core.body import (
    body_content_type,
    body_variants,
    load_body_template,
    marker_count,
)
from atlasscan.core.context import ScanOptions
from atlasscan.core.crawler import Form, is_safe_to_submit, parse_page
from atlasscan.core.scanner import run_scan


# --------------------------------------------------------------- body helpers
def test_marker_count():
    assert marker_count('{"a":"FUZZ","b":"FUZZ"}') == 2
    assert marker_count("no marker") == 0


def test_load_body_template_from_file(tmp_path):
    path = tmp_path / "body.json"
    path.write_text('{"q":"FUZZ"}', encoding="utf-8")

    assert load_body_template(f"@{path}") == '{"q":"FUZZ"}'


def test_load_body_template_requires_marker(tmp_path):
    path = tmp_path / "body.json"
    path.write_text('{"q":"x"}', encoding="utf-8")

    with pytest.raises(ValueError, match="FUZZ"):
        load_body_template(str(path))
    with pytest.raises(ValueError, match="not found"):
        load_body_template("@definitely-missing.json")


def test_body_content_type_autodetects_json():
    assert body_content_type('{"q":"FUZZ"}') == "application/json"
    assert body_content_type('["FUZZ"]') == "application/json"
    assert body_content_type("q=FUZZ") == "application/x-www-form-urlencoded"
    assert body_content_type("q=FUZZ", "text/plain") == "text/plain"


def test_raw_body_variants_inject_one_marker_at_a_time():
    variants = body_variants("a=FUZZ&b=FUZZ", "PAY")

    assert [body for _, body in variants] == ["a=PAY&b=atlas", "a=atlas&b=PAY"]


def test_json_body_variants_stay_valid_and_escape_payload():
    payload = '"><svg/onload=alert(1)>'
    variants = body_variants('{"user":{"q":"FUZZ"},"list":["x","FUZZ"]}', payload)

    assert [label for label, _ in variants] == ["user.q", "list[1]"]
    first = json.loads(variants[0][1])
    assert first["user"]["q"] == payload
    assert first["list"][1] == "atlas"


def test_body_variants_without_marker_is_empty():
    assert body_variants("q=1", "PAY") == []


def test_json_body_with_several_markers_in_one_string():
    variants = body_variants('{"q":"a=FUZZ&b=FUZZ"}', "PAY")

    assert [label for label, _ in variants] == ["q[1]", "q[2]"]
    assert [json.loads(body)["q"] for _, body in variants] == [
        "a=PAY&b=atlas",
        "a=atlas&b=PAY",
    ]


# -------------------------------------------------------------------- crawler
def test_parse_form_captures_values_and_password():
    parser = parse_page(
        "<form method='post' action='/save'>"
        "<input type='hidden' name='csrf' value='tok'>"
        "<input type='text' name='q'>"
        "<input type='password' name='pass'>"
        "</form>",
        "https://example.test/",
    )

    form = parser.forms[0]
    assert form.action == "https://example.test/save"
    assert form.values == {"csrf": "tok", "q": "", "pass": ""}
    assert form.has_password is True


def test_is_safe_to_submit_filters_dangerous_forms():
    assert is_safe_to_submit(Form("https://x.test/search", "POST", ["q"]))
    assert not is_safe_to_submit(Form("https://x.test/delete?id=1", "POST", ["id"]))
    assert not is_safe_to_submit(Form("https://x.test/save", "POST", ["pass"], has_password=True))
    assert not is_safe_to_submit(Form("https://x.test/search", "GET", ["q"]))


# -------------------------------------------------------- active POST testing
def test_post_forms_are_not_tested_by_default(server_url):
    options = ScanOptions(delay=0.0, crawl=True, max_pages=5, timeout=5)
    result = run_scan(server_url, options=options, module_names=["xss"])

    assert not any(finding.url.endswith("/post-echo") for finding in result.findings)


def test_xss_in_post_form(server_url):
    options = ScanOptions(delay=0.0, crawl=True, max_pages=5, timeout=5, post_forms=True)
    result = run_scan(server_url, options=options, module_names=["xss"])

    hits = [finding for finding in result.findings if finding.url.endswith("/post-echo")]
    assert hits
    assert "Field: q" in hits[0].evidence
    assert not any(finding.url.endswith("/login") for finding in result.findings)


def test_sqli_in_post_form(server_url):
    options = ScanOptions(delay=0.0, crawl=True, max_pages=5, timeout=5, post_forms=True)
    result = run_scan(server_url, options=options, module_names=["sqli"])

    hits = [finding for finding in result.findings if finding.url.endswith("/post-echo")]
    assert hits
    assert hits[0].name == "SQL injection (error-based)"
    assert "Field: q" in hits[0].evidence


# ------------------------------------------------------------- JSON body test
def test_xss_in_json_body(server_url):
    target = f"{server_url}/json-echo"
    options = ScanOptions(delay=0.0, crawl=False, timeout=5, data='{"q":"FUZZ"}')
    result = run_scan(target, options=options, module_names=["xss"])

    hits = [finding for finding in result.findings if finding.url == target]
    assert hits
    assert "Body field: q" in hits[0].evidence


def test_sqli_in_json_body(server_url):
    target = f"{server_url}/json-echo"
    options = ScanOptions(delay=0.0, crawl=False, timeout=5, data='{"q":"FUZZ"}')
    result = run_scan(target, options=options, module_names=["sqli"])

    hits = [finding for finding in result.findings if finding.url == target]
    assert hits
    assert "Body field: q" in hits[0].evidence


def test_coverage_counts_post_fields_and_body_markers(server_url):
    options = ScanOptions(
        delay=0.0,
        crawl=True,
        max_pages=5,
        timeout=5,
        post_forms=True,
        data='{"a":"FUZZ","b":"FUZZ"}',
    )
    result = run_scan(server_url, options=options, module_names=["headers"])

    # csrf + q from the test form, plus two body markers, plus the URL parameters.
    assert result.coverage.parameters_discovered >= 4
