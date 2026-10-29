from __future__ import annotations

import json

import pytest

from atlasscan.core.context import ScanOptions
from atlasscan.core.cookies import load_cookie_file, parse_cookie_string
from atlasscan.core.http import HttpClient
from atlasscan.core.scanner import run_scan


# --------------------------------------------------------------- cookie string
def test_parse_cookie_string_basic():
    assert parse_cookie_string("session=abc; csrf=xyz") == {"session": "abc", "csrf": "xyz"}


def test_parse_cookie_string_keeps_equals_in_value():
    assert parse_cookie_string("token=a=b=c") == {"token": "a=b=c"}


def test_parse_cookie_string_trims_whitespace_and_empty_parts():
    assert parse_cookie_string("  a=1 ;; b=2  ") == {"a": "1", "b": "2"}


def test_parse_cookie_string_accepts_full_cookie_header():
    assert parse_cookie_string("Cookie: session=abc; csrf=xyz") == {
        "session": "abc",
        "csrf": "xyz",
    }


@pytest.mark.parametrize("raw", ["", "  ", "novalue", "=value", "a=1; b"])
def test_parse_cookie_string_rejects_invalid_input(raw):
    with pytest.raises(ValueError):
        parse_cookie_string(raw)


# ----------------------------------------------------------------- cookie file
def test_load_netscape_cookie_file(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(
        "# Netscape HTTP Cookie File\n"
        "127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tabc123\n"
        "127.0.0.1\tFALSE\t/admin\tFALSE\t0\trole\tadmin\n",
        encoding="utf-8",
    )

    cookies = load_cookie_file(path)

    assert {cookie["name"]: cookie["value"] for cookie in cookies} == {
        "session": "abc123",
        "role": "admin",
    }


def test_load_json_cookie_list(tmp_path):
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps([{"name": "session", "value": "abc", "domain": "127.0.0.1", "path": "/"}]),
        encoding="utf-8",
    )

    cookies = load_cookie_file(path)

    assert cookies == [
        {"name": "session", "value": "abc", "domain": "127.0.0.1", "path": "/"}
    ]


def test_load_playwright_json_export(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"cookies": [{"name": "token", "value": "xyz", "domain": ".example.test"}]}),
        encoding="utf-8",
    )

    cookies = load_cookie_file(path)

    assert cookies[0]["name"] == "token"
    assert cookies[0]["value"] == "xyz"
    assert cookies[0]["path"] == "/"


def test_load_cookie_file_missing_raises(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        load_cookie_file(tmp_path / "nope.txt")


def test_load_cookie_file_empty_raises(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="no cookies"):
        load_cookie_file(path)


def test_load_cookie_file_broken_json_raises(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("[{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_cookie_file(path)


# ------------------------------------------------------------------ http client
def test_http_client_sends_cookie_from_dict(server_url):
    client = HttpClient(delay=0.0, timeout=5, cookies={"session": "abc123"})
    try:
        response = client.get(f"{server_url}/echo-cookie")
    finally:
        client.close()

    assert response is not None
    assert "session=abc123" in response.text


def test_http_client_sends_cookie_from_jar(server_url, tmp_path):
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps([{"name": "session", "value": "jarvalue", "domain": "127.0.0.1", "path": "/"}]),
        encoding="utf-8",
    )
    client = HttpClient(delay=0.0, timeout=5, cookie_jar=str(path))
    try:
        response = client.get(f"{server_url}/echo-cookie")
    finally:
        client.close()

    assert response is not None
    assert "session=jarvalue" in response.text


# ---------------------------------------------------------------------- scanner
def test_scan_marks_coverage_as_authenticated(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5, cookies={"session": "abc"})
    result = run_scan(server_url, options=options, module_names=["headers"])

    assert result.coverage.authenticated is True


def test_scan_without_cookies_is_not_authenticated(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5)
    result = run_scan(server_url, options=options, module_names=["headers"])

    assert result.coverage.authenticated is False


def test_scan_warns_when_session_still_hits_login_page(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5, cookies={"session": "stale"})
    result = run_scan(f"{server_url}/login", options=options, module_names=["headers"])

    assert any("still looks like a login" in warning for warning in result.coverage.warnings)


def test_scan_does_not_warn_on_a_normal_page(server_url):
    options = ScanOptions(delay=0.0, crawl=False, timeout=5, cookies={"session": "abc"})
    result = run_scan(server_url, options=options, module_names=["headers"])

    assert not any("still looks like a login" in warning for warning in result.coverage.warnings)
