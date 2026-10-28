from __future__ import annotations

import pytest

from atlasscan.core.utils import detect_sql_error, normalize_url, param_names, with_param


def test_normalize_url_strips_fragments_and_sorts_query():
    assert normalize_url("https://x.test/a?b=2&a=1#frag") == "https://x.test/a?a=1&b=2"


def test_with_param_replaces_and_adds():
    assert with_param("https://x.test/?a=1&b=2", "b", "9") == "https://x.test/?a=1&b=9"
    assert with_param("https://x.test/", "q", "1") == "https://x.test/?q=1"


def test_param_names():
    assert param_names("https://x.test/?a=1&b=2") == ["a", "b"]
    assert param_names("https://x.test/") == []


@pytest.mark.parametrize(
    "text",
    [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "ORA-01756: quoted string not properly terminated",
        "Microsoft SQL Server Native Client error",
        "sqlite3.OperationalError: near \"x\": syntax error",
    ],
)
def test_detect_sql_error(text):
    assert detect_sql_error(text)


def test_detect_sql_error_negative():
    assert detect_sql_error("Welcome to our shop") == ""


def test_normalize_target_requires_host():
    from atlasscan.core.scanner import normalize_target

    assert normalize_target("example.com") == "https://example.com/"
    with pytest.raises(ValueError):
        normalize_target("ftp://example.com")
