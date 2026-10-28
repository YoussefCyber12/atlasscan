from __future__ import annotations

import pytest

from atlasscan.cli import build_parser, exit_code_for, parse_headers
from atlasscan.core.models import Finding, ScanResult


def result_with(*severities: str) -> ScanResult:
    result = ScanResult(target="https://example.test/", started_at="now")
    for severity in severities:
        result.add(Finding(f"{severity} issue", severity, "https://example.test/", "test", "d"))
    return result


def test_parser_requires_target():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan"])


def test_parser_scan_defaults():
    args = build_parser().parse_args(["scan", "https://example.test"])
    assert args.command == "scan"
    assert args.max_pages == 25
    assert args.delay == 0.15
    assert args.authorized is False


def test_parser_modules_command():
    args = build_parser().parse_args(["modules", "--json"])
    assert args.command == "modules"


def test_parse_headers():
    assert parse_headers(["X-Test: 1", "Authorization: Bearer abc"]) == {
        "X-Test": "1",
        "Authorization": "Bearer abc",
    }
    with pytest.raises(SystemExit):
        parse_headers(["broken"])


@pytest.mark.parametrize(
    ("fail_on", "severities", "expected"),
    [
        ("none", ["critical"], 0),
        ("high", ["critical"], 1),
        ("high", ["medium"], 0),
        ("low", ["info"], 0),
        ("info", ["info"], 1),
        ("critical", [], 0),
        ("medium", ["low", "medium"], 1),
    ],
)
def test_exit_codes(fail_on, severities, expected):
    assert exit_code_for(result_with(*severities), fail_on) == expected
