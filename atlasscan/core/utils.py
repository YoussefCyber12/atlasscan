from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from atlasscan.core.models import Finding


def normalize_url(url: str) -> str:
    """Drop fragments, sort query params and keep the URL canonical enough to dedupe."""
    parsed = urlparse(url.strip())
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


def same_origin(a: str, b: str) -> bool:
    return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()


def with_param(url: str, name: str, value: str) -> str:
    """Return `url` with query parameter `name` replaced (or added)."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out = []
    for key, val in pairs:
        if key == name and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, val))
    if not replaced:
        out.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(out)))


def param_names(url: str) -> list[str]:
    return [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


_SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*\Wmysqli?_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"ORA-\d{4,5}",
    r"Oracle error",
    r"Microsoft SQL (?:Server|Native Client)",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"sqlite3\.OperationalError",
    r"near \".*\": syntax error",
]
SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)


def detect_sql_error(text: str) -> str:
    match = SQL_ERROR_RE.search(text or "")
    return match.group(0) if match else ""


def redact_header(value: str, max_len: int = 200) -> str:
    value = value.replace("\n", " ").replace("\r", " ")
    return value[:max_len] + ("..." if len(value) > max_len else "")


def finding(
    name: str,
    severity: str,
    url: str,
    module: str,
    description: str,
    **kwargs: str,
) -> Finding:
    return Finding(
        name=name,
        severity=severity,
        url=url,
        module=module,
        description=description,
        **kwargs,
    )
