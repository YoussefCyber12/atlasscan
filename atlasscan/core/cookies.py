"""Cookie helpers for authenticated scans."""

from __future__ import annotations

import json
from http.cookiejar import LoadError, MozillaCookieJar
from pathlib import Path
from typing import Any


def parse_cookie_string(raw: str) -> dict[str, str]:
    """Parse a `Cookie:` header value such as `session=abc; csrf=xyz`."""
    raw = raw.strip()
    if raw.lower().startswith("cookie:"):
        raw = raw.split(":", 1)[1]
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid cookie (expected name=value): {part!r}")
        name, value = part.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid cookie (empty name): {part!r}")
        cookies[name] = value.strip()
    if not cookies:
        raise ValueError("no cookies found (expected 'name=value[; name=value]')")
    return cookies


def _json_cookies(data: Any) -> list[dict[str, str]]:
    if isinstance(data, dict):
        data = data.get("cookies", [])
    if not isinstance(data, list):
        raise ValueError("JSON cookie file must be a list or an object with a 'cookies' list")
    items: list[dict[str, str]] = []
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        items.append(
            {
                "name": str(entry["name"]),
                "value": str(entry.get("value", "")),
                "domain": str(entry.get("domain") or ""),
                "path": str(entry.get("path") or "/"),
            }
        )
    if not items:
        raise ValueError("cookie file contains no cookies")
    return items


def load_cookie_file(path: str | Path) -> list[dict[str, str]]:
    """Load cookies from a Netscape `cookies.txt` file or a JSON export.

    JSON accepts either a bare list or a Playwright-style `{"cookies": [...]}` object.
    """
    cookie_path = Path(path).expanduser()
    if not cookie_path.is_file():
        raise ValueError(f"cookie file not found: {cookie_path}")

    text = cookie_path.read_text(encoding="utf-8", errors="replace")
    if text.lstrip().startswith(("[", "{")):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON cookie file: {exc}") from exc
        return _json_cookies(data)

    jar = MozillaCookieJar(str(cookie_path))
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except (LoadError, OSError) as exc:
        raise ValueError(
            "cannot parse cookie file: expected Netscape cookies.txt or a JSON export "
            f"({exc})"
        ) from exc
    items = [
        {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path or "/",
        }
        for cookie in jar
    ]
    if not items:
        raise ValueError("cookie file contains no cookies")
    return items
