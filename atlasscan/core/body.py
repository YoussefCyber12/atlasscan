"""Request-body helpers for POST/JSON fuzzing.

A body template is a normal body with one or more `FUZZ` markers where a payload should go.
JSON templates are handled structurally so payloads stay valid JSON (quotes are escaped for
you), while form-encoded/raw bodies are substituted literally.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterator

FUZZ = "FUZZ"
BENIGN = "atlas"


def load_body_template(raw: str) -> str:
    """Return a body template, reading it from `@file` when requested."""
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        if not path.is_file():
            raise ValueError(f"body file not found: {path}")
        raw = path.read_text(encoding="utf-8")
    if FUZZ not in raw:
        raise ValueError("body template must contain at least one FUZZ marker")
    return raw


def body_content_type(template: str, override: str | None = None) -> str:
    if override:
        return override
    stripped = template.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(template)
        except ValueError:
            pass
        else:
            return "application/json"
    return "application/x-www-form-urlencoded"


def marker_count(template: str) -> int:
    return template.count(FUZZ)


def _json_strings(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], str]]:
    if isinstance(value, str):
        if FUZZ in value:
            yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _json_strings(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _json_strings(child, path + (index,))


def _replace_at_path(value: Any, path: tuple[Any, ...], replacement: str) -> Any:
    if not path:
        return replacement
    clone = copy.deepcopy(value)
    target = clone
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return clone


def _substitute_all(value: Any, replacement: str) -> Any:
    if isinstance(value, str):
        return value.replace(FUZZ, replacement)
    if isinstance(value, dict):
        return {key: _substitute_all(child, replacement) for key, child in value.items()}
    if isinstance(value, list):
        return [_substitute_all(child, replacement) for child in value]
    return value


def _label(path: tuple[Any, ...]) -> str:
    if not path:
        return "root"
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + str(part)
    return out


def _json_variants(template: str, payload: str) -> list[tuple[str, str]] | None:
    try:
        data = json.loads(template)
    except ValueError:
        return None
    variants: list[tuple[str, str]] = []
    base = _substitute_all(data, BENIGN)
    for path, text in _json_strings(data):
        parts = text.split(FUZZ)
        if len(parts) == 1:
            continue
        multiple = len(parts) > 2
        for index in range(len(parts) - 1):
            filled = [BENIGN] * (len(parts) - 1)
            filled[index] = payload
            value = parts[0] + "".join(
                item + tail for item, tail in zip(filled, parts[1:])
            )
            body = json.dumps(_replace_at_path(base, path, value), ensure_ascii=False)
            label = _label(path) + (f"[{index + 1}]" if multiple else "")
            variants.append((label, body))
    return variants


def body_variants(template: str, payload: str) -> list[tuple[str, str]]:
    """Return one `(label, body)` pair per FUZZ marker, injecting `payload` one at a time.

    Other markers are filled with a harmless value so each request has exactly one probe.
    """
    variants = _json_variants(template, payload)
    if variants is not None:
        return variants

    parts = template.split(FUZZ)
    if len(parts) == 1:
        return []
    out: list[tuple[str, str]] = []
    for index in range(len(parts) - 1):
        filled = [BENIGN] * (len(parts) - 1)
        filled[index] = payload
        body = parts[0]
        for value, tail in zip(filled, parts[1:]):
            body += value + tail
        out.append((f"marker {index + 1}", body))
    return out
