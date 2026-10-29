"""Baseline support: only report findings that are new since a previous scan."""

from __future__ import annotations

import json
from pathlib import Path

from atlasscan.core.models import ScanResult
from atlasscan.core.storage import Storage


class BaselineError(ValueError):
    """Raised when a baseline path or scan id cannot be resolved."""


def load_baseline(source: str, storage: Storage | None = None) -> ScanResult:
    """Load a baseline from a JSON report path or from the local scan storage."""
    path = Path(source).expanduser()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BaselineError(f"cannot read baseline {source}: {exc}") from exc
        try:
            return ScanResult.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise BaselineError(f"invalid baseline {source}: {exc}") from exc

    stored = (storage or Storage()).load(source)
    if stored is None:
        raise BaselineError(
            f"baseline not found: {source} (pass a JSON report path or a saved scan id)"
        )
    return stored


def apply_baseline(result: ScanResult, baseline: ScanResult) -> int:
    """Drop findings already present in `baseline` and record why. Returns the count."""
    known = {finding.id for finding in baseline.findings}
    before = len(result.findings)
    result.findings = [finding for finding in result.findings if finding.id not in known]
    result.suppressed = before - len(result.findings)
    result.baseline_scan_id = baseline.scan_id

    if baseline.target.rstrip("/") != result.target.rstrip("/"):
        result.coverage.warnings.append(
            f"Baseline {baseline.scan_id} was recorded for {baseline.target}, but this scan "
            f"targeted {result.target}. Comparisons across different hosts are unreliable."
        )
    return result.suppressed
