from __future__ import annotations

import json
import os
from pathlib import Path

from atlasscan.core.models import ScanResult


def default_data_dir() -> Path:
    override = os.environ.get("ATLASCAN_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".atlasscan"


class Storage:
    """Tiny JSON-per-scan storage shared by the CLI and the dashboard."""

    def __init__(self, data_dir: Path | str | None = None) -> None:
        self.data_dir = Path(data_dir).expanduser() if data_dir else default_data_dir()
        self.scans_dir = self.data_dir / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, scan_id: str) -> Path:
        safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in "-_")
        return self.scans_dir / f"{safe}.json"

    def save(self, result: ScanResult) -> Path:
        path = self.path_for(result.scan_id)
        path.write_text(result.to_json(), encoding="utf-8")
        return path

    def load(self, scan_id: str) -> ScanResult | None:
        path = self.path_for(scan_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return ScanResult.from_dict(data)

    def delete(self, scan_id: str) -> bool:
        path = self.path_for(scan_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list(self, limit: int = 100) -> list[dict]:
        items: list[dict] = []
        files = sorted(self.scans_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in files[:limit]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            items.append(
                {
                    "scan_id": data.get("scan_id", path.stem),
                    "target": data.get("target", "?"),
                    "started_at": data.get("started_at", ""),
                    "finished_at": data.get("finished_at", ""),
                    "risk_score": data.get("risk_score", 0),
                    "counts": data.get("counts", {}),
                    "findings": len(data.get("findings", [])),
                }
            )
        return items
