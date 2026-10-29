from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from atlasscan.core.models import ScanResult
from atlasscan.core.sarif import render_sarif

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "web" / "templates"

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(result: ScanResult) -> str:
    template = _env().get_template("report.html")
    return template.render(
        result=result.to_dict(),
        severity_labels=SEVERITY_LABELS,
        counts=result.counts(),
        risk=result.risk_score(),
        risk_breakdown=result.risk_breakdown(),
        coverage=result.coverage.to_dict(),
        findings=[f.to_dict() for f in result.sorted_findings()],
    )


def write_report(result: ScanResult, path: str | Path) -> Path:
    """Write HTML, JSON or SARIF based on the file extension."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix in (".html", ".htm"):
        path.write_text(render_html(result), encoding="utf-8")
    elif suffix == ".sarif":
        path.write_text(render_sarif(result), encoding="utf-8")
    else:
        path.write_text(result.to_json(), encoding="utf-8")
    return path
