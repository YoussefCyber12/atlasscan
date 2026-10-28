from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

from atlasscan import __version__
from atlasscan.config import SEVERITY_WEIGHT

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """A single issue reported by a module."""

    name: str
    severity: str
    url: str
    module: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    confidence: str = "firm"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")

    @property
    def id(self) -> str:
        raw = f"{self.module}|{self.name}|{self.url}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["id"] = self.id
        return data

    def sort_key(self) -> tuple[int, str, str]:
        return (SEVERITY_ORDER[self.severity], self.name, self.url)


@dataclass
class ScanStats:
    requests: int = 0
    pages_crawled: int = 0
    params_tested: int = 0
    errors: int = 0
    duration: float = 0.0


@dataclass
class Coverage:
    """What the scan actually covered, so a clean report is never mistaken for a safe app."""

    pages_crawled: int = 0
    pages_limit: int = 0
    pages_truncated: bool = False
    urls_discovered: int = 0
    parameters_discovered: int = 0
    parameters_tested: int = 0
    params_limit: int = 0
    params_truncated: bool = False
    forms_discovered: int = 0
    modules_run: list[str] = field(default_factory=list)
    modules_failed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Coverage:
        if not data:
            return cls()
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


RISK_FORMULA = "100 × (1 − e^(−total_weight / 25))"


def compute_risk(total_weight: float) -> float:
    if total_weight <= 0:
        return 0.0
    return round(100 * (1 - math.exp(-total_weight / 25.0)), 1)


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    coverage: Coverage = field(default_factory=Coverage)
    modules: list[str] = field(default_factory=list)
    tool_version: str = __version__
    scan_id: str = ""

    def __post_init__(self) -> None:
        if not self.scan_id:
            self.scan_id = ScanResult.make_id(self.target, self.started_at)

    @staticmethod
    def make_id(target: str, started_at: str) -> str:
        raw = f"{target}|{started_at}|{time.time_ns()}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def risk_score(self) -> float:
        """0-100 aggregate score. Higher means more risk."""
        return compute_risk(sum(f.weight for f in self.findings))

    def risk_breakdown(self) -> dict[str, Any]:
        """Explain the score: which severities contributed how much."""
        counts = self.counts()
        total = 0.0
        contributions: list[dict[str, Any]] = []
        for severity in SEVERITY_ORDER:
            weight = SEVERITY_WEIGHT[severity]
            points = counts[severity] * weight
            total += points
            contributions.append(
                {
                    "severity": severity,
                    "count": counts[severity],
                    "weight": weight,
                    "points": round(points, 2),
                }
            )
        for item in contributions:
            item["share"] = round(100 * item["points"] / total, 1) if total else 0.0
        return {
            "score": compute_risk(total),
            "formula": RISK_FORMULA,
            "total_weight": round(total, 2),
            "contributions": contributions,
        }

    def to_dict(self) -> dict[str, Any]:
        self.stats.params_tested = self.coverage.parameters_tested
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tool_version": self.tool_version,
            "modules": self.modules,
            "stats": dataclasses.asdict(self.stats),
            "coverage": self.coverage.to_dict(),
            "risk": self.risk_breakdown(),
            "risk_score": self.risk_score(),
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        stats = ScanStats(**data.get("stats", {}))
        result = cls(
            target=data["target"],
            started_at=data.get("started_at", ""),
            finished_at=data.get("finished_at", ""),
            stats=stats,
            coverage=Coverage.from_dict(data.get("coverage")),
            modules=data.get("modules", []),
            tool_version=data.get("tool_version", __version__),
            scan_id=data.get("scan_id", ""),
        )
        for item in data.get("findings", []):
            item = {k: v for k, v in item.items() if k != "id"}
            result.findings.append(Finding(**item))
        return result
