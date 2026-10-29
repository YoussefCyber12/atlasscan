"""SARIF 2.1.0 export so scan results can be uploaded to GitHub code scanning."""

from __future__ import annotations

import json
import re
from typing import Any

from atlasscan import __version__
from atlasscan.core.models import Finding, ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub's code scanning UI ranks results with this property (0-10, CVSS-like).
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "finding"


def rule_id(finding: Finding) -> str:
    return f"atlasscan/{finding.module}/{_slug(finding.name)}"


def _rule(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id(finding),
        "name": finding.name,
        "shortDescription": {"text": finding.name},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": LEVELS[finding.severity]},
        "properties": {
            "tags": ["security", finding.module],
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "severity": finding.severity,
        },
    }
    if finding.remediation:
        rule["help"] = {"text": finding.remediation, "markdown": finding.remediation}
    if finding.cwe:
        rule["properties"]["cwe"] = finding.cwe
    if finding.owasp:
        rule["properties"]["owasp"] = finding.owasp
    return rule


def _result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule_id(finding),
        "level": LEVELS[finding.severity],
        "message": {"text": finding.description or finding.name},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.url},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
        ],
        "partialFingerprints": {"atlasscanFindingId/v1": finding.id},
        "properties": {
            "severity": finding.severity,
            "module": finding.module,
            "confidence": finding.confidence,
            "url": finding.url,
        },
    }
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence
    if finding.remediation:
        result["properties"]["remediation"] = finding.remediation
    if finding.cwe:
        result["properties"]["cwe"] = finding.cwe
    if finding.owasp:
        result["properties"]["owasp"] = finding.owasp
    return result


def build_sarif(result: ScanResult) -> dict[str, Any]:
    findings = result.sorted_findings()
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(rule_id(finding), _rule(finding))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "AtlasScan",
                "informationUri": "https://github.com/YoussefCyber12/atlasscan",
                "version": __version__,
                "rules": list(rules.values()),
            }
        },
        "automationDetails": {"id": f"atlasscan/{result.scan_id or 'scan'}"},
        "results": [_result(finding) for finding in findings],
        "properties": {
            "risk_score": result.risk_score(),
            "baseline_scan_id": result.baseline_scan_id,
            "suppressed": result.suppressed,
            "coverage": result.coverage.to_dict(),
        },
    }
    if result.modules:
        run["properties"]["modules"] = result.modules
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render_sarif(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(build_sarif(result), indent=indent, ensure_ascii=False)
