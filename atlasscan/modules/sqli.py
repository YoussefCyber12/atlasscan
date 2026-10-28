from __future__ import annotations

import time

from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding
from atlasscan.core.utils import detect_sql_error, finding, param_names, with_param

ERROR_PAYLOADS = ("'", '"', "')", "\\'")
TIME_PAYLOADS = (
    ("' OR SLEEP(3)-- -", 3.0),
    ("'; SELECT pg_sleep(3)-- -", 3.0),
    ("' WAITFOR DELAY '0:0:3'-- -", 3.0),
    ("' OR SLEEP(3)#", 3.0),
)
TIME_THRESHOLD = 2.2


class SqliModule:
    name = "sqli"
    description = "Error-based (and optional time-based) SQL injection in GET parameters"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0
        seen: set[tuple[str, str]] = set()

        for page in ctx.pages:
            for name in param_names(page):
                if tested >= ctx.options.max_params:
                    return findings
                if (page, name) in seen:
                    continue
                seen.add((page, name))
                tested += 1

                for payload in ERROR_PAYLOADS:
                    url = with_param(page, name, payload)
                    response = ctx.client.get(url)
                    if response is None:
                        continue
                    match = detect_sql_error(response.text or "")
                    if match:
                        findings.append(
                            finding(
                                "SQL injection (error-based)",
                                "high",
                                url,
                                self.name,
                                "Injecting quote characters makes the database throw an error, which "
                                "means the parameter reaches a SQL query unsafely.",
                                evidence=f"Parameter: {name}\nPayload: {payload}\nDB error: {match}",
                                remediation="Use parameterized queries / prepared statements and validate input types.",
                                cwe="CWE-89",
                                owasp="A03:2021",
                            )
                        )
                        break

                if ctx.options.time_based:
                    finding_time = self._time_based(ctx, page, name)
                    if finding_time:
                        findings.append(finding_time)

        return findings

    def _time_based(self, ctx: ScanContext, page: str, name: str) -> Finding | None:
        baseline = ctx.client.get(page)
        if baseline is None:
            return None
        base_time = baseline.elapsed.total_seconds()

        for payload, expected in TIME_PAYLOADS:
            url = with_param(page, name, payload)
            started = time.monotonic()
            response = ctx.client.get(url)
            elapsed = time.monotonic() - started
            if response is None:
                continue
            delta = elapsed - max(base_time, 0.05)
            if delta >= TIME_THRESHOLD and elapsed >= expected * 0.8:
                return finding(
                    "SQL injection (time-based)",
                    "high",
                    url,
                    self.name,
                    "The response was delayed by the injected SQL sleep function, indicating the "
                    "parameter is evaluated inside a database query.",
                    evidence=(
                        f"Parameter: {name}\nPayload: {payload}\n"
                        f"Baseline: {base_time:.2f}s, injected: {elapsed:.2f}s"
                    ),
                    remediation="Use parameterized queries / prepared statements.",
                    cwe="CWE-89",
                    owasp="A03:2021",
                )
        return None
