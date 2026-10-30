from __future__ import annotations

import time

from atlasscan.core.body import body_content_type, body_variants
from atlasscan.core.context import ScanContext
from atlasscan.core.crawler import is_safe_to_submit
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
    description = (
        "Error-based (and optional time-based) SQL injection in GET parameters, POST forms "
        "and JSON bodies"
    )

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0
        seen: set[tuple[str, str]] = set()

        # --------------------------------------------------------------- GET
        for page in ctx.pages:
            for name in param_names(page):
                if not self._take_budget(ctx, tested):
                    return findings
                if (page, name) in seen:
                    continue
                seen.add((page, name))
                tested += 1
                ctx.mark_param(page, name)

                for payload in ERROR_PAYLOADS:
                    url = with_param(page, name, payload)
                    response = ctx.client.get(url)
                    if response is None:
                        continue
                    item = self._error_finding(
                        response, url, f"Parameter: {name}", "GET", payload
                    )
                    if item:
                        findings.append(item)
                        break

                if ctx.options.time_based:
                    finding_time = self._time_based(ctx, page, name)
                    if finding_time:
                        findings.append(finding_time)

        # -------------------------------------------------------------- POST
        if ctx.options.post_forms:
            for form in ctx.forms:
                if not is_safe_to_submit(form):
                    continue
                for name in form.fields:
                    if (form.action, name) in seen:
                        continue
                    seen.add((form.action, name))
                    if not self._take_budget(ctx, tested):
                        return findings
                    tested += 1
                    ctx.mark_param(form.action, name)

                    for payload in ERROR_PAYLOADS:
                        data = {
                            field: (form.values.get(field) or "atlas")
                            for field in form.fields
                        }
                        data[name] = payload
                        response = ctx.client.post(form.action, data=data)
                        if response is None:
                            continue
                        item = self._error_finding(
                            response, form.action, f"Field: {name}", "POST", payload
                        )
                        if item:
                            findings.append(item)
                            break

        # ---------------------------------------------------------- raw body
        if ctx.options.data:
            content_type = body_content_type(ctx.options.data, ctx.options.content_type)
            first = body_variants(ctx.options.data, ERROR_PAYLOADS[0])
            labels = [label for label, _ in first]
            by_payload = {
                payload: dict(body_variants(ctx.options.data, payload))
                for payload in ERROR_PAYLOADS
            }
            for label in labels:
                if not self._take_budget(ctx, tested):
                    return findings
                tested += 1
                ctx.mark_param(ctx.base_url, f"body:{label}")
                for payload in ERROR_PAYLOADS:
                    body = by_payload[payload].get(label)
                    if body is None:
                        continue
                    response = ctx.client.post(
                        ctx.base_url, data=body, headers={"Content-Type": content_type}
                    )
                    if response is None:
                        continue
                    item = self._error_finding(
                        response,
                        ctx.base_url,
                        f"Body field: {label}",
                        "POST " + content_type.split(";")[0].strip(),
                        payload,
                    )
                    if item:
                        findings.append(item)
                        break

        return findings

    def _take_budget(self, ctx: ScanContext, tested: int) -> bool:
        if tested >= ctx.options.max_params:
            ctx.budget_exhausted = True
            return False
        return True

    def _error_finding(
        self, response, url: str, location: str, method: str, payload: str
    ) -> Finding | None:
        match = detect_sql_error(response.text or "")
        if not match:
            return None
        return finding(
            "SQL injection (error-based)",
            "high",
            url,
            self.name,
            "Injecting quote characters makes the database throw an error, which means the "
            f"input ({method}) reaches a SQL query unsafely.",
            evidence=f"Method: {method}\n{location}\nPayload: {payload}\nDB error: {match}",
            remediation="Use parameterized queries / prepared statements and validate input types.",
            cwe="CWE-89",
            owasp="A03:2021",
        )

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
