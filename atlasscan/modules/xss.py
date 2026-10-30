from __future__ import annotations

import random

from atlasscan.core.body import body_content_type, body_variants
from atlasscan.core.context import ScanContext
from atlasscan.core.crawler import is_safe_to_submit
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding, param_names, with_param

PAYLOAD_TEMPLATE = 'vs{marker}"\'><svg/onload=alert({marker})>'


class XssModule:
    name = "xss"
    description = "Reflected cross-site scripting in GET parameters, POST forms and JSON bodies"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0

        # --------------------------------------------------------------- GET
        for page in ctx.pages:
            for name in param_names(page):
                if not self._take_budget(ctx, tested):
                    return findings
                tested += 1

                marker, payload = self._probe()
                url = with_param(page, name, payload)
                ctx.mark_param(page, name)
                response = ctx.client.get(url)
                if response is None:
                    continue
                item = self._reflection(response, marker, url, f"Parameter: {name}", "GET")
                if item:
                    findings.append(item)

        # -------------------------------------------------------------- POST
        if ctx.options.post_forms:
            seen: set[tuple[str, str]] = set()
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

                    marker, payload = self._probe()
                    data = {field: (form.values.get(field) or "atlas") for field in form.fields}
                    data[name] = payload
                    ctx.mark_param(form.action, name)
                    response = ctx.client.post(form.action, data=data)
                    if response is None:
                        continue
                    item = self._reflection(
                        response, marker, form.action, f"Field: {name}", "POST"
                    )
                    if item:
                        findings.append(item)

        # ---------------------------------------------------------- raw body
        if ctx.options.data:
            marker, payload = self._probe()
            content_type = body_content_type(ctx.options.data, ctx.options.content_type)
            for label, body in body_variants(ctx.options.data, payload):
                if not self._take_budget(ctx, tested):
                    return findings
                tested += 1
                ctx.mark_param(ctx.base_url, f"body:{label}")
                response = ctx.client.post(
                    ctx.base_url, data=body, headers={"Content-Type": content_type}
                )
                if response is None:
                    continue
                item = self._reflection(
                    response,
                    marker,
                    ctx.base_url,
                    f"Body field: {label}",
                    "POST " + content_type.split(";")[0].strip(),
                )
                if item:
                    findings.append(item)

        return findings

    def _take_budget(self, ctx: ScanContext, tested: int) -> bool:
        if tested >= ctx.options.max_params:
            ctx.budget_exhausted = True
            return False
        return True

    @staticmethod
    def _probe() -> tuple[str, str]:
        marker = str(random.randint(1000, 9999))
        return marker, PAYLOAD_TEMPLATE.format(marker=marker)

    def _reflection(
        self, response, marker: str, url: str, location: str, method: str
    ) -> Finding | None:
        body = response.text or ""
        idx = body.find(marker)
        if idx == -1:
            return None

        # The marker is reflected; check whether the dangerous characters around it
        # survived unencoded (i.e. a real HTML injection point).
        window = body[idx: idx + 160]
        if "<svg/onload=" not in window:
            return None

        snippet = body[max(0, idx - 100): idx + 160].replace("\n", " ")
        return finding(
            "Reflected XSS",
            "medium",
            url,
            self.name,
            "User input is reflected in the HTML response without encoding, so a crafted "
            f"request ({method}) can execute JavaScript in the victim's browser.",
            evidence=f"Method: {method}\n{location}\n{_snippet(snippet)}",
            remediation="HTML-encode all user input, use a strict CSP and validate parameters.",
            cwe="CWE-79",
            owasp="A03:2021",
        )


def _snippet(text: str, limit: int = 190) -> str:
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")
