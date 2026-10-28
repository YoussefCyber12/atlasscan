from __future__ import annotations

import random

from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding, param_names, with_param

PAYLOAD_TEMPLATE = 'vs{marker}"\'><svg/onload=alert({marker})>'


class XssModule:
    name = "xss"
    description = "Reflected cross-site scripting in GET parameters"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0

        for page in ctx.pages:
            for name in param_names(page):
                if tested >= ctx.options.max_params:
                    ctx.budget_exhausted = True
                    return findings
                tested += 1

                marker = str(random.randint(1000, 9999))
                payload = PAYLOAD_TEMPLATE.format(marker=marker)
                url = with_param(page, name, payload)
                ctx.mark_param(page, name)
                response = ctx.client.get(url)
                if response is None:
                    continue

                body = response.text or ""
                idx = body.find(marker)
                if idx == -1:
                    continue

                # The marker is reflected; check whether the dangerous characters
                # around it survived unencoded (i.e. a real HTML injection point).
                window = body[idx: idx + 160]
                if "<svg/onload=" not in window:
                    continue

                snippet = body[max(0, idx - 100): idx + 160].replace("\n", " ")
                findings.append(
                    finding(
                        "Reflected XSS",
                        "medium",
                        url,
                        self.name,
                        "User input is reflected in the HTML response without encoding, so a crafted "
                        "link can execute JavaScript in the victim's browser.",
                        evidence=f"Parameter: {name}\n{_snippet(snippet)}",
                        remediation="HTML-encode all user input, use a strict CSP and validate parameters.",
                        cwe="CWE-79",
                        owasp="A03:2021",
                    )
                )

        return findings


def _snippet(text: str, limit: int = 190) -> str:
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")
