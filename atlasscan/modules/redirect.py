from __future__ import annotations

from urllib.parse import urlparse

from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding, param_names, with_param

SUSPICIOUS_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "redir", "next",
    "return", "returnurl", "return_url", "returnto", "dest", "destination",
    "continue", "target", "goto", "out", "link", "callback", "checkout",
    "success", "failure", "cancel", "u", "r", "view",
}

EVIL = "https://atlasscan.invalid/redirect"


class RedirectModule:
    name = "redirect"
    description = "Open redirects in redirect-style GET parameters"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for page in ctx.pages:
            for name in param_names(page):
                if name.lower() not in SUSPICIOUS_PARAMS:
                    continue
                ctx.mark_param(page, name)
                url = with_param(page, name, EVIL)
                response = ctx.client.get(url, allow_redirects=False)
                if response is None or not (300 <= response.status_code < 400):
                    continue
                location = response.headers.get("Location", "")
                if not location:
                    continue
                host = urlparse(location).netloc.lower()
                if "atlasscan.invalid" in host:
                    findings.append(
                        finding(
                            "Open redirect",
                            "medium",
                            url,
                            self.name,
                            "The application redirects to an attacker-controlled domain, which is "
                            "used in phishing and OAuth token theft.",
                            evidence=f"Parameter: {name}\nLocation: {location}",
                            remediation="Only allow relative paths or validate the target against an allowlist.",
                            cwe="CWE-601",
                            owasp="A01:2021",
                        )
                    )

        return findings
