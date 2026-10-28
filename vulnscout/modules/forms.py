from __future__ import annotations

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding

TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "_token", "nonce")


class FormsModule:
    name = "forms"
    description = "Forms without CSRF tokens"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()

        for form in ctx.forms:
            if form.method != "POST" or not form.fields:
                continue
            has_token = any(hint in field.lower() for field in form.fields for hint in TOKEN_HINTS)
            if has_token or form.action in reported:
                continue
            reported.add(form.action)
            findings.append(
                finding(
                    "POST form without an anti-CSRF token",
                    "low",
                    form.action,
                    self.name,
                    "The form has no visible CSRF token field, so cross-site requests may be accepted.",
                    evidence=f"Method: POST\nFields: {', '.join(form.fields)}",
                    remediation="Add a per-session CSRF token and validate it server-side (or use SameSite cookies).",
                    cwe="CWE-352",
                    owasp="A01:2021",
                )
            )

        return findings
