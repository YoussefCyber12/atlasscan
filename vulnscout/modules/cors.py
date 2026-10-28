from __future__ import annotations

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding

EVIL_ORIGIN = "https://vulnscout.invalid"


class CorsModule:
    name = "cors"
    description = "Permissive CORS configuration"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        response = ctx.client.get(ctx.base_url, headers={"Origin": EVIL_ORIGIN})
        if response is None:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_creds = headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin == EVIL_ORIGIN and allow_creds:
            findings.append(
                finding(
                    "CORS misconfiguration with credentials",
                    "high",
                    response.url,
                    self.name,
                    "Any origin is reflected in Access-Control-Allow-Origin while credentials are "
                    "allowed, so a malicious site can read authenticated responses.",
                    evidence=f"Origin: {EVIL_ORIGIN}\nACAO: {allow_origin}\nACAC: true",
                    remediation="Reflect only trusted origins from an allowlist and avoid wildcard/`null`.",
                    cwe="CWE-942",
                    owasp="A01:2021",
                )
            )
        elif allow_origin == EVIL_ORIGIN:
            findings.append(
                finding(
                    "Reflected CORS origin",
                    "medium",
                    response.url,
                    self.name,
                    "The server reflects any Origin header, which exposes responses to arbitrary websites.",
                    evidence=f"Origin: {EVIL_ORIGIN}\nACAO: {allow_origin}",
                    remediation="Validate Origin against an allowlist before returning CORS headers.",
                    cwe="CWE-942",
                    owasp="A01:2021",
                )
            )
        elif allow_origin == "*" and allow_creds:
            findings.append(
                finding(
                    "Wildcard CORS with credentials",
                    "medium",
                    response.url,
                    self.name,
                    "A wildcard origin combined with credentials is an invalid and risky configuration.",
                    evidence="ACAO: *\nACAC: true",
                    remediation="Never combine `*` with credentials; reflect an allowlisted origin instead.",
                    cwe="CWE-942",
                    owasp="A01:2021",
                )
            )

        if allow_origin == "null":
            findings.append(
                finding(
                    "CORS allows 'null' origin",
                    "medium",
                    response.url,
                    self.name,
                    "The `null` origin can be forged by sandboxed iframes and local files.",
                    evidence="ACAO: null",
                    remediation="Do not allow the `null` origin.",
                    cwe="CWE-942",
                    owasp="A01:2021",
                )
            )

        return findings
