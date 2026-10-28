from __future__ import annotations

import re

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding


class HeadersModule:
    name = "headers"
    description = "Missing security headers and information disclosure"

    CHECKS = [
        (
            "content-security-policy",
            "medium",
            "Missing Content-Security-Policy",
            "Without a CSP, the impact of any injected script (XSS) is much higher.",
            "Set a restrictive Content-Security-Policy (start with `default-src 'self'`).",
            "CWE-693",
            "A05:2021",
        ),
        (
            "x-content-type-options",
            "low",
            "Missing X-Content-Type-Options",
            "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
            "Send `X-Content-Type-Options: nosniff` on every response.",
            "CWE-693",
            "A05:2021",
        ),
        (
            "referrer-policy",
            "low",
            "Missing Referrer-Policy",
            "Sensitive URL data can leak to third parties through the Referer header.",
            "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
            "CWE-200",
            "A01:2021",
        ),
        (
            "permissions-policy",
            "info",
            "Missing Permissions-Policy",
            "Browser features (camera, geolocation, ...) are not explicitly restricted.",
            "Define a Permissions-Policy that disables features the app does not need.",
            "CWE-693",
            "A05:2021",
        ),
    ]

    VERSION_RE = re.compile(r"\d+\.\d+")

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        response = ctx.client.get(ctx.base_url)
        if response is None:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        url = response.url

        for header, severity, title, why, fix, cwe, owasp in self.CHECKS:
            if header not in headers:
                findings.append(
                    finding(
                        title,
                        severity,
                        url,
                        self.name,
                        why,
                        evidence=f"Header `{header}` not present in the response.",
                        remediation=fix,
                        cwe=cwe,
                        owasp=owasp,
                    )
                )

        is_https = url.lower().startswith("https://")
        if is_https and "strict-transport-security" not in headers:
            findings.append(
                finding(
                    "Missing Strict-Transport-Security",
                    "low",
                    url,
                    self.name,
                    "HSTS is not enabled, so the first request may be downgraded to plain HTTP.",
                    evidence="Header `Strict-Transport-Security` not present.",
                    remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                    cwe="CWE-319",
                    owasp="A02:2021",
                )
            )

        csp = headers.get("content-security-policy", "")
        xfo = headers.get("x-frame-options", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            findings.append(
                finding(
                    "Missing clickjacking protection",
                    "medium",
                    url,
                    self.name,
                    "The page can be framed by an attacker to trick users into unintended clicks.",
                    evidence="Neither `X-Frame-Options` nor CSP `frame-ancestors` is set.",
                    remediation="Send `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.",
                    cwe="CWE-1021",
                    owasp="A05:2021",
                )
            )

        if csp:
            lowered = csp.lower()
            weak = []
            if "'unsafe-inline'" in lowered:
                weak.append("'unsafe-inline'")
            if "'unsafe-eval'" in lowered:
                weak.append("'unsafe-eval'")
            if re.search(r"(script-src|default-src)[^;]*\*", lowered):
                weak.append("wildcard source")
            if weak:
                findings.append(
                    finding(
                        "Weak Content-Security-Policy",
                        "low",
                        url,
                        self.name,
                        "The CSP contains directives that significantly weaken XSS mitigation.",
                        evidence=f"Weak directives: {', '.join(weak)}\nCSP: {csp[:300]}",
                        remediation="Remove unsafe-inline/unsafe-eval and avoid wildcard sources; use nonces or hashes.",
                        cwe="CWE-693",
                        owasp="A05:2021",
                    )
                )

        for header, label in (
            ("server", "Server"),
            ("x-powered-by", "X-Powered-By"),
            ("x-aspnet-version", "X-AspNet-Version"),
            ("x-generator", "X-Generator"),
        ):
            value = headers.get(header)
            if value and (self.VERSION_RE.search(value) or header != "server"):
                findings.append(
                    finding(
                        "Technology/version disclosure",
                        "low",
                        url,
                        self.name,
                        f"The `{label}` header reveals software details that help attackers pick exploits.",
                        evidence=f"{label}: {value}",
                        remediation=f"Remove or obfuscate the `{label}` response header.",
                        cwe="CWE-200",
                        owasp="A05:2021",
                    )
                )

        return findings
