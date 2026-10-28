from __future__ import annotations

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding


def _set_cookie_headers(response) -> list[str]:
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None:
        for method in ("getlist", "get_all"):
            getter = getattr(headers, method, None)
            if getter:
                try:
                    values = getter("Set-Cookie")
                except Exception:
                    continue
                if values:
                    return list(values)
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


class CookiesModule:
    name = "cookies"
    description = "Cookie security attributes"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        response = ctx.client.get(ctx.base_url)
        if response is None:
            return findings

        is_https = response.url.lower().startswith("https://")

        for cookie in _set_cookie_headers(response):
            parts = [part.strip() for part in cookie.split(";") if part.strip()]
            if not parts:
                continue
            name = parts[0].split("=", 1)[0].strip()
            lowered = " ".join(parts[1:]).lower()

            if is_https and "secure" not in lowered:
                findings.append(
                    finding(
                        "Cookie without Secure flag",
                        "medium",
                        response.url,
                        self.name,
                        "The cookie can be sent over plain HTTP and intercepted on the network.",
                        evidence=cookie[:300],
                        remediation=f"Add the `Secure` attribute to cookie `{name}`.",
                        cwe="CWE-614",
                        owasp="A05:2021",
                    )
                )

            if "httponly" not in lowered:
                findings.append(
                    finding(
                        "Cookie without HttpOnly flag",
                        "medium",
                        response.url,
                        self.name,
                        "Client-side JavaScript can read this cookie, which helps session hijacking via XSS.",
                        evidence=cookie[:300],
                        remediation=f"Add the `HttpOnly` attribute to cookie `{name}`.",
                        cwe="CWE-1004",
                        owasp="A05:2021",
                    )
                )

            if "samesite" not in lowered:
                findings.append(
                    finding(
                        "Cookie without SameSite attribute",
                        "low",
                        response.url,
                        self.name,
                        "Without SameSite the cookie is sent on cross-site requests, enabling CSRF.",
                        evidence=cookie[:300],
                        remediation=f"Set `SameSite=Lax` or `SameSite=Strict` on cookie `{name}`.",
                        cwe="CWE-1275",
                        owasp="A01:2021",
                    )
                )
            elif "samesite=none" in lowered and "secure" not in lowered:
                findings.append(
                    finding(
                        "SameSite=None without Secure",
                        "medium",
                        response.url,
                        self.name,
                        "Browsers reject (or mishandle) SameSite=None cookies that are not marked Secure.",
                        evidence=cookie[:300],
                        remediation="Combine `SameSite=None` with the `Secure` attribute.",
                        cwe="CWE-614",
                        owasp="A05:2021",
                    )
                )

        return findings
