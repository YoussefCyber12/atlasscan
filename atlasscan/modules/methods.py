from __future__ import annotations

from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding, redact_header

# Methods that can write data or tunnel traffic. A server advertising them is worth a note;
# actually calling PUT/DELETE is out of scope (it could destroy data on the target).
WRITE_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT"}


class MethodsModule:
    name = "methods"
    description = "Dangerous HTTP methods and TRACE (cross-site tracing)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.base_url

        options = ctx.client.request("OPTIONS", base)
        allow = ""
        if options is not None and options.status_code not in (404, 405, 501):
            allow = options.headers.get("Allow", "") or options.headers.get("allow", "")

        advertised = {method.strip().upper() for method in allow.split(",") if method.strip()}
        dangerous = sorted(advertised & WRITE_METHODS)
        if dangerous:
            findings.append(
                finding(
                    "Dangerous HTTP methods advertised",
                    "low",
                    base,
                    self.name,
                    "The server advertises write-capable methods through `Allow`. If these are "
                    "reachable without authentication they allow data modification or tunnelling.",
                    evidence=f"Allow: {redact_header(allow)}",
                    remediation=(
                        "Disable methods the application does not need at the web server and "
                        "require authentication for every write operation."
                    ),
                    cwe="CWE-650",
                    owasp="A05:2021",
                    confidence="tentative",
                )
            )

        trace = ctx.client.request("TRACE", base)
        body = (trace.text or "").strip() if trace is not None else ""
        if trace is not None and trace.status_code == 200 and "TRACE" in body.upper():
            findings.append(
                finding(
                    "TRACE method enabled (cross-site tracing)",
                    "medium",
                    base,
                    self.name,
                    "TRACE reflects the request back to the client. Combined with legacy browser "
                    "bugs or a proxy that forwards cookies, this can leak HttpOnly cookies.",
                    evidence=redact_header(body.splitlines()[0] if body else "TRACE"),
                    remediation="Disable the TRACE method at the web server or reverse proxy.",
                    cwe="CWE-693",
                    owasp="A05:2021",
                )
            )

        return findings
