from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding


class TlsModule:
    name = "tls"
    description = "TLS certificate and protocol weaknesses"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.base_url)
        if parsed.scheme != "https":
            return findings

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return findings

        try:
            cert = self._peer_cert(host, port, ctx.options.timeout)
        except (ssl.SSLError, OSError) as exc:
            findings.append(
                finding(
                    "TLS handshake failed",
                    "medium",
                    ctx.base_url,
                    self.name,
                    "A trusted TLS connection could not be established.",
                    evidence=str(exc),
                    remediation="Install a valid certificate chain from a trusted CA.",
                    cwe="CWE-295",
                    owasp="A02:2021",
                )
            )
            return findings

        if cert is None:
            return findings

        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    finding(
                        "TLS certificate expired",
                        "high",
                        ctx.base_url,
                        self.name,
                        "The certificate is expired, so browsers show a security warning.",
                        evidence=f"notAfter: {not_after}",
                        remediation="Renew the certificate and automate renewal.",
                        cwe="CWE-298",
                        owasp="A02:2021",
                    )
                )
            elif days_left < 30:
                findings.append(
                    finding(
                        "TLS certificate expires soon",
                        "low",
                        ctx.base_url,
                        self.name,
                        "The certificate expires in less than 30 days.",
                        evidence=f"notAfter: {not_after} ({days_left} days left)",
                        remediation="Renew the certificate before it expires.",
                        cwe="CWE-298",
                        owasp="A02:2021",
                    )
                )
            else:
                findings.append(
                    finding(
                        "TLS certificate information",
                        "info",
                        ctx.base_url,
                        self.name,
                        "Certificate details collected during the scan.",
                        evidence=(
                            f"subject: {cert.get('subject')}\nissuer: {cert.get('issuer')}\n"
                            f"notBefore: {not_before}\nnotAfter: {not_after}"
                        ),
                        remediation="No action needed.",
                        cwe="CWE-295",
                        owasp="A02:2021",
                    )
                )
        except (TypeError, ValueError):
            pass

        for protocol, label in ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1")):
            if self._supports(host, port, protocol, ctx.options.timeout):
                findings.append(
                    finding(
                        f"Deprecated {label} supported",
                        "medium",
                        ctx.base_url,
                        self.name,
                        f"The server negotiates {label}, which is deprecated and has known weaknesses.",
                        evidence=f"{label} handshake succeeded with {host}:{port}",
                        remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
                        cwe="CWE-326",
                        owasp="A02:2021",
                    )
                )

        return findings

    def _peer_cert(self, host: str, port: int, timeout: float):
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert()

    def _supports(self, host: str, port: int, version, timeout: float) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, ssl.SSLError):
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError):
            return False
