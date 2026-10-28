from __future__ import annotations

from atlasscan.core.context import ScanContext
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding

# path -> (regex signature, severity, title, description, remediation, cwe)
SENSITIVE_PATHS = [
    (
        "/.git/HEAD",
        r"ref:\s+refs/",
        "high",
        "Exposed Git repository",
        "The .git directory is served publicly; the full source code and history can be reconstructed.",
        "Block access to dotfiles and version-control directories at the web server level.",
        "CWE-538",
    ),
    (
        "/.git/config",
        r"\[core\]",
        "high",
        "Exposed Git config",
        "The Git configuration is readable and may contain remote URLs or credentials.",
        "Block access to the .git directory.",
        "CWE-538",
    ),
    (
        "/.env",
        r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=",
        "critical",
        "Exposed .env file",
        "Environment variables with secrets (DB passwords, API keys) are publicly readable.",
        "Move secrets out of the web root and deny dotfiles.",
        "CWE-538",
    ),
    (
        "/.svn/entries",
        r"\d+",
        "high",
        "Exposed SVN metadata",
        "Subversion metadata is exposed, allowing source code recovery.",
        "Remove .svn directories from deployments or block access.",
        "CWE-538",
    ),
    (
        "/.DS_Store",
        r"\x00\x00\x00\x01Bud1",
        "low",
        "Exposed .DS_Store",
        "A macOS metadata file is exposed and leaks directory/file names.",
        "Exclude .DS_Store from deployments and deny dotfiles.",
        "CWE-538",
    ),
    (
        "/phpinfo.php",
        r"PHP Version|phpinfo\(\)",
        "high",
        "phpinfo() exposed",
        "The phpinfo page reveals paths, modules, environment variables and configuration.",
        "Remove phpinfo() from production.",
        "CWE-200",
    ),
    (
        "/server-status",
        r"Apache Server Status|Server Status",
        "medium",
        "Apache server-status exposed",
        "Current requests, client IPs and internal URLs are exposed.",
        "Restrict /server-status to localhost.",
        "CWE-200",
    ),
    (
        "/actuator/env",
        r"\"propertySources\"|\"activeProfiles\"",
        "high",
        "Spring Actuator env exposed",
        "Actuator endpoints expose configuration and may leak credentials.",
        "Disable or secure Spring Boot Actuator endpoints.",
        "CWE-200",
    ),
    (
        "/actuator/health",
        r"\"status\"\s*:\s*\"UP\"",
        "info",
        "Spring Actuator health exposed",
        "The health endpoint is publicly reachable; usually low risk but confirms Actuator is on.",
        "Restrict Actuator endpoints to internal networks.",
        "CWE-200",
    ),
    (
        "/swagger-ui.html",
        r"swagger|Swagger UI",
        "info",
        "Swagger UI exposed",
        "API documentation is public and makes hidden endpoints easier to find.",
        "Protect API documentation in production.",
        "CWE-200",
    ),
    (
        "/backup.zip",
        r"PK\x03\x04",
        "high",
        "Backup archive exposed",
        "A backup archive is downloadable and likely contains source code or data.",
        "Remove backups from the web root.",
        "CWE-538",
    ),
    (
        "/.well-known/security.txt",
        r"Contact:",
        "info",
        "security.txt present",
        "A security contact file exists (good practice).",
        "Keep the contact information up to date.",
        "CWE-1059",
    ),
]


class FilesModule:
    name = "files"
    description = "Exposed sensitive files and metadata"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        root = ctx.base_url.rstrip("/")

        for path, signature, severity, title, description, remediation, cwe in SENSITIVE_PATHS:
            url = root + path
            response = ctx.client.get(url, allow_redirects=False)
            if response is None or response.status_code not in (200, 301, 302, 403):
                continue
            if response.status_code == 403 and severity != "info":
                # A 403 means the file exists but is protected. The real fix is removing it
                # from the deployment, not hiding it behind a web-server rule.
                findings.append(
                    finding(
                        "Sensitive path exists (403)",
                        "low",
                        url,
                        self.name,
                        f"`{path}` returns 403, so the resource is still deployed even though "
                        "access is blocked. Any web-server misconfiguration re-exposes it.",
                        evidence=f"HTTP 403 for {path}",
                        remediation=(
                            "Remove the file/directory from the production docroot (build artifact). "
                            "Blocking it in Nginx/Apache is only a fallback, not a fix."
                        ),
                        cwe=cwe,
                    )
                )
                continue
            if response.status_code != 200:
                continue

            body = response.text or ""
            raw = response.content or b""
            if not _matches(signature, body, raw):
                continue

            findings.append(
                finding(
                    title,
                    severity,
                    url,
                    self.name,
                    description,
                    evidence=f"HTTP 200 for {path}\n{body[:180].strip()}",
                    remediation=remediation,
                    cwe=cwe,
                )
            )

        return findings


def _matches(signature: str, text: str, raw: bytes) -> bool:
    import re

    if signature.startswith("PK"):
        return raw.startswith(b"PK\x03\x04")
    if signature.startswith("\\x00"):
        return b"Bud1" in raw[:64]
    return bool(re.search(signature, text))
