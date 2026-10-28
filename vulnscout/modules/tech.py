from __future__ import annotations

import re

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding

# (label, regex over headers+body)
SIGNATURES = [
    ("WordPress", r"wp-content/|wp-includes/|/wp-json/"),
    ("Drupal", r"Drupal\.settings|sites/default/files|drupal"),
    ("Joomla", r"/media/jui/|content=\"Joomla"),
    ("Laravel", r"laravel_session|XSRF-TOKEN|Laravel"),
    ("Django", r"csrfmiddlewaretoken|__admin_media_prefix__"),
    ("Ruby on Rails", r"csrf-token\" content=|X-Runtime"),
    ("ASP.NET", r"__VIEWSTATE|ASP\.NET|X-AspNet-Version"),
    ("Spring Boot", r"Whitelabel Error Page|spring"),
    ("Express.js", r"X-Powered-By: Express"),
    ("Next.js", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", r"__NUXT__|/_nuxt/"),
    ("React", r"data-reactroot|react-dom|__REACT_DEVTOOLS"),
    ("Vue.js", r"data-v-|vue\.runtime|__VUE__"),
    ("Angular", r"ng-version=|angular\.min\.js"),
    ("jQuery", r"jquery[\.-](\d+\.\d+\.\d+)?(\.min)?\.js"),
    ("Bootstrap", r"bootstrap[\.-](\d+\.\d+\.\d+)?(\.min)?\.(css|js)"),
    ("Cloudflare", r"cloudflare|cf-ray"),
    ("Nginx", r"Server: nginx"),
    ("Apache", r"Server: Apache"),
    ("IIS", r"Server: Microsoft-IIS"),
    ("PHP", r"X-Powered-By: PHP|PHPSESSID"),
    ("Tomcat", r"Server: Apache-Coyote|JSESSIONID"),
]

VERSION_PATTERNS = {
    "jQuery": r"jquery[\.-](\d+\.\d+\.\d+)",
    "Bootstrap": r"bootstrap[\.-](\d+\.\d+\.\d+)",
    "Angular": r"ng-version=\"([\d\.]+)\"",
    "PHP": r"X-Powered-By: PHP/([\d\.]+)",
    "Nginx": r"Server: nginx/([\d\.]+)",
    "Apache": r"Server: Apache/([\d\.]+)",
    "IIS": r"Server: Microsoft-IIS/([\d\.]+)",
}


class TechModule:
    name = "tech"
    description = "Technology fingerprinting and outdated component hints"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        response = ctx.client.get(ctx.base_url)
        if response is None:
            return findings

        haystack = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        haystack += "\n" + (response.text or "")[:200_000]
        detected = []
        for label, pattern in SIGNATURES:
            if re.search(pattern, haystack, re.IGNORECASE):
                version = ""
                version_pattern = VERSION_PATTERNS.get(label)
                if version_pattern:
                    match = re.search(version_pattern, haystack, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                detected.append(f"{label} {version}".strip())

        if detected:
            findings.append(
                finding(
                    "Technology fingerprint",
                    "info",
                    response.url,
                    self.name,
                    "Detected technologies: " + ", ".join(detected),
                    evidence=", ".join(detected),
                    remediation="Remove version banners where possible and keep components patched.",
                    cwe="CWE-200",
                    owasp="A05:2021",
                )
            )

        if re.search(r"<!--.*?(TODO|FIXME|password|api[_-]?key|secret).*?-->", response.text or "", re.IGNORECASE | re.DOTALL):
            findings.append(
                finding(
                    "Sensitive data in HTML comments",
                    "low",
                    response.url,
                    self.name,
                    "HTML comments contain development notes or potential secrets.",
                    evidence="Comment matched TODO/FIXME/password/api_key/secret.",
                    remediation="Strip comments from production builds.",
                    cwe="CWE-615",
                    owasp="A05:2021",
                )
            )

        return findings
