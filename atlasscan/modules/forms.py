from __future__ import annotations

from urllib.parse import urlparse

from atlasscan.core.context import ScanContext
from atlasscan.core.crawler import Form
from atlasscan.core.models import Finding
from atlasscan.core.utils import finding

TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "_token", "nonce")

# Forms that are not authenticated state-changing actions. Flagging them as CSRF is noise and
# makes the whole report less credible.
SEARCH_FIELDS = {"s", "q", "query", "search", "keyword", "keywords", "term", "terms"}
BENIGN_ACTIONS = (
    "wp-comments-post.php",  # public commenting
    "wp-signup.php",  # public registration
    "wp-login.php",  # handled below: only the post-password form is exempt
)


def _benign(form: Form) -> bool:
    parsed = urlparse(form.action)
    path = parsed.path.lower()
    action_query = parsed.query.lower()
    fields = {field.lower() for field in form.fields}

    if any(hint in path for hint in BENIGN_ACTIONS[:2]):
        return True
    if "wp-login.php" in path:
        # WordPress "protected post" form: not an authenticated action, no CSRF possible.
        if "action=postpass" in action_query or fields == {"post_password"}:
            return True
        if "action=lostpassword" in action_query:
            return True
    if fields == {"post_password"}:
        return True
    if fields and fields <= SEARCH_FIELDS:
        return True
    return False


class FormsModule:
    name = "forms"
    description = "POST forms without CSRF tokens (known-benign forms excluded)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()

        for form in ctx.forms:
            if form.method != "POST" or not form.fields:
                continue
            if _benign(form):
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
                    "The form performs a state change without a visible CSRF token, so cross-site "
                    "requests may be accepted. Confirm manually whether the endpoint checks Origin, "
                    "Referer or SameSite cookies.",
                    evidence=f"Method: POST\nFields: {', '.join(form.fields)}",
                    remediation="Add a per-session CSRF token and validate it server-side (or rely on SameSite cookies).",
                    cwe="CWE-352",
                    owasp="A01:2021",
                )
            )

        return findings
