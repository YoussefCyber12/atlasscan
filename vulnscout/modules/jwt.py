from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding
from vulnscout.core.utils import finding

TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

# Small, high-signal list of secrets that show up in tutorials and real apps.
WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt", "jwtsecret", "jwt_secret",
    "password", "passw0rd", "admin", "changeme", "change_me", "test",
    "test123", "dev", "development", "staging", "production", "supersecret",
    "super_secret", "mysecret", "my_secret", "your-256-bit-secret",
    "your_jwt_secret", "your-secret-key", "s3cr3t", "s3cr3tkey", "key",
    "private", "privatekey", "token", "tokenkey", "api", "apikey", "api_key",
    "example", "sample", "demo", "default", "123456", "1234567890",
    "qwerty", "letmein", "topsecret", "top-secret", "gizli", "shhhh",
]

HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope", "scopes", "permissions")


def b64url_decode(part: str) -> bytes:
    padding = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_segment(segment: str) -> dict:
    try:
        value = json.loads(b64url_decode(segment))
        return value if isinstance(value, dict) else {}
    except (ValueError, binascii.Error):
        return {}


def sign_hs(header_b64: str, payload_b64: str, secret: str, digest) -> str:
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, digest).digest()
    return b64url_encode(signature)


def discover_tokens(response, body: str) -> dict[str, str]:
    """Return {token: source} for tokens found in cookies, links and page body."""
    found: dict[str, str] = {}
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    cookie_values: list[str] = []
    if raw_headers is not None:
        getter = getattr(raw_headers, "getlist", None) or getattr(raw_headers, "get_all", None)
        if getter:
            try:
                cookie_values = list(getter("Set-Cookie") or [])
            except Exception:
                cookie_values = []
    header_cookie = response.headers.get("Set-Cookie")
    if header_cookie:
        cookie_values.append(header_cookie)

    for cookie in cookie_values:
        for match in TOKEN_RE.finditer(cookie):
            found.setdefault(match.group(0), "cookie")
    for match in TOKEN_RE.finditer(body or ""):
        found.setdefault(match.group(0), "response body")
    return found


class JwtModule:
    name = "jwt"
    description = "JWT weaknesses: alg none, weak HMAC secret, exp/kid handling"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        response = ctx.client.get(ctx.base_url)
        if response is None:
            return findings

        tokens = discover_tokens(response, response.text or "")
        for token, source in tokens.items():
            findings.extend(self._inspect(ctx, token, source))
        return findings

    def _inspect(self, ctx: ScanContext, token: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx.base_url
        parts = token.split(".")
        if len(parts) < 2:
            return findings

        header = decode_segment(parts[0])
        payload = decode_segment(parts[1])
        alg = str(header.get("alg", "")).upper()
        evidence_base = f"Source: {source}\nToken: {token[:60]}...\nHeader: {header}"

        if alg in ("NONE", "") or "alg" not in header:
            findings.append(
                finding(
                    "JWT uses 'none' algorithm",
                    "high",
                    url,
                    self.name,
                    "A token without a real algorithm can be forged by anyone; the signature is not checked.",
                    evidence=evidence_base,
                    remediation="Reject `alg: none` explicitly and pin the expected algorithm server-side.",
                    cwe="CWE-347",
                    owasp="A02:2021",
                )
            )
        elif alg in HS_ALGS and len(parts) == 3:
            digest = HS_ALGS[alg]
            signature = parts[2]
            for secret in WEAK_SECRETS:
                if hmac.compare_digest(sign_hs(parts[0], parts[1], secret, digest), signature):
                    findings.append(
                        finding(
                            "JWT signed with a weak secret",
                            "critical",
                            url,
                            self.name,
                            "The HMAC signing key is a common word, so the token can be forged and "
                            "the application fully impersonated.",
                            evidence=f"Source: {source}\nAlgorithm: {alg}\nRecovered secret: {secret}",
                            remediation="Use a long random secret from a secret manager and rotate it.",
                            cwe="CWE-798",
                            owasp="A02:2021",
                        )
                    )
                    break

        exp = payload.get("exp")
        now = time.time()
        if exp is None:
            findings.append(
                finding(
                    "JWT has no expiration",
                    "medium",
                    url,
                    self.name,
                    "Tokens without `exp` stay valid forever, so a leak cannot be mitigated by expiry.",
                    evidence=evidence_base,
                    remediation="Always set a short `exp` and support server-side revocation.",
                    cwe="CWE-613",
                    owasp="A07:2021",
                )
            )
        elif isinstance(exp, (int, float)) and exp < now:
            findings.append(
                finding(
                    "JWT is already expired",
                    "info",
                    url,
                    self.name,
                    "The token found in the response has an `exp` in the past, which is informational.",
                    evidence=f"{evidence_base}\nexp: {exp} (now: {int(now)})",
                    remediation="Confirm the server rejects expired tokens.",
                    cwe="CWE-613",
                    owasp="A07:2021",
                )
            )

        if "kid" in header and re.search(r"[/\\.]|\.\.|select|union", str(header["kid"]), re.IGNORECASE):
            findings.append(
                finding(
                    "JWT 'kid' header may be injectable",
                    "low",
                    url,
                    self.name,
                    "The `kid` header contains path or SQL-like characters; if used to load keys it can "
                    "enable key confusion or path traversal.",
                    evidence=f"{evidence_base}\nkid: {header['kid']}",
                    remediation="Validate `kid` against a fixed key set and never use it in file paths or SQL.",
                    cwe="CWE-74",
                    owasp="A03:2021",
                )
            )

        leaked = [claim for claim in SENSITIVE_CLAIMS if claim in payload]
        if leaked:
            findings.append(
                finding(
                    "Sensitive claims stored in JWT payload",
                    "info",
                    url,
                    self.name,
                    "JWT payloads are only signed, not encrypted, so these claims are readable by users.",
                    evidence=f"{evidence_base}\nClaims: {', '.join(leaked)}",
                    remediation="Do not store secrets in the payload; treat claims as untrusted input.",
                    cwe="CWE-312",
                    owasp="A02:2021",
                )
            )

        return findings
