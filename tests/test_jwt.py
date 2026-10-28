from __future__ import annotations

import hashlib

import pytest

from atlasscan.modules.jwt import (
    b64url_decode,
    b64url_encode,
    decode_segment,
    sign_hs,
)


def make_jwt(secret: str = "secret") -> str:
    header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url_encode(b'{"sub":"1","role":"admin"}')
    signature = sign_hs(header, payload, secret, hashlib.sha256)
    return f"{header}.{payload}.{signature}"


def test_b64url_roundtrip():
    data = b'{"hello": "world"}'
    assert b64url_decode(b64url_encode(data)) == data
    assert "=" not in b64url_encode(data)


def test_decode_segment():
    token = make_jwt()
    header = decode_segment(token.split(".")[0])
    payload = decode_segment(token.split(".")[1])
    assert header["alg"] == "HS256"
    assert payload["role"] == "admin"


def test_sign_hs_matches_reference():
    header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url_encode(b'{"sub":"1"}')
    expected = b64url_encode(
        __import__("hmac").new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    assert sign_hs(header, payload, "secret", hashlib.sha256) == expected


def test_decode_segment_handles_garbage():
    assert decode_segment("not-a-token") == {}


@pytest.mark.parametrize("secret", ["secret", "changeme", "your-256-bit-secret"])
def test_weak_secret_list_detects_common_values(secret):
    from atlasscan.modules.jwt import WEAK_SECRETS

    assert secret in WEAK_SECRETS
