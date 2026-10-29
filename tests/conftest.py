from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(secret: str = "secret") -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1", "role": "admin"}).encode())
    signature = b64(
        hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


INDEX = """<!doctype html>
<html><head><title>Test app</title></head>
<body>
  <a href="/search?q=hello">Search</a>
  <a href="/sqli?id=1">Item</a>
  <a href="/go?next=/home">Continue</a>
  <form method="post" action="/login">
    <input type="text" name="user">
    <input type="password" name="pass">
  </form>
  <form method="post" action="/wp-login.php?action=postpass">
    <input type="password" name="post_password">
  </form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "TestServer/1.0"

    def log_message(self, *args) -> None:  # keep test output clean
        pass

    def _send(self, code: int, body: str, headers: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(200, "<html><body>ok</body></html>")

    def do_OPTIONS(self) -> None:
        self._send(200, "", {"Allow": "GET, HEAD, OPTIONS, PUT, TRACE"})

    def do_TRACE(self) -> None:
        body = f"TRACE {self.path} HTTP/1.1\r\nHost: {self.headers.get('Host', '')}\r\n\r\n"
        self._send(200, body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            headers = {
                "Set-Cookie": f"session={make_jwt()}; Path=/",
                "Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
                "Access-Control-Allow-Credentials": "true",
            }
            self._send(200, INDEX, headers)
        elif path == "/search":
            q = query.get("q", [""])[0]
            self._send(200, f"<html><body>Results for {q}</body></html>")
        elif path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value:
                self._send(
                    200,
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version",
                )
            else:
                self._send(200, "<html><body>id ok</body></html>")
        elif path == "/go":
            target = query.get("next", [""])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        elif path == "/.git/HEAD":
            # Exists but is protected -> must be reported as "remove it from the docroot".
            self._send(403, "forbidden")
        else:
            self._send(404, "not found")


@pytest.fixture(scope="session")
def server_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
