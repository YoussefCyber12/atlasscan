"""A deliberately vulnerable local app, useful to try AtlasScan without touching a real site.

    python examples/vulnerable_app.py
    atlasscan scan http://127.0.0.1:8080 --authorized

This server is intentionally insecure and MUST NOT be exposed to a network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def weak_jwt() -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "demo", "role": "admin"}).encode())
    signature = b64(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


INDEX = """<!doctype html>
<html><head><title>AtlasScan demo</title></head>
<body>
  <h1>Deliberately vulnerable demo</h1>
  <a href="/search?q=hello">Search</a>
  <a href="/item?id=1">Item</a>
  <a href="/go?next=/home">Continue</a>
  <form method="post" action="/login">
    <input name="user"><input name="pass" type="password">
    <button>Login</button>
  </form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.0"

    def log_message(self, *args) -> None:
        pass

    def _send(self, code: int, body: str, headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send(200, "<html><body>logged in (no CSRF token, no validation)</body></html>")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/":
            self._send(
                200,
                INDEX,
                {
                    "Set-Cookie": f"session={weak_jwt()}; Path=/",
                    "Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        elif parsed.path == "/search":
            q = query.get("q", [""])[0]
            # Intentionally reflects input without encoding -> XSS
            self._send(200, f"<html><body>Results for {q}</body></html>")
        elif parsed.path == "/item":
            value = query.get("id", [""])[0]
            if "'" in value:
                self._send(
                    200,
                    "You have an error in your SQL syntax; check the manual that corresponds "
                    "to your MySQL server version",
                )
            else:
                self._send(200, "<html><body>item ok</body></html>")
        elif parsed.path == "/go":
            # Open redirect
            self.send_response(302)
            self.send_header("Location", query.get("next", ["/"])[0])
            self.end_headers()
        else:
            self._send(404, "not found")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    print("Vulnerable demo running on http://127.0.0.1:8080 (press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
