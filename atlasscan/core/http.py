"""Thin wrapper around requests with throttling, retries and counters."""

from __future__ import annotations

import random
import time
from typing import Any, Callable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from atlasscan.config import DEFAULT_UA


class HttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.15,
        user_agent: str = DEFAULT_UA,
        verify: bool = True,
        retries: int = 2,
        proxies: Optional[dict[str, str]] = None,
        extra_headers: Optional[dict[str, str]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.verify = verify
        self.logger = logger
        self.request_count = 0
        self.error_count = 0
        self._last_request = 0.0

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            }
        )
        if extra_headers:
            self.session.headers.update(extra_headers)

        if proxies:
            self.session.proxies.update(proxies)

        retry = Retry(
            total=retries,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        now = time.monotonic()
        wait = self.delay - (now - self._last_request)
        if wait > 0:
            time.sleep(wait + random.uniform(0, self.delay * 0.3))
        self._last_request = time.monotonic()

    def request(self, method: str, url: str, **kwargs: Any) -> Optional[requests.Response]:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", True)
        self.request_count += 1
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            if self.verify:
                # Retry once without verification so the scan can continue and
                # the TLS module can report the certificate problem properly.
                kwargs["verify"] = False
                try:
                    self.request_count += 1
                    return self.session.request(method, url, **kwargs)
                except requests.RequestException as exc:
                    self._fail(url, exc)
                    return None
            self._fail(url, RuntimeError("TLS verification failed"))
            return None
        except requests.RequestException as exc:
            self._fail(url, exc)
            return None

    def _fail(self, url: str, exc: Exception) -> None:
        self.error_count += 1
        if self.logger:
            self.logger(f"request failed: {url} ({exc.__class__.__name__})")

    def get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
