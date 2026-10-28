"""Very small HTML crawler built on the standard library parser (no bs4 dependency)."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from atlasscan.core.http import HttpClient
from atlasscan.core.utils import normalize_url

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dmg", ".apk",
)


@dataclass
class Form:
    action: str
    method: str = "GET"
    fields: list[str] = field(default_factory=list)


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._current_form: Form | None = None
        self.title = ""
        self._in_title = False
        self.scripts: list[str] = []
        self.comments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and data.get("href"):
            self.links.append(urljoin(self.base_url, data["href"]))
        elif tag in ("script", "img", "iframe", "source") and data.get("src"):
            self.links.append(urljoin(self.base_url, data["src"]))
        elif tag == "link" and data.get("href"):
            self.links.append(urljoin(self.base_url, data["href"]))
        elif tag == "form":
            action = urljoin(self.base_url, data.get("action") or self.base_url)
            self._current_form = Form(action=action, method=(data.get("method") or "GET").upper())
            self.forms.append(self._current_form)
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            if data.get("name") and data.get("type", "").lower() not in ("submit", "button", "reset", "file"):
                self._current_form.fields.append(data["name"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(urljoin(self.base_url, data["src"]))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()

    def handle_comment(self, data: str) -> None:
        comment = data.strip()
        if comment:
            self.comments.append(comment[:300])


def parse_page(html: str, url: str) -> PageParser:
    parser = PageParser(url)
    try:
        parser.feed(html)
    except Exception:  # malformed HTML should never kill a scan
        pass
    return parser


def is_crawlable(url: str, root: str, scope_netloc: str | None = None) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    netloc = (scope_netloc or urlparse(root).netloc).lower()
    if parsed.netloc.lower() != netloc:
        return False
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return False
    if "logout" in path or "signout" in path or "delete" in path:
        return False
    return True


def crawl(
    client: HttpClient,
    start_url: str,
    max_pages: int = 25,
    max_depth: int = 2,
    scope_netloc: str | None = None,
) -> tuple[list[str], list[Form]]:
    """Breadth-first crawl returning unique URLs and discovered forms."""
    root = normalize_url(start_url)
    seen: set[str] = {root}
    queue: list[tuple[str, int]] = [(root, 0)]
    urls: list[str] = []
    forms: list[Form] = []

    while queue and len(urls) < max_pages:
        url, depth = queue.pop(0)
        response = client.get(url)
        if response is None or "html" not in response.headers.get("Content-Type", "").lower():
            urls.append(url)
            continue
        urls.append(url)
        if depth >= max_depth:
            continue
        parser = parse_page(response.text, url)
        for form in parser.forms:
            if is_crawlable(form.action, root, scope_netloc):
                forms.append(form)
        for link in parser.links:
            clean = normalize_url(link)
            if clean not in seen and is_crawlable(clean, root, scope_netloc):
                seen.add(clean)
                queue.append((clean, depth + 1))

    return urls, forms
