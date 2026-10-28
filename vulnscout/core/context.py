from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from vulnscout.core.crawler import Form
from vulnscout.core.http import HttpClient


@dataclass
class ScanOptions:
    crawl: bool = True
    max_pages: int = 25
    max_depth: int = 2
    timeout: float = 10.0
    delay: float = 0.15
    verify: bool = True
    default_creds: bool = False
    time_based: bool = False
    max_params: int = 40
    active: bool = True
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanContext:
    client: HttpClient
    base_url: str
    options: ScanOptions
    pages: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    log: Callable[[str], None] = lambda message: None
