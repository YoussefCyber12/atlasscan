from __future__ import annotations

from typing import Protocol

from vulnscout.core.context import ScanContext
from vulnscout.core.models import Finding


class Module(Protocol):
    name: str
    description: str

    def run(self, ctx: ScanContext) -> list[Finding]:
        ...
