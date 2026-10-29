from __future__ import annotations

from atlasscan import __version__

SEVERITIES = ("critical", "high", "medium", "low", "info")

SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

SEVERITY_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}

DEFAULT_UA = f"AtlasScan/{__version__} (+https://github.com/YoussefCyber12/atlasscan)"
