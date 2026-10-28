from __future__ import annotations

from atlasscan.modules.base import Module
from atlasscan.modules.cookies import CookiesModule
from atlasscan.modules.cors import CorsModule
from atlasscan.modules.files import FilesModule
from atlasscan.modules.forms import FormsModule
from atlasscan.modules.headers import HeadersModule
from atlasscan.modules.jwt import JwtModule
from atlasscan.modules.redirect import RedirectModule
from atlasscan.modules.sqli import SqliModule
from atlasscan.modules.tech import TechModule
from atlasscan.modules.tls import TlsModule
from atlasscan.modules.xss import XssModule

ALL_MODULES: dict[str, type[Module]] = {
    cls.name: cls
    for cls in (
        HeadersModule,
        CookiesModule,
        CorsModule,
        TechModule,
        FilesModule,
        TlsModule,
        FormsModule,
        JwtModule,
        XssModule,
        SqliModule,
        RedirectModule,
    )
}

DEFAULT_MODULES = [
    "headers",
    "cookies",
    "cors",
    "tech",
    "files",
    "tls",
    "forms",
    "jwt",
    "xss",
    "sqli",
    "redirect",
]


def resolve_modules(names: list[str] | None = None) -> list[Module]:
    if names:
        unknown = [name for name in names if name not in ALL_MODULES]
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(unknown)}")
        selected = names
    else:
        selected = DEFAULT_MODULES
    return [ALL_MODULES[name]() for name in selected]
