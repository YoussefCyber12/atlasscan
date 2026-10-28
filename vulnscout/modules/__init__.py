from __future__ import annotations

from vulnscout.modules.base import Module
from vulnscout.modules.cookies import CookiesModule
from vulnscout.modules.cors import CorsModule
from vulnscout.modules.files import FilesModule
from vulnscout.modules.forms import FormsModule
from vulnscout.modules.headers import HeadersModule
from vulnscout.modules.jwt import JwtModule
from vulnscout.modules.redirect import RedirectModule
from vulnscout.modules.sqli import SqliModule
from vulnscout.modules.tech import TechModule
from vulnscout.modules.tls import TlsModule
from vulnscout.modules.xss import XssModule

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
