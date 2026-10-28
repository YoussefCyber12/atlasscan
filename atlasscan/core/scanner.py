from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

from atlasscan.core.context import ScanContext, ScanOptions
from atlasscan.core.crawler import crawl
from atlasscan.core.http import HttpClient
from atlasscan.core.models import Finding, ScanResult
from atlasscan.core.utils import normalize_url, param_names
from atlasscan.modules import Module, resolve_modules

ProgressFn = Callable[[str, str], None]


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target must use http:// or https://")
    if not parsed.netloc:
        raise ValueError("target has no host")
    return normalize_url(target)


def run_scan(
    target: str,
    options: Optional[ScanOptions] = None,
    module_names: Optional[list[str]] = None,
    progress: Optional[ProgressFn] = None,
) -> ScanResult:
    """Run a full scan against `target` and return the collected findings.

    `progress(module_name, message)` is optional and used by the CLI/dashboard.
    """
    options = options or ScanOptions()
    base_url = normalize_target(target)
    modules: list[Module] = resolve_modules(module_names)

    started = datetime.now(timezone.utc)
    result = ScanResult(
        target=base_url,
        started_at=started.isoformat(timespec="seconds"),
        modules=[module.name for module in modules],
    )

    def log(message: str) -> None:
        if progress:
            progress("http", message)

    client = HttpClient(
        timeout=options.timeout,
        delay=options.delay,
        verify=options.verify,
        extra_headers=options.headers,
        proxies={"http": options.proxy, "https": options.proxy} if options.proxy else None,
        logger=log,
    )

    begin = time.monotonic()
    try:
        if options.crawl:
            if progress:
                progress("crawl", f"crawling {base_url}")
            pages, forms = crawl(
                client,
                base_url,
                max_pages=options.max_pages,
                max_depth=options.max_depth,
            )
            pages = [base_url, *[p for p in pages if p != base_url]]
        else:
            pages, forms = [base_url], []

        result.stats.pages_crawled = len(pages)
        discovered_params = {(page, name) for page in pages for name in param_names(page)}
        ctx = ScanContext(
            client=client,
            base_url=base_url,
            options=options,
            pages=pages,
            forms=forms,
            log=lambda message: progress("scan", message) if progress else None,
        )

        for module in modules:
            if progress:
                progress(module.name, f"running {module.name}")
            try:
                findings = module.run(ctx) or []
            except Exception as exc:  # a broken module must not abort the scan
                result.stats.errors += 1
                result.coverage.modules_failed.append(module.name)
                if progress:
                    progress(module.name, f"module {module.name} failed: {exc}")
                continue
            for finding in findings:
                if isinstance(finding, Finding):
                    result.add(finding)

        _fill_coverage(result, ctx, discovered_params, modules, options)
    finally:
        client.close()

    result.stats.requests = client.request_count
    result.stats.duration = round(time.monotonic() - begin, 2)
    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if progress:
        progress("done", f"{len(result.findings)} finding(s)")
    return result


def _fill_coverage(
    result: ScanResult,
    ctx: ScanContext,
    discovered_params: set[tuple[str, str]],
    modules: list[Module],
    options: ScanOptions,
) -> None:
    """Record what was actually tested so an empty result is never read as "safe"."""
    coverage = result.coverage
    coverage.pages_crawled = len(ctx.pages)
    coverage.pages_limit = options.max_pages if options.crawl else 1
    coverage.pages_truncated = options.crawl and len(ctx.pages) >= options.max_pages
    coverage.urls_discovered = len(ctx.pages)
    coverage.parameters_discovered = len(discovered_params)
    coverage.parameters_tested = len(ctx.tested_params)
    coverage.params_limit = options.max_params
    coverage.params_truncated = ctx.budget_exhausted
    coverage.forms_discovered = len(ctx.forms)
    coverage.modules_run = [m.name for m in modules if m.name not in coverage.modules_failed]

    ran = set(coverage.modules_run)
    injection_modules = sorted(ran & {"xss", "sqli", "redirect"})
    if coverage.parameters_discovered == 0 and injection_modules:
        coverage.warnings.append(
            "No URL parameters were discovered, so these modules had nothing to test: "
            + ", ".join(injection_modules)
            + ". This is NOT evidence that the application is free of those issues."
        )
    if coverage.pages_truncated:
        coverage.warnings.append(
            f"Crawl stopped at the --max-pages limit ({options.max_pages}); findings may be "
            "incomplete. Increase --max-pages or scan specific URLs."
        )
    if coverage.params_truncated:
        coverage.warnings.append(
            f"Parameter testing stopped at --max-params ({options.max_params}); increase it "
            "for deeper coverage."
        )
    if coverage.modules_failed:
        coverage.warnings.append(
            "These modules failed and did not complete: "
            + ", ".join(coverage.modules_failed)
            + "."
        )
    if "forms" in ran and coverage.forms_discovered == 0:
        coverage.warnings.append(
            "No HTML forms were discovered, so the CSRF heuristic had nothing to analyse."
        )
