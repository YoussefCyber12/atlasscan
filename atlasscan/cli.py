from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from atlasscan import __version__
from atlasscan.config import SEVERITY_COLOR
from atlasscan.core.baseline import BaselineError, apply_baseline, load_baseline
from atlasscan.core.context import ScanOptions
from atlasscan.core.models import ScanResult
from atlasscan.core.report import SEVERITY_LABELS, render_html, write_report
from atlasscan.core.scanner import normalize_target, run_scan
from atlasscan.core.storage import Storage
from atlasscan.modules import ALL_MODULES, DEFAULT_MODULES
from atlasscan.web import serve

console = Console()

RISK_ORDER = ["none", "info", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atlasscan",
        description="Lightweight web vulnerability scanner (CLI + dashboard).",
        epilog="Only scan systems you own or have written permission to test.",
    )
    parser.add_argument("--version", action="version", version=f"atlasscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a target URL")
    scan.add_argument("target", help="URL or host to scan (https:// is assumed)")
    scan.add_argument("-y", "--authorized", action="store_true", help="confirm you are authorized to test the target")
    scan.add_argument("-m", "--modules", help=f"comma separated modules (default: {','.join(DEFAULT_MODULES)})")
    scan.add_argument("--no-crawl", action="store_true", help="only test the given URL")
    scan.add_argument("--max-pages", type=int, default=25, help="maximum pages to crawl (default: 25)")
    scan.add_argument("--max-depth", type=int, default=2, help="maximum crawl depth (default: 2)")
    scan.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default: 10)")
    scan.add_argument("--delay", type=float, default=0.15, help="delay between requests in seconds (default: 0.15)")
    scan.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    scan.add_argument("--time-based", action="store_true", help="enable slow time-based SQL injection checks")
    scan.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    scan.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE", help="extra request header")
    scan.add_argument("-o", "--output", help="write the report to this path (.html, .json or .sarif)")
    scan.add_argument("--json", action="store_true", help="print the raw JSON result to stdout")
    scan.add_argument(
        "--baseline",
        metavar="PATH|SCAN_ID",
        help="only report findings that are new since this JSON report or saved scan id",
    )
    scan.add_argument("--fail-on", choices=RISK_ORDER, default="none", help="exit 1 when a finding at/above this severity exists")
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    scan.add_argument("-v", "--verbose", action="store_true", help="print description, evidence and remediation for every finding")
    scan.add_argument("--data-dir", help="where to store scan results (default: ~/.atlasscan)")

    dash = sub.add_parser("dashboard", help="start the local web dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    dash.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    dash.add_argument("--data-dir", help="where scan results are stored")

    lst = sub.add_parser("list", help="list saved scans")
    lst.add_argument("--data-dir", help="where scan results are stored")
    lst.add_argument("--limit", type=int, default=20)

    show = sub.add_parser("show", help="print a saved scan as JSON")
    show.add_argument("scan_id")
    show.add_argument("--data-dir")

    mods = sub.add_parser("modules", help="list available modules")
    mods.add_argument("--json", action="store_true")

    return parser


def parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        if ":" not in raw:
            raise SystemExit(f"invalid header (expected 'Name: value'): {raw}")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def confirm_authorization(assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        console.print("[red]Refusing to scan without --authorized.[/red]")
        raise SystemExit(2)
    console.print(
        Panel(
            "Only scan systems you own or have [bold]written permission[/bold] to test.\n"
            "Unauthorized scanning may be illegal.",
            title="Authorization",
            border_style="yellow",
        )
    )
    answer = console.input("Do you have permission to test this target? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit(2)


def print_findings(result: ScanResult, verbose: bool) -> None:
    if not result.findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Module", style="dim", no_wrap=True)
    table.add_column("Finding", overflow="fold")
    table.add_column("URL", style="dim", overflow="fold")

    for finding in result.sorted_findings():
        color = SEVERITY_COLOR[finding.severity]
        table.add_row(
            Text(finding.severity.upper(), style=f"bold {color}"),
            finding.module,
            finding.name,
            finding.url,
        )

    console.print(table)

    if verbose:
        for finding in result.sorted_findings():
            body = Text()
            body.append(f"{finding.name}\n", style=f"bold {SEVERITY_COLOR[finding.severity]}")
            body.append(f"{finding.description}\n\n", style="")
            if finding.evidence:
                body.append(f"{finding.evidence}\n\n", style="dim")
            if finding.remediation:
                body.append(f"Fix: {finding.remediation}\n", style="cyan")
            console.print(Panel(body, border_style="dim"))


def print_summary(result: ScanResult, report_path: Optional[Path], verbose: bool = False) -> None:
    counts = result.counts()
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev]:
            parts.append(f"[{SEVERITY_COLOR[sev]}]{counts[sev]} {SEVERITY_LABELS[sev].lower()}[/]")
    summary = " · ".join(parts) if parts else "no findings"

    risk = result.risk_score()
    risk_color = "green" if risk < 25 else ("yellow" if risk < 60 else "red")
    coverage = result.coverage

    lines = [
        f"[bold]{result.target}[/bold]",
        f"Risk score: [{risk_color}]{risk}/100[/{risk_color}]   Findings: {len(result.findings)}",
        summary,
        f"Requests: {result.stats.requests}   Pages: {coverage.pages_crawled}"
        f"/{coverage.pages_limit}   Duration: {result.stats.duration}s",
        f"Coverage: {coverage.parameters_discovered} parameter(s) found, "
        f"{coverage.parameters_tested} tested · {coverage.forms_discovered} form(s)",
    ]
    if report_path:
        lines.append(f"Report: {report_path}")
    if result.baseline_scan_id:
        lines.append(
            f"Baseline: {result.baseline_scan_id}   "
            f"Suppressed: {result.suppressed} known finding(s)"
        )
    console.print(Panel("\n".join(lines), title="AtlasScan", border_style=risk_color))

    if verbose:
        table = Table(title="Risk score breakdown", header_style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        table.add_column("Weight", justify="right")
        table.add_column("Points", justify="right")
        table.add_column("Share", justify="right")
        breakdown = result.risk_breakdown()
        for row in breakdown["contributions"]:
            if not row["count"]:
                continue
            table.add_row(
                Text(SEVERITY_LABELS[row["severity"]], style=SEVERITY_COLOR[row["severity"]]),
                str(row["count"]),
                str(row["weight"]),
                str(row["points"]),
                f"{row['share']}%",
            )
        table.add_row("Total", str(len(result.findings)), "", str(breakdown["total_weight"]),
                      f"{breakdown['score']}/100")
        console.print(table)
        console.print(f"[dim]{breakdown['formula']}[/dim]")

    for warning in coverage.warnings:
        console.print(f"[yellow]! Coverage warning:[/yellow] {warning}")


def cmd_scan(args: argparse.Namespace) -> int:
    confirm_authorization(args.authorized)

    modules = [m.strip() for m in args.modules.split(",")] if args.modules else None
    if modules:
        unknown = [m for m in modules if m not in ALL_MODULES]
        if unknown:
            console.print(f"[red]Unknown module(s): {', '.join(unknown)}[/red]")
            return 2

    headers = parse_headers(args.header)

    options = ScanOptions(
        crawl=not args.no_crawl,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        timeout=args.timeout,
        delay=args.delay,
        verify=not args.insecure,
        time_based=args.time_based,
        proxy=args.proxy,
        headers=headers,
    )

    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        console.print(f"[red]Invalid target: {exc}[/red]")
        return 2

    if not args.quiet:
        console.print(f"[dim]Scanning[/dim] [bold]{target}[/bold]")

    progress = None
    spinner = None
    if not args.quiet:
        spinner = console.status("[cyan]starting…[/cyan]", spinner="dots")
        spinner.start()

        def progress(module: str, message: str) -> None:
            spinner.update(f"[cyan]{message}[/cyan]")

    # Proxy is injected at the client level from the scan options.

    try:
        result = run_scan(args.target, options=options, module_names=modules, progress=progress)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    finally:
        if spinner:
            spinner.stop()

    storage = Storage(args.data_dir)

    if args.baseline:
        try:
            baseline = load_baseline(args.baseline, storage)
        except BaselineError as exc:
            console.print(f"[red]{exc}[/red]")
            return 2
        suppressed = apply_baseline(result, baseline)
        if suppressed and not args.quiet:
            console.print(
                f"[dim]Baseline {baseline.scan_id}: suppressed {suppressed} known finding(s)[/dim]"
            )

    stored = storage.save(result)

    report_path: Optional[Path] = None
    if args.output:
        report_path = write_report(result, args.output)
    elif not args.quiet and not args.json:
        report_path = stored.with_suffix(".html")
        report_path.write_text(render_html(result), encoding="utf-8")

    if args.json:
        print(result.to_json())
    else:
        print_findings(result, verbose=args.verbose)
        print_summary(result, report_path, verbose=args.verbose)
        console.print(f"[dim]JSON result: {stored}[/dim]")

    return exit_code_for(result, args.fail_on)


def exit_code_for(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = RISK_ORDER.index(fail_on)
    for finding in result.findings:
        if RISK_ORDER.index(finding.severity) >= threshold:
            return 1
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[yellow]Warning:[/yellow] the dashboard has no authentication. "
            "Binding to a non-loopback address exposes it to the network."
        )
    console.print(f"[green]Dashboard:[/green] http://{args.host}:{args.port}")
    serve(host=args.host, port=args.port, data_dir=args.data_dir)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    scans = Storage(args.data_dir).list(limit=args.limit)
    if not scans:
        console.print("[dim]No scans yet.[/dim]")
        return 0
    table = Table(header_style="bold")
    table.add_column("Scan ID", style="cyan", no_wrap=True)
    table.add_column("Target", overflow="fold")
    table.add_column("Started")
    table.add_column("Risk", justify="right")
    table.add_column("Findings", justify="right")
    for scan in scans:
        table.add_row(
            scan["scan_id"],
            scan["target"],
            scan["started_at"],
            str(scan["risk_score"]),
            str(scan["findings"]),
        )
    console.print(table)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    result = Storage(args.data_dir).load(args.scan_id)
    if result is None:
        console.print(f"[red]Scan not found: {args.scan_id}[/red]")
        return 1
    print(result.to_json())
    return 0


def cmd_modules(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps([{"name": n, "description": c.description} for n, c in ALL_MODULES.items()]))
        return 0
    table = Table(header_style="bold")
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Default", justify="center")
    table.add_column("Description")
    for name, cls in ALL_MODULES.items():
        table.add_row(name, "yes" if name in DEFAULT_MODULES else "-", cls.description)
    console.print(table)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "dashboard": cmd_dashboard,
        "list": cmd_list,
        "show": cmd_show,
        "modules": cmd_modules,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
