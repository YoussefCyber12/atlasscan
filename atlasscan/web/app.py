from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from atlasscan import __version__
from atlasscan.core.context import ScanOptions
from atlasscan.core.report import SEVERITY_LABELS, TEMPLATES_DIR
from atlasscan.core.scanner import normalize_target, run_scan
from atlasscan.core.storage import Storage
from atlasscan.modules import ALL_MODULES

MAX_CONCURRENT_SCANS = 3


def create_app(data_dir: Path | str | None = None) -> FastAPI:
    storage = Storage(data_dir)
    jobs: dict[str, dict[str, Any]] = {}
    jobs_lock = threading.Lock()
    semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

    app = FastAPI(
        title="AtlasScan",
        version=__version__,
        description="Local dashboard for AtlasScan scan results.",
    )
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.globals["severity_labels"] = SEVERITY_LABELS

    def render(request: Request, name: str, **context: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, context)

    # ---------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, error: Optional[str] = None) -> HTMLResponse:
        return render(request, "index.html", scans=storage.list(), error=error)

    @app.post("/scan")
    def start_scan_form(
        request: Request,
        target: str = Form(...),
        authorized: Optional[str] = Form(None),
    ):
        if authorized not in ("on", "true", "1", "yes"):
            return render(
                request,
                "index.html",
                scans=storage.list(),
                error="You must confirm you are authorized to test this target.",
            )
        try:
            normalized = normalize_target(target)
        except ValueError as exc:
            return render(request, "index.html", scans=storage.list(), error=str(exc))

        job_id = _start_job(normalized, storage, jobs, jobs_lock, semaphore)
        return RedirectResponse(url=f"/job/{job_id}", status_code=303)

    @app.get("/job/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str) -> HTMLResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        return render(request, "job.html", job_id=job_id, target=job["target"])

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def scan_page(request: Request, scan_id: str) -> HTMLResponse:
        result = storage.load(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return render(
            request,
            "detail.html",
            result=result.to_dict(),
            counts=result.counts(),
            risk=result.risk_score(),
            risk_breakdown=result.risk_breakdown(),
            coverage=result.coverage.to_dict(),
            findings=[f.to_dict() for f in result.sorted_findings()],
        )

    # ------------------------------------------------------------------ api
    @app.get("/api/scans")
    def api_scans() -> JSONResponse:
        return JSONResponse(storage.list())

    @app.get("/api/scans/{scan_id}")
    def api_scan(scan_id: str) -> JSONResponse:
        result = storage.load(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return JSONResponse(result.to_dict())

    @app.delete("/api/scans/{scan_id}")
    def api_delete_scan(scan_id: str) -> JSONResponse:
        if not storage.delete(scan_id):
            raise HTTPException(status_code=404, detail="scan not found")
        return JSONResponse({"deleted": scan_id})

    @app.get("/api/modules")
    def api_modules() -> JSONResponse:
        return JSONResponse(
            [{"name": name, "description": cls.description} for name, cls in ALL_MODULES.items()]
        )

    @app.post("/api/scan")
    async def api_start_scan(request: Request) -> JSONResponse:
        payload = await request.json()
        target = payload.get("target", "")
        if not payload.get("authorized"):
            raise HTTPException(status_code=403, detail="authorization confirmation required")
        try:
            normalized = normalize_target(target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        modules = payload.get("modules")
        options = ScanOptions(
            crawl=bool(payload.get("crawl", True)),
            time_based=bool(payload.get("time_based", False)),
            max_pages=int(payload.get("max_pages", 25)),
            delay=float(payload.get("delay", 0.15)),
        )
        job_id = _start_job(normalized, storage, jobs, jobs_lock, semaphore, modules, options)
        return JSONResponse({"job_id": job_id, "status": "running"}, status_code=202)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: str) -> JSONResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        return JSONResponse(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "message": job["message"],
                "error": job["error"],
                "scan_id": job["scan_id"],
                "log": job["log"][-200:],
            }
        )

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    return app


def _start_job(
    target: str,
    storage: Storage,
    jobs: dict[str, dict[str, Any]],
    lock: threading.Lock,
    semaphore: threading.BoundedSemaphore,
    modules: Optional[list[str]] = None,
    options: Optional[ScanOptions] = None,
) -> str:
    job_id = uuid.uuid4().hex[:12]
    job: dict[str, Any] = {
        "target": target,
        "status": "running",
        "message": "queued",
        "error": None,
        "scan_id": None,
        "log": [],
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with lock:
        jobs[job_id] = job

    def worker() -> None:
        with semaphore:
            def progress(module: str, message: str) -> None:
                job["message"] = message
                job["log"].append(f"[{module}] {message}")
                if len(job["log"]) > 500:
                    del job["log"][:100]

            try:
                result = run_scan(target, options=options, module_names=modules, progress=progress)
                storage.save(result)
                job["scan_id"] = result.scan_id
                job["status"] = "done"
                job["message"] = f"finished with {len(result.findings)} finding(s)"
            except Exception as exc:  # surface scan errors in the UI
                job["status"] = "error"
                job["error"] = f"{exc.__class__.__name__}: {exc}"
                job["message"] = "scan failed"

    threading.Thread(target=worker, name=f"atlasscan-{job_id}", daemon=True).start()
    return job_id
