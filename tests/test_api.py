from __future__ import annotations

from fastapi.testclient import TestClient

from atlasscan.core.models import Finding, ScanResult
from atlasscan.core.storage import Storage
from atlasscan.web.app import create_app


def test_dashboard_pages(tmp_path):
    storage = Storage(tmp_path)
    result = ScanResult(target="https://example.test/", started_at="2026-01-01T00:00:00+00:00")
    result.add(Finding("X", "high", "https://example.test/", "headers", "desc"))
    storage.save(result)

    app = create_app(tmp_path)
    client = TestClient(app)

    index = client.get("/")
    assert index.status_code == 200
    assert "example.test" in index.text

    detail = client.get(f"/scan/{result.scan_id}")
    assert detail.status_code == 200
    assert "X" in detail.text

    api = client.get("/api/scans").json()
    assert api[0]["scan_id"] == result.scan_id

    modules = client.get("/api/modules").json()
    assert any(m["name"] == "jwt" for m in modules)


def test_api_requires_authorization(tmp_path):
    client = TestClient(create_app(tmp_path))
    response = client.post("/api/scan", json={"target": "https://example.test/"})
    assert response.status_code == 403


def test_unknown_scan_returns_404(tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.get("/scan/nope").status_code == 404
    assert client.get("/api/scans/nope").status_code == 404


def test_api_rejects_invalid_cookie_string(tmp_path):
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/api/scan",
        json={"target": "https://example.test/", "authorized": True, "cookies": "broken"},
    )
    assert response.status_code == 400
    assert "cookie" in response.json()["detail"].lower()


def test_api_rejects_body_template_without_marker(tmp_path):
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/api/scan",
        json={"target": "https://example.test/", "authorized": True, "data": '{"q":"x"}'},
    )
    assert response.status_code == 400
    assert "FUZZ" in response.json()["detail"]
