"""The public dashboard API must stay read-only and expose only the summary."""
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    summary = tmp_path / "dashboard_summary.json"
    summary.write_text(json.dumps({"generated_at": "2026-10-29T12:00:00+00:00", "totals": {}}))
    import dashboard.api as api
    monkeypatch.setattr(api, "SUMMARY_PATH", str(summary))
    return TestClient(api.app), summary


def test_summary_and_page_are_served_with_security_headers(client):
    c, _ = client
    r = c.get("/summary")
    assert r.status_code == 200 and r.json()["generated_at"].startswith("2026-10-29")
    page = c.get("/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    csp = page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp
    assert "cdnjs.cloudflare.com" in csp and "basemaps.cartocdn.com" in csp
    assert page.headers["x-content-type-options"] == "nosniff"


def test_missing_or_corrupt_summary_is_a_503_not_a_crash(client):
    c, summary = client
    summary.write_text("{ broken")
    assert c.get("/summary").status_code == 503
    summary.unlink()
    assert c.get("/summary").status_code == 503


@pytest.mark.parametrize("method,path", [
    ("post", "/attackers/block"), ("post", "/attackers/unblock"), ("get", "/refresh"), ("post", "/refresh"),
    ("get", "/report"), ("get", "/alerts"), ("get", "/attackers"), ("get", "/docs"), ("get", "/openapi.json"),
])
def test_old_endpoints_and_docs_are_gone(client, method, path):
    c, _ = client
    assert getattr(c, method)(path).status_code in (404, 405)
