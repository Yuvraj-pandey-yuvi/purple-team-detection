"""The public dashboard API: read-only, only the summary and public alerts, masked and bounded."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from schemas import Alert
from detection import public_alerts as pa

NOW = datetime.now(timezone.utc)


def make(rule="rule_001_ssh_brute_force", sev="HIGH", src="auth_log", mins=10, desc="5 failed SSH attempts", raw="", extra=None, auid=None):
    when = NOW - timedelta(minutes=mins)
    return Alert(rule_id=rule, technique="T1110.001", severity=sev, timestamp=when, first_seen=when, log_source=src,
                 dedup_key=f"{rule}|{mins}", description=desc, source_ip="9.9.9.9", auid=auid, raw_log=raw, extra=extra or {})


@pytest.fixture
def client(tmp_path, monkeypatch):
    summary = tmp_path / "dashboard_summary.json"
    summary.write_text(json.dumps({"generated_at": "2026-10-29T12:00:00+00:00", "totals": {}}))
    db = tmp_path / "public_alerts.db"
    alerts = [make(sev="MEDIUM", mins=5), make(sev="CRITICAL", mins=50, rule="rule_004_shadow_access", src="auditd",
                                               raw="arn:aws:iam::349491201539:user/x", extra={"acct": "349491201539"}),
              make(mins=60 * 24 * 3, desc="<img src=x onerror=alert(1)>"), make(auid=1000, mins=2)]
    pa.rebuild(alerts, str(db), hidden_ips=set())
    import dashboard.api as api
    monkeypatch.setattr(api, "SUMMARY_PATH", str(summary))
    monkeypatch.setattr(api, "ALERTS_DB", str(db))
    monkeypatch.setattr(api, "MAP_KEY", "test-key")
    return TestClient(api.app), summary, db


def test_pages_summary_and_headers(client):
    c, _, _ = client
    assert c.get("/summary").json()["generated_at"].startswith("2026-10-29")
    for path in ("/", "/alerts"):
        r = c.get(path)
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert c.get("/alerts.js").status_code == 200
    csp = c.get("/").headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp
    assert "https://basemaps.cartocdn.com" in csp and "cdnjs.cloudflare.com" in csp
    assert c.get("/").headers["x-content-type-options"] == "nosniff"
    assert c.get("/config").json() == {"map_key": "test-key"}


def test_alert_list_is_public_only_sorted_and_paged(client):
    c, _, _ = client
    r = c.get("/api/alerts?hours=24&sort=priority&per_page=15").json()
    assert r["total"] == 2 and r["items"][0]["severity"] == "CRITICAL"       # owner alert (auid 1000) is absent
    assert c.get("/api/alerts?sort=time").json()["total"] == 3
    assert c.get("/api/alerts?per_page=5000").status_code == 422             # bounded
    assert c.get("/api/alerts?hours=99999").status_code == 422


def test_detail_is_complete_and_masked(client):
    c, _, _ = client
    item = c.get("/api/alerts?rule=rule_004_shadow_access").json()["items"][0]
    d = c.get(f"/api/alerts/{item['id']}").json()
    assert d["rule_id"] == "rule_004_shadow_access" and d["technique"] and d["extra"]
    assert "349491201539" not in json.dumps(d) and d["raw_log"] is None and "withheld" in d["raw_log_note"]
    assert c.get("/api/alerts/doesnotexist").status_code == 404


def test_hostile_description_is_returned_as_data_and_sql_in_params_is_inert(client):
    c, _, _ = client
    r = c.get("/api/alerts", params={"day": "2026-10-30' OR '1'='1", "sort": "x; DROP TABLE alerts", "rule": "x' OR 1=1 --"})
    assert r.status_code == 200 and r.json()["total"] == 0
    assert c.get("/api/alerts").json()["total"] == 3
    assert any("<img" in i["description"] for i in c.get("/api/alerts?sort=time").json()["items"])


def test_days_and_rule_counts(client):
    c, _, _ = client
    assert sum(d["count"] for d in c.get("/api/days").json()) == 3
    assert c.get("/api/rules").json()["rule_001_ssh_brute_force"]["total"] == 2


def test_missing_data_is_a_503_not_a_crash(client):
    c, summary, db = client
    summary.write_text("{ broken"); db.unlink()
    assert c.get("/summary").status_code == 503
    for path in ("/api/alerts", "/api/days", "/api/rules", "/api/alerts/abc"):
        assert c.get(path).status_code == 503


@pytest.mark.parametrize("method,path", [
    ("post", "/attackers/block"), ("post", "/attackers/unblock"), ("get", "/refresh"), ("post", "/refresh"),
    ("get", "/report"), ("get", "/attackers"), ("get", "/docs"), ("get", "/openapi.json"),
    ("post", "/api/alerts"), ("delete", "/api/alerts/abc"), ("put", "/api/alerts/abc"),
])
def test_old_endpoints_docs_and_writes_are_gone(client, method, path):
    c, _, _ = client
    assert getattr(c, method)(path).status_code in (404, 405)


def test_attacker_detail_endpoint(client, tmp_path, monkeypatch):
    import dashboard.api as api
    path = tmp_path / "public_attackers.json"
    path.write_text(json.dumps({"attackers": {"9.9.9.9": {"ip": "9.9.9.9", "sessions": 3}}}))
    monkeypatch.setattr(api, "ATTACKERS_PATH", str(path))
    api._attackers_cache.update(mtime=None, data={})
    c, _, _ = client
    assert c.get("/api/attackers/9.9.9.9").json()["sessions"] == 3
    assert c.get("/api/attackers/8.8.8.8").status_code == 404                  # not among the listed attackers
    assert c.get("/api/attackers/not-an-ip").status_code == 404
    assert c.get("/api/attackers/9.9.9.9' OR 1=1").status_code == 404
    path.unlink()
    api._attackers_cache.update(mtime=None, data={})
    assert c.get("/api/attackers/9.9.9.9").status_code == 503
