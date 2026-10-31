# dashboard/api.py
"""
Public, READ-ONLY dashboard API.

Serves the pages, dashboard_summary.json and queries against public_alerts.db (both written
by the engine, both already stripped of raw logs for internal sources, of the owner's own
activity, and masked). No write endpoints, no access to alerts.json. The pod also mounts
the volume read-only, so the rule is enforced twice.
"""
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse

from detection import public_alerts

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SUMMARY_PATH = os.environ.get("PURPLE_SUMMARY_PATH", str(ROOT / "reports" / "dashboard_summary.json"))
ATTACKERS_PATH = os.environ.get("PURPLE_ATTACKERS_PATH", str(ROOT / "reports" / "public_attackers.json"))
ALERTS_DB = os.environ.get("PURPLE_ALERTS_DB", str(ROOT / "reports" / "public_alerts.db"))
MAP_KEY = os.environ.get("PURPLE_MAP_KEY", "")           # CARTO tile key: public by design, kept out of git

_attackers_cache = {"mtime": None, "data": {}}

app = FastAPI(title="Purple Team Detection", docs_url=None, redoc_url=None, openapi_url=None)

CDN = "https://cdnjs.cloudflare.com"                       # Leaflet, pinned to 1.9.4 in the page
TILES = "https://basemaps.cartocdn.com https://*.basemaps.cartocdn.com"
CSP = (f"default-src 'none'; script-src 'self' 'unsafe-inline' {CDN}; style-src 'unsafe-inline' {CDN}; "
       f"img-src 'self' data: {TILES}; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _json(data):
    return Response(content=json.dumps(data), media_type="application/json", headers={"Cache-Control": "no-store"})


def _db(call, *args, **kwargs):
    try:
        return call(ALERTS_DB, *args, **kwargs)
    except Exception:                                      # missing/unreadable db: the page shows a message
        raise HTTPException(status_code=503, detail="alert database not ready")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(HERE / "index.html", media_type="text/html")


@app.get("/alerts", include_in_schema=False)
def alerts_page():
    return FileResponse(HERE / "alerts.html", media_type="text/html")


@app.get("/alerts.js", include_in_schema=False)
def alerts_script():
    return FileResponse(HERE / "alerts.js", media_type="application/javascript")


@app.get("/config")
def config():
    return _json({"map_key": MAP_KEY})


@app.get("/summary")
def summary():
    try:
        with open(SUMMARY_PATH) as f:
            return _json(json.load(f))
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="summary not generated yet")
    except ValueError:
        raise HTTPException(status_code=503, detail="summary unreadable")


@app.get("/api/days")
def days():
    return _json(_db(public_alerts.list_days))


@app.get("/api/rules")
def rules():
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    return _json(_db(public_alerts.rule_counts, since))


@app.get("/api/alerts")
def alerts(day: str | None = None, hours: int | None = Query(None, ge=1, le=720), sort: str = "priority",
           rule: str | None = Query(None, max_length=80), page: int = Query(1, ge=1, le=100000),
           per_page: int = Query(50, ge=1, le=public_alerts.MAX_PER_PAGE)):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat() if hours else None
    return _json(_db(public_alerts.query_alerts, day=day, since=since, sort=sort, rule=rule, page=page, per_page=per_page))


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str):
    found = _db(public_alerts.get_alert, alert_id)
    if not found:
        raise HTTPException(status_code=404, detail="no such alert")
    return _json(found)


@app.get("/api/attackers/{ip}")
def attacker(ip: str):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=404, detail="not an IP address")
    try:
        mtime = os.stat(ATTACKERS_PATH).st_mtime
        if _attackers_cache["mtime"] != mtime:                 # reload only when the engine wrote a new file
            with open(ATTACKERS_PATH) as f:
                _attackers_cache.update(mtime=mtime, data=json.load(f).get("attackers", {}))
    except (OSError, ValueError):
        raise HTTPException(status_code=503, detail="attacker details not ready")
    found = _attackers_cache["data"].get(ip)
    if not found:
        raise HTTPException(status_code=404, detail="no details for this IP (only the most active attackers are listed)")
    return _json(found)


@app.get("/health")
def health():
    return {"status": "ok"}
