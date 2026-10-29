# dashboard/api.py
"""
Public, READ-ONLY dashboard API.

It serves exactly two things: the page, and dashboard_summary.json (written by the engine,
already stripped of raw logs and of the owner's own activity). There are no write
endpoints, no /refresh and no access to alerts.json, so the full report never leaves the
cluster. The dashboard pod also mounts the volume read-only, which enforces the same
rule at the filesystem level (two independent layers).
"""
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SUMMARY_PATH = os.environ.get("PURPLE_SUMMARY_PATH", str(PROJECT_ROOT / "reports" / "dashboard_summary.json"))
INDEX_PATH = str(Path(__file__).resolve().parent / "index.html")

# No docs/openapi pages on a public service.
app = FastAPI(title="Purple Team Detection", docs_url=None, redoc_url=None, openapi_url=None)

# One page with inline script/style. The ONLY third-party hosts allowed: the Leaflet CDN and the map tiles.
CDN = "https://cdnjs.cloudflare.com"                      # Leaflet, pinned to 1.9.4 in the page
TILES = "https://*.basemaps.cartocdn.com"                  # dark map tiles
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


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(INDEX_PATH, media_type="text/html")


@app.get("/summary")
def summary():
    try:
        with open(SUMMARY_PATH) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="summary not generated yet")
    except ValueError:
        raise HTTPException(status_code=503, detail="summary unreadable")
    return Response(content=json.dumps(data), media_type="application/json",
                    headers={"Cache-Control": "no-store"})


@app.get("/health")
def health():
    return {"status": "ok"}
