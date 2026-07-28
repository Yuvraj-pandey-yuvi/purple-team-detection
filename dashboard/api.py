# api.py
# FastAPI backend serving detection report to dashboard

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI(title="Purple Team Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = str(PROJECT_ROOT / "reports" / "latest_report.json")
DASHBOARD_PATH = str(PROJECT_ROOT / "dashboard")


def load_report():
    if not os.path.exists(REPORT_PATH):
        raise HTTPException(
            status_code=404,
            detail="No report found. Run report_generator.py first."
        )
    with open(REPORT_PATH) as f:
        return json.load(f)


def _to_frontend_alert(a: dict) -> dict:
    """The dashboard's index.html JS was built against an older,
    flatter alert shape (rule_name, reason, comm, attempts,
    auid_human, etc.) that doesn't match the current Alert schema
    (rule_id, description, extra={...}). Rather than rewrite the
    frontend JS, this maps each real alert onto the field names it
    expects, without changing any HTML/JS.
    """
    extra = a.get("extra", {}) or {}
    auid = extra.get("auid")

    out = {
        **a,  # keep everything real (rule_id, technique, severity, etc.)
        **extra,  # flatten extra fields (comm, exe, auid, attempt_count, etc.) to top level
        "rule_name": a.get("rule_id"),
        "reason":    a.get("description"),
        "auid_human": str(auid) if auid is not None else None,
        "attempts":   extra.get("attempt_count"),
        "cron_file":  extra.get("file"),
        "created_by": extra.get("auid_human"),
        "privilege_escalated": a.get("technique") == "T1548",
        "name_suspicious": extra.get("signal") == "name_mismatch",
    }
    return out


@app.get("/")
def serve_dashboard():
    index_path = os.path.join(DASHBOARD_PATH, 'index.html')
    return FileResponse(index_path)


@app.get("/report")
def get_report():
    return load_report()


@app.get("/summary")
def get_summary():
    report = load_report()
    return {
        'generated_at': report.get('generated_at'),
        'summary':      report.get('summary'),
    }


@app.get("/techniques")
def get_techniques():
    report = load_report()
    return report.get('techniques', {})


@app.get("/alerts")
def get_alerts():
    report   = load_report()
    alerts   = report.get('alerts', [])
    order    = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    sorted_alerts = sorted(
        alerts,
        key=lambda x: order.get(x.get('severity', 'MEDIUM'), 9)
    )
    return [_to_frontend_alert(a) for a in sorted_alerts]


@app.get("/user-activity")
def get_user_activity():
    report = load_report()
    return report.get('user_activity', {})


@app.get("/attackers")
def get_attackers():
    report = load_report()
    return report.get('user_activity', {}).get('ssh_attackers', {})


@app.post("/refresh")
def refresh_report():
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'reports.report_generator'],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Report generation failed: {result.stderr}"
            )
        return {
            'status':    'success',
            'message':   'Report refreshed successfully',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Report generation timed out"
        )


@app.get("/health")
def health():
    report_exists = os.path.exists(REPORT_PATH)
    return {
        'status':        'running',
        'report_exists': report_exists,
        'timestamp':     datetime.now(timezone.utc).isoformat()
    }