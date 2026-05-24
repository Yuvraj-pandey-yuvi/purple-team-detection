# api.py
# FastAPI backend serving detection report to dashboard

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

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

REPORT_PATH = os.path.expanduser(
    '~/project/reports/latest_report.json'
)
DASHBOARD_PATH = os.path.expanduser(
    '~/project/dashboard'
)


def load_report():
    """Load and return the latest report"""
    if not os.path.exists(REPORT_PATH):
        raise HTTPException(
            status_code=404,
            detail="No report found. Run report_generator.py first."
        )
    with open(REPORT_PATH) as f:
        return json.load(f)


# ── ROUTES ───────────────────────────────────────────────

@app.get("/")
def serve_dashboard():
    """Serve the HTML dashboard"""
    index_path = os.path.join(DASHBOARD_PATH, 'index.html')
    return FileResponse(index_path)


@app.get("/report")
def get_report():
    """Full detection report"""
    return load_report()


@app.get("/summary")
def get_summary():
    """Coverage summary only"""
    report = load_report()
    return {
        'generated_at': report.get('generated_at'),
        'summary':      report.get('summary'),
    }


@app.get("/techniques")
def get_techniques():
    """ATT&CK technique coverage"""
    report = load_report()
    return report.get('techniques', {})


@app.get("/alerts")
def get_alerts():
    """All alerts sorted by severity"""
    report   = load_report()
    alerts   = report.get('alerts', [])
    order    = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    sorted_alerts = sorted(
        alerts,
        key=lambda x: order.get(x.get('severity', 'MEDIUM'), 9)
    )
    return sorted_alerts


@app.get("/user-activity")
def get_user_activity():
    """User account activity summary"""
    report = load_report()
    return report.get('user_activity', {})


@app.get("/attackers")
def get_attackers():
    """SSH attacker IPs with metadata"""
    report = load_report()
    return report.get('user_activity', {}).get('ssh_attackers', {})


@app.post("/refresh")
def refresh_report():
    """
    Trigger a fresh detection run and update the report.
    Runs report_generator.py as a subprocess.
    """
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'reports.report_generator'],
            cwd=os.path.expanduser('~/project'),
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
    """Health check"""
    report_exists = os.path.exists(REPORT_PATH)
    return {
        'status':        'running',
        'report_exists': report_exists,
        'timestamp':     datetime.now(timezone.utc).isoformat()
    }