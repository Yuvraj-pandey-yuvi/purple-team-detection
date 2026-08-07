# reports/report_generator.py
# Generates a structured JSON report from the detection engine's REAL
# current output (AlertReport + CoverageSummary), for the dashboard API.

import json
import os
from datetime import datetime, timezone
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detection.engine import run_engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _alert_to_dict(alert) -> dict:
    return alert.model_dump(mode="json")


def generate_report():
    print("Running detection engine...")
    report_obj = run_engine()
    alerts = [_alert_to_dict(a) for a in report_obj.alerts]

    total    = report_obj.coverage.total_techniques
    detected = report_obj.coverage.detected_count
    missed   = total - detected
    coverage = report_obj.coverage.coverage_pct

    # ── TECHNIQUE BREAKDOWN (restored — the dashboard's ATT&CK matrix
    # and "Alerts by Technique" chart both read report.techniques,
    # keyed by technique id, shaped {name, detected, status, alert_count}) ──
    techniques = {}
    for t in report_obj.coverage.techniques:
        tid = t.technique.value if hasattr(t.technique, "value") else str(t.technique)
        techniques[tid] = {
            "name":        t.name,
            "detected":    t.detected,
            "status":      "detected" if t.detected else "missed",
            "alert_count": t.alert_count,
        }

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for alert in alerts:
        sev = alert.get("severity", "UNKNOWN")
        if sev in severity_counts:
            severity_counts[sev] += 1

    source_counts = {}
    for alert in alerts:
        source = alert.get("log_source", "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1

    ssh_attackers = {}
    attacker_ips = []
    for alert in alerts:
        if alert.get("technique") == "T1110.001" and alert.get("source_ip"):
            ip = alert["source_ip"]
            extra = alert.get("extra", {})
            entry = {
                "attempts":     extra.get("attempt_count"),  # matches frontend's `data.attempts`
                "attack_speed": extra.get("attack_speed"),
                "first_seen":   alert.get("first_seen"),
                "last_seen":    alert.get("last_seen"),
                "geo": None,
            }
            ssh_attackers[ip] = entry
            attacker_ips.append({"ip": ip, **entry})

    auid_alert_counts = {}
    user_technique_map = {}
    privilege_escalations = []

    for alert in alerts:
        extra = alert.get("extra", {})
        auid = extra.get("auid")
        technique = alert.get("technique", "unknown")

        if auid is not None:
            key = str(auid)
            auid_alert_counts[key] = auid_alert_counts.get(key, 0) + 1
            user_technique_map.setdefault(key, [])
            if technique not in user_technique_map[key]:
                user_technique_map[key].append(technique)

        if technique == "T1548" and auid is not None:
            privilege_escalations.append({
                "auid_human": str(auid),   # frontend expects `auid_human`
                "auid":       auid,
                "euid":       extra.get("euid"),
                "technique":  technique,
                "comm":       extra.get("comm"),
                "timestamp":  alert.get("timestamp"),
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_techniques": total,
            "detected":         detected,
            "missed":           missed,
            "coverage_percent": coverage,
            "total_alerts":     len(alerts),
            "severity_counts":  severity_counts,
            "source_counts":    source_counts,
        },
        "techniques":   techniques,
        "attacker_ips": attacker_ips,
        "alerts":       alerts,
        "user_activity": {
            "auid_alert_counts":     auid_alert_counts,
            "privilege_escalations": privilege_escalations,
            "user_technique_map":    user_technique_map,
            "ssh_attackers":         ssh_attackers,
        },
    }

    output_dir = PROJECT_ROOT / "reports"
    output_path = output_dir / "latest_report.json"
    output_dir.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nReport saved to {output_path}")
    print(f"\n{'='*45}")
    print(f"  REPORT SUMMARY")
    print(f"{'='*45}")
    print(f"  Generated  : {report['generated_at']}")
    print(f"  Coverage   : {coverage}% ({detected}/{total} techniques)")
    print(f"  Alerts     : {len(alerts)} total")
    print(f"  Critical   : {severity_counts['CRITICAL']}")
    print(f"  High       : {severity_counts['HIGH']}")
    print(f"  Log sources: {source_counts}")
    print(f"{'='*45}\n")

    return report


if __name__ == "__main__":
    generate_report()
