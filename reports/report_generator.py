# report_generator.py
# Generates a structured JSON report from detection engine output
# This feeds the dashboard in Phase 6

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.expanduser('~/project'))

from detection.engine import run_engine, TECHNIQUES


def generate_report():
    """
    Runs the detection engine and saves results as JSON.
    Returns the report dict.
    """

    print("Running detection engine...")
    alerts, detected_techniques = run_engine()

    # ── SUMMARY ─────────────────────────────────────────
    total      = len(TECHNIQUES)
    detected   = len(detected_techniques)
    missed     = total - detected
    coverage   = round(detected / total * 100, 1) if total > 0 else 0

    # ── TECHNIQUE BREAKDOWN ─────────────────────────────
    techniques = {}
    for tid, tname in TECHNIQUES.items():
        is_detected = tid in detected_techniques

        # Find alerts for this technique
        technique_alerts = [
            a for a in alerts
            if a.get('technique', '').startswith(tid)
        ]

        techniques[tid] = {
            'name':         tname,
            'detected':     is_detected,
            'status':       'detected' if is_detected else 'missed',
            'alert_count':  len(technique_alerts),
        }

    # ── ATTACKER IP SUMMARY (for map) ───────────────────
    attacker_ips = []
    for alert in alerts:
        if alert.get('rule_id') == 'RULE-001':
            attacker_ips.append({
                'ip':           alert.get('source_ip'),
                'attempts':     alert.get('attempts'),
                'attack_speed': alert.get('attack_speed'),
                'first_seen':   alert.get('first_seen'),
                'last_seen':    alert.get('last_seen'),
                'time_window':  alert.get('time_window_seconds'),
            })

    # ── ALERTS BY SEVERITY ───────────────────────────────
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
    for alert in alerts:
        sev = alert.get('severity', 'UNKNOWN')
        if sev in severity_counts:
            severity_counts[sev] += 1

    # ── ALERTS BY LOG SOURCE ────────────────────────────
    source_counts = {}
    for alert in alerts:
        source = alert.get('log_source', 'unknown')
        source_counts[source] = source_counts.get(source, 0) + 1


    # ── USER ACTIVITY SUMMARY (for bar charts) ──────────

    # Which auid generated the most alerts
    auid_alert_counts = {}
    for alert in alerts:
        auid_human = alert.get('auid_human')
        if auid_human and auid_human != 'unknown':
            auid_alert_counts[auid_human] = (
                auid_alert_counts.get(auid_human, 0) + 1
            )

    # Which user created accounts
    account_creators = {}
    for alert in alerts:
        if alert.get('rule_id') == 'RULE-003':
            creator  = alert.get('created_by', 'unknown')
            new_user = alert.get('new_username', 'unknown')
            account_creators[creator] = (
                account_creators.get(creator, [])
            )
            account_creators[creator].append(new_user)

    # Which user triggered privilege escalation
    privilege_escalations = []
    for alert in alerts:
        if alert.get('privilege_escalated'):
            privilege_escalations.append({
                'auid_human': alert.get('auid_human', 'unknown'),
                'auid':       alert.get('auid', 'unknown'),
                'euid':       alert.get('euid', 'unknown'),
                'technique':  alert.get('technique'),
                'comm':       alert.get('comm', 'unknown'),
                'timestamp':  alert.get('timestamp', 'unknown'),
            })

    # Which techniques each user triggered
    user_technique_map = {}
    for alert in alerts:
        auid_human = alert.get('auid_human', 'unknown')
        technique  = alert.get('technique', 'unknown')
        if auid_human == 'unknown':
            continue
        if auid_human not in user_technique_map:
            user_technique_map[auid_human] = []
        if technique not in user_technique_map[auid_human]:
            user_technique_map[auid_human].append(technique)

    # SSH login attempts by source IP with geolocation placeholder
    ssh_attackers = {}
    for alert in alerts:
        if alert.get('rule_id') == 'RULE-001':
            ip = alert.get('source_ip', 'unknown')
            ssh_attackers[ip] = {
                'attempts':     alert.get('attempts', 0),
                'attack_speed': alert.get('attack_speed', 'unknown'),
                'first_seen':   alert.get('first_seen', 'unknown'),
                'last_seen':    alert.get('last_seen', 'unknown'),
                'time_window':  alert.get('time_window_seconds', 0),
                # Geolocation filled by dashboard via ip-api.com
                'geo': None,
            }


    
    # ── FULL REPORT ─────────────────────────────────────
    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_techniques': total,
            'detected':         detected,
            'missed':           missed,
            'coverage_percent': coverage,
            'total_alerts':     len(alerts),
            'severity_counts':  severity_counts,
            'source_counts':    source_counts,
        },
        'techniques':   techniques,
        'attacker_ips': attacker_ips,
        'alerts':       alerts,

        # New user activity sections
        'user_activity': {
            'auid_alert_counts':      auid_alert_counts,
            'account_creators':       account_creators,
            'privilege_escalations':  privilege_escalations,
            'user_technique_map':     user_technique_map,
            'ssh_attackers':          ssh_attackers,
        },
    }
    # ── SAVE REPORT ─────────────────────────────────────
    output_dir  = os.path.expanduser('~/project/reports')
    output_path = os.path.join(output_dir, 'latest_report.json')

    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nReport saved to {output_path}")

    # ── PRINT SUMMARY ───────────────────────────────────
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