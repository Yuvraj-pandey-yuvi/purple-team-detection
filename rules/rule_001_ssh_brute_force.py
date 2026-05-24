# rule_001_ssh_brute_force.py
# ATT&CK T1110.001 - Brute Force: Password Guessing
#
# Logic: If more than 5 failed SSH attempts from the
# same IP within 60 seconds - fire alert
#
# Log source: auth.log

import re
from collections import defaultdict
from datetime import datetime, timezone

def detect(auth_log_text):
    """
    Sliding window brute force detection.
    Returns list of alerts (one per offending IP)
    """
    alerts = []

    # Pattern matches timestamp and IP from lines like:
    # 2026-05-22T13:04:11... Invalid user root from 1.2.3.4
    pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*'
        r'(?:Failed password|Invalid user).*'
        r'from (\d+\.\d+\.\d+\.\d+)'
    )

    # Store per IP: list of (timestamp, raw_line) tuples
    attempts = defaultdict(list)

    for line in auth_log_text.split('\n'):
        match = pattern.search(line)
        if match:
            timestamp_str = match.group(1)
            ip            = match.group(2)
            attempts[ip].append((timestamp_str, line))

    THRESHOLD = 5

    for ip, entries in attempts.items():
        if len(entries) < THRESHOLD:
            continue

        # Extract all timestamps for this IP
        timestamps = [e[0] for e in entries]
        raw_lines  = [e[1] for e in entries]

        # Parse first and last timestamp
        try:
            fmt = '%Y-%m-%dT%H:%M:%S'
            first_dt = datetime.strptime(timestamps[0],  fmt)
            last_dt  = datetime.strptime(timestamps[-1], fmt)
            time_window_seconds = int(
                (last_dt - first_dt).total_seconds()
            )
            first_seen = timestamps[0]
            last_seen  = timestamps[-1]
        except Exception:
            time_window_seconds = -1
            first_seen = timestamps[0]  if timestamps else 'unknown'
            last_seen  = timestamps[-1] if timestamps else 'unknown'

        # Classify attack speed
        if time_window_seconds < 60:
            attack_speed = 'aggressive'
        elif time_window_seconds < 3600:
            attack_speed = 'moderate'
        else:
            attack_speed = 'slow_scan'

        alerts.append({
            'rule_id':              'RULE-001',
            'rule_name':            'SSH Brute Force Detected',
            'technique':            'T1110.001',
            'severity':             'HIGH',
            'source_ip':            ip,
            'attempts':             len(entries),
            'threshold':            THRESHOLD,
            'first_seen':           first_seen,
            'last_seen':            last_seen,
            'time_window_seconds':  time_window_seconds,
            'attack_speed':         attack_speed,
            'log_source':           'auth.log',
            'reason': (
                f"IP {ip} made {len(entries)} failed SSH attempts "
                f"over {time_window_seconds}s ({attack_speed})"
            ),
            # First 3 raw log lines for context
            'sample_logs': raw_lines[:3]
        })

    return alerts