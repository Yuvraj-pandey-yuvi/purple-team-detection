# rules/rule_001_ssh_brute_force.py
# ATT&CK T1110.001 - Brute Force: Password Guessing

from collections import defaultdict
from datetime import datetime, timezone
from schemas import (
    AuthLogEvent, Alert, ATTCKTechnique,
    Severity, AttackSpeed, LogSource
)

THRESHOLD       = 5
WINDOW_SECONDS  = 60


def detect(events: list[AuthLogEvent]) -> list[Alert]:
    """
    Sliding window SSH brute force detection.

    Groups failed auth events by source IP.
    For each IP, slides a 60-second window across attempts.
    If >= 5 attempts fall within any 60-second window, fires alert.

    INPUT:  list[AuthLogEvent] — pre-parsed, typed, validated
    OUTPUT: list[Alert]        — typed, ready for API
    """
    alerts = []

    # Step 1: group failed attempts by IP
    by_ip: dict[str, list[AuthLogEvent]] = defaultdict(list)
    for event in events:
        if event.auth_result == "failed" and event.source_ip:
            by_ip[event.source_ip].append(event)

    # Step 2: sliding window per IP
    for ip, attempts in by_ip.items():

        # Sort by time so window math works
        attempts.sort(key=lambda e: e.epoch)

        window = []   # attempts within current 60-second window

        for attempt in attempts:
            # Drop attempts outside the 60-second window
            window = [a for a in window
                      if attempt.epoch - a.epoch <= WINDOW_SECONDS]
            window.append(attempt)

            # Threshold crossed — fire alert
            if len(window) >= THRESHOLD:
                first = window[0]
                last  = window[-1]
                duration = last.epoch - first.epoch

                # Classify attack speed
                rate = len(window) / max(duration, 1)
                if rate > 10:
                    speed    = AttackSpeed.AGGRESSIVE
                    severity = Severity.CRITICAL
                elif rate > 3:
                    speed    = AttackSpeed.MODERATE
                    severity = Severity.HIGH
                else:
                    speed    = AttackSpeed.SLOW_SCAN
                    severity = Severity.MEDIUM

                alerts.append(Alert(
                    rule_id=ATTCKTechnique.T1110_001,
                    technique=ATTCKTechnique.T1110_001,
                    severity=severity,
                    timestamp=datetime.now(timezone.utc),
                    first_seen=first.timestamp,
                    last_seen=last.timestamp,
                    source_ip=ip,
                    username=attempt.username,
                    log_source=LogSource.AUTH_LOG,
                    description=(
                        f"{len(window)} failed SSH attempts from {ip} "
                        f"in {duration:.0f}s — {speed.value}"
                    ),
                    extra={
                        "attempt_count": len(window),
                        "attack_speed":  speed.value,
                        "window_seconds": WINDOW_SECONDS,
                    }
                ))

                # Reset window to avoid duplicate alerts for same burst
                window = []

    return alerts