from collections import defaultdict
from datetime import datetime, timezone
from schemas import (
    AuthLogEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

THRESHOLD_ATTEMPTS = 5
WINDOW_SECONDS     = 600  # 10 minutes

def detect(events: list[AuthLogEvent]) -> list[Alert]:
    alerts = []

    # Step 1: group by IP
    failed_by_ip   = defaultdict(list)
    accepted_by_ip = defaultdict(list)

    for event in events:
        if event.auth_result == "failed" and event.source_ip:
            failed_by_ip[event.source_ip].append(event)
        elif event.auth_result == "accepted" and event.source_ip:
            accepted_by_ip[event.source_ip].append(event)

    # Step 2: for each successful login check if preceded by failures
    for ip, accepted_events in accepted_by_ip.items():
        if ip not in failed_by_ip:
            continue  # no failures from this IP — not suspicious

        failures = failed_by_ip[ip]

        if len(failures) < THRESHOLD_ATTEMPTS:
            continue  # not enough failures to be brute force

        for accepted in accepted_events:
            last_failure = failures[-1]
            time_diff = accepted.epoch - last_failure.epoch

            if 0 <= time_diff <= WINDOW_SECONDS:
                alerts.append(Alert(
                    rule_id     = "rule_007_brute_force_success",
                    technique   = ATTCKTechnique.T1110_001,
                    severity    = Severity.CRITICAL,
                    timestamp   = datetime.now(timezone.utc),
                    first_seen  = failures[0].timestamp,
                    last_seen   = accepted.timestamp,
                    source_ip   = ip,
                    username    = accepted.username,
                    log_source  = LogSource.AUTH_LOG,
                    description = (
                        f"Brute force SUCCESS — {len(failures)} failures "
                        f"from {ip} followed by successful login as "
                        f"'{accepted.username}' "
                        f"{time_diff:.0f}s after last failure"
                    ),
                    extra = {
                        "attempt_count": len(failures),
                        "seconds_after_last_failure": time_diff,
                        "last_failure_time": str(last_failure.timestamp),
                        "success_time":      str(accepted.timestamp),
                    }
                ))

    return alerts