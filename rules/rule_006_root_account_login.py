from datetime import datetime, timezone
from schemas import (
    CloudTrailEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

def detect(events: list[CloudTrailEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if not (event.actor_type == "Root" and event.is_console_login):
            continue

        alerts.append(Alert(
            rule_id     = "rule_006_root_account_login",
            technique   = ATTCKTechnique.T1078_001,
            severity    = Severity.CRITICAL,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.CLOUDTRAIL,
            description = (
                f"Root account console login detected from "
                f"{event.source_ip} — root should never log in directly"
            ),
            extra = {
                "source_ip":   event.source_ip,
                "aws_region":  event.aws_region,
                "user_agent":  event.user_agent,
                "event_name":  event.event_name,
            }
        ))

    return alerts