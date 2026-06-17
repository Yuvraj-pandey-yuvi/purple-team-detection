from datetime import datetime, timezone
from schemas import (
    CloudTrailEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

def detect(events: list[CloudTrailEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.is_suspicious_login:
            severity    = Severity.CRITICAL
            description = (
                f"Console login without MFA by {event.actor_username} "
                f"from {event.source_ip}"
            )
        elif event.is_api_call_without_mfa:
            severity    = Severity.MEDIUM
            description = (
                f"API call {event.event_name} without MFA "
                f"by {event.actor_username} from {event.source_ip}"
            )
        else:
            continue

        alerts.append(Alert(
            rule_id     = "rule_002_console_login_no_mfa",
            technique   = ATTCKTechnique.T1078,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            source_ip   = event.source_ip,
            username    = event.actor_username,
            log_source  = LogSource.CLOUDTRAIL,
            description = description,
            extra       = {
                "event_name": event.event_name,
                "aws_region": event.aws_region,
                "mfa_authenticated": event.mfa_authenticated,
            }
        ))

    return alerts