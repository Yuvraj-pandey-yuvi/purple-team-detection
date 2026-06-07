from datetime import datetime, timezone
from schemas import (
    CloudTrailEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

CRITICAL_EVENTS = {"DeleteTrail", "StopLogging"}
HIGH_EVENTS     = {"UpdateTrail", "PutEventSelectors"}

def detect(events: list[CloudTrailEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.event_name in CRITICAL_EVENTS:
            severity = Severity.CRITICAL
        elif event.event_name in HIGH_EVENTS:
            severity = Severity.HIGH
        else:
            continue

        alerts.append(Alert(
            rule_id     = "rule_009_cloudtrail_disabled",
            technique   = ATTCKTechnique.T1562_002,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            source_ip   = event.source_ip,
            username    = event.actor_username,
            log_source  = LogSource.CLOUDTRAIL,
            description = (
                f"CloudTrail impaired: {event.event_name} "
                f"by {event.actor_username} from {event.source_ip}"
            ),
            extra = {
                "event_name":  event.event_name,
                "aws_region":  event.aws_region,
                "user_agent":  event.user_agent,
                "actor_type":  event.actor_type,
            }
        ))

    return alerts