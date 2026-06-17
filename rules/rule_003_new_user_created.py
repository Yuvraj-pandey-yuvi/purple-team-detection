from datetime import datetime, timezone
from schemas import (
    AuthLogEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

SUSPICIOUS_NAMES = {
    "root", "daemon", "sys", "bin",
    "admin", "administrator", "ubuntu",
    "ec2-user", "support", "service",
    "backup", "sysadmin"
}

def detect(events: list[AuthLogEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.new_username is None:
            continue

        severity = (
            Severity.CRITICAL
            if event.new_username in SUSPICIOUS_NAMES
            else Severity.HIGH
        )

        alerts.append(Alert(
            rule_id     = "rule_003_new_user_created",
            technique   = ATTCKTechnique.T1136_001,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            username    = event.new_username,
            log_source  = LogSource.AUTH_LOG,
            description = (
                f"New user '{event.new_username}' created on {event.hostname}"
                + (" [SUSPICIOUS NAME]" if event.new_username in SUSPICIOUS_NAMES else "")
            ),
            extra = {
                "new_username":  event.new_username,
                "hostname":      event.hostname,
                "sudo_user":     event.sudo_user,
                "sudo_command":  event.sudo_command,
            }
        ))

    return alerts