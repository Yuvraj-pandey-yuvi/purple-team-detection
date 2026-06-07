from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

WRITE_SYSCALLS = {257, 2, 82, 86}  # openat, open, rename, link

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.key != "cron_modification":
            continue
        if event.syscall is None:
            continue
        if int(event.syscall) not in WRITE_SYSCALLS:
            continue  # ignore ls, stat, read-only access

        severity = (
            Severity.CRITICAL
            if event.is_privileged_escalation
            else Severity.HIGH
        )

        alerts.append(Alert(
            rule_id     = "rule_008_cron_persistence",
            technique   = ATTCKTechnique.T1053_003,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.AUDITD,
            description = (
                f"Cron file modified: {event.name or 'unknown'} "
                f"by {event.exe} "
                f"(auid={event.auid}, euid={event.euid})"
            ),
            extra = {
                "exe":     event.exe,
                "comm":    event.comm,
                "auid":    event.auid,
                "euid":    event.euid,
                "syscall": event.syscall,
                "file":    event.name,
            }
        ))

    return alerts