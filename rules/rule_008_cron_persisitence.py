from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)
 
# Syscalls that reference a watched PATH and modify it or its
# attributes — NOT literally "syscalls that write data" (plain write()
# operates on an already-open file descriptor, not a path, so it never
# matches an auditd path-watch rule in the first place).
# 257=openat, 2=open, 82=rename, 86=link
CRON_PATH_WRITE_SYSCALLS = {257, 2, 82, 86}
def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:
        if event.key != "cron_modification":
            continue
        if event.syscall is None:
            continue
        if int(event.syscall) not in CRON_PATH_WRITE_SYSCALLS:
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
            dedup_key=f"{event.exe}:{event.auid}:{event.name}",
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