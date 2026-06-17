import os
from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

SHADOW_WHITELIST = {
    "/usr/bin/passwd",
    "/usr/sbin/unix_chkpwd", 
    "/usr/bin/sudo",
    "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
}

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    for event in events:

        # Signal 1: Shadow file access by unknown process (T1003.008)
        if event.key == "shadow_access" and event.exe not in SHADOW_WHITELIST:
            alerts.append(Alert(
                rule_id     = "rule_004_shadow_access",
                technique   = ATTCKTechnique.T1003_008,
                severity    = Severity.CRITICAL,
                timestamp   = datetime.now(timezone.utc),
                first_seen  = event.timestamp,
                log_source  = LogSource.AUDITD,
                description = (
                    f"Unauthorized /etc/shadow access by {event.exe} "
                    f"(auid={event.auid}, euid={event.euid})"
                ),
                extra = {
                    "exe":  event.exe,
                    "comm": event.comm,
                    "auid": event.auid,
                    "euid": event.euid,
                    "key":  event.key,
                }
            ))

        # Signal 2: Process name mismatch — masquerading (T1036.005)
        if not event.exe_matches_comm and event.exe:
            alerts.append(Alert(
                rule_id     = "rule_004_masquerading",
                technique   = ATTCKTechnique.T1036,
                severity    = Severity.CRITICAL,
                timestamp   = datetime.now(timezone.utc),
                first_seen  = event.timestamp,
                log_source  = LogSource.AUDITD,
                description = (
                    f"Process name mismatch: comm='{event.comm}' "
                    f"but exe='{event.exe}' — possible masquerading"
                ),
                extra = {
                    "exe":  event.exe,
                    "comm": event.comm,
                    "auid": event.auid,
                    "pid":  event.pid,
                }
            ))

    return alerts