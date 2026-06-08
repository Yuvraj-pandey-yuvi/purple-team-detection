from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

def detect(events: list[AuditdEvent]) -> list[Alert]:
    """
    Detect auditd tampering via auditctl execution.
    
    Requires audit rule:
      auditctl -w /sbin/auditctl -p x -k auditd_tamper
    
    LIMITATION: Catches the attempt before silence.
    Complement with heartbeat monitoring in log_collector
    for detecting instant kills.
    """
    alerts = []

    for event in events:
        # Primary signal — auditctl was executed
        if event.key != "auditd_tamper":
            continue

        # Any execution of auditctl by a non-system process is suspicious
        severity = (
            Severity.CRITICAL
            if event.is_privileged_escalation
            else Severity.HIGH
        )

        alerts.append(Alert(
            rule_id     = "rule_010_auditd_tamper",
            technique   = ATTCKTechnique.T1562_001,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            log_source  = LogSource.AUDITD,
            description = (
                f"auditctl executed by auid={event.auid} "
                f"euid={event.euid} via {event.exe} — "
                f"possible attempt to disable audit logging"
            ),
            extra = {
                "exe":  event.exe,
                "comm": event.comm,
                "auid": event.auid,
                "euid": event.euid,
            }
        ))

    return alerts