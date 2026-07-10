import os
from collections import defaultdict
from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

EXCLUDED_AUIDS = {4294967295, 0}

ENUMERATION_COMMANDS = {
    "whoami", "id", "who", "w", "getent", "finger",
    "groups", "last", "lastlog", "users"
}

SENSITIVE_FILES = {
    "/etc/passwd", "/etc/group",
    "/etc/sudoers", "/etc/shadow"
}

WINDOW_SECONDS = 120
THRESHOLD      = 5

def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []
    by_auid: dict[int, list[AuditdEvent]] = defaultdict(list)

    # Loop 1: populate by_auid
    for event in events:
        if event.auid in EXCLUDED_AUIDS:
            continue

        cmd = os.path.basename(event.exe or "")
        is_enum_cmd = cmd in ENUMERATION_COMMANDS
        is_cat_sensitive = (cmd == "cat" and event.name in SENSITIVE_FILES)
        is_sensitive_file = event.name in SENSITIVE_FILES and cmd != "cat"

        if not (is_enum_cmd or is_cat_sensitive or is_sensitive_file):
            continue

        by_auid[event.auid].append(event)

    # Loop 2: sliding window per auid
    for auid, auid_events in by_auid.items():
        auid_events.sort(key=lambda e: e.epoch)
        window = []
        for event in auid_events:
            window = [e for e in window
                      if event.epoch - e.epoch <= WINDOW_SECONDS]
            window.append(event)
            if len(window) >= THRESHOLD:
                first = window[0]
                alerts.append(Alert(
                    rule_id     = "rule_012_account_enumeration",
                    technique   = ATTCKTechnique.T1087_001,
                    severity    = Severity.HIGH,
                    timestamp   = datetime.now(timezone.utc),
                    first_seen  = first.timestamp,
                    last_seen   = event.timestamp,
                    log_source  = LogSource.AUDITD,
                    description = (
                        f"Account enumeration by auid={auid}: "
                        f"{len(window)} events in "
                        f"{event.epoch - first.epoch:.0f}s — "
                        f"commands: {set(e.comm for e in window)}"
                    ),
                    extra = {
                        "auid":     auid,
                        "commands": list({e.comm for e in window}),
                        "files":    list({e.name for e in window if e.name}),
                        "count":    len(window),
                    }
                ))
                window = []
    return alerts