import os
from collections import defaultdict
from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

ENUMERATION_COMMANDS = {
    "whoami", "id", "who", "w", "getent", "finger"
}

SENSITIVE_FILES = {
    "/etc/passwd", "/etc/group",
    "/etc/sudoers", "/etc/shadow"
}

WINDOW_SECONDS = 120
THRESHOLD      = 3


def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    # Group events by auid — different users tracked separately
    by_auid: dict[int, list[AuditdEvent]] = defaultdict(list)

    for event in events:
        cmd = os.path.basename(event.exe or "")

        # cat only counts when accessing sensitive files
        is_enum_cmd = cmd in ENUMERATION_COMMANDS
        is_cat_sensitive = (cmd == "cat" and event.name in SENSITIVE_FILES)
        is_sensitive_file = event.name in SENSITIVE_FILES and cmd != "cat"

        if not (is_enum_cmd or is_cat_sensitive or is_sensitive_file):
            continue

        by_auid[event.auid].append(event)

    # Sliding window per auid
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
                        "files":    list({e.name for e in window
                                          if e.name}),
                        "count":    len(window),
                    }
                ))
                window = []  # reset after alert

    return alerts