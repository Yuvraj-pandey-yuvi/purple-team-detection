import os
from collections import defaultdict
from datetime import datetime, timezone
from schemas import (
    AuditdEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

EXCLUDED_AUIDS = {4294967295, 0}

DISCOVERY_COMMANDS = {
    "uname", "hostname", "uptime",
    "ps", "top", "htop",
    "netstat", "ss", "arp",
    "ifconfig", "ip",
    "df", "mount",
    "env", "printenv",
    "find",
}

WINDOW_SECONDS = 120
THRESHOLD      = 5


def detect(events: list[AuditdEvent]) -> list[Alert]:
    alerts = []

    # Group by auid — each user tracked independently
    by_auid: dict[int, list[AuditdEvent]] = defaultdict(list)

    for event in events:
        if event.auid in EXCLUDED_AUIDS:
            continue
        cmd = os.path.basename(event.exe or "")
        if cmd in DISCOVERY_COMMANDS:
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
                    rule_id     = "rule_013_system_discovery",
                    technique   = ATTCKTechnique.T1082,
                    severity    = Severity.MEDIUM,
                    timestamp   = datetime.now(timezone.utc),
                    first_seen  = first.timestamp,
                    last_seen   = event.timestamp,
                    log_source  = LogSource.AUDITD,
                    description = (
                        f"System discovery by auid={auid}: "
                        f"{len(window)} recon commands in "
                        f"{event.epoch - first.epoch:.0f}s — "
                        f"possible post-exploitation fingerprinting"
                    ),
                    extra = {
                        "auid":     auid,
                        "commands": list({e.comm for e in window}),
                        "count":    len(window),
                    }
                ))
                window = []

    return alerts