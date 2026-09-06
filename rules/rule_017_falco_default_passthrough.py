"""
rules/rule_017_falco_default_passthrough.py
---------------------------------------------
Converts Falco's OWN default-rule alerts into Alert objects -- no new
detection logic here, just a bridge so Falco's existing MITRE-tagged
alerts reach alerts.json/the dashboard before custom ATT&CK-mapped
Falco rules exist (that's the next phase).
"""

import re
from datetime import datetime, timezone
from schemas import (
    FalcoEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

# Extend this ONLY when a real captured Falco alert surfaces a new tag --
# don't pre-populate speculatively (same discipline as output_fields).
# Confirmed so far: T1555 from your own real shadow-read alert.
KNOWN_FALCO_TECHNIQUES = {
    "T1555": ATTCKTechnique.T1555,
}

FALCO_PRIORITY_TO_SEVERITY = {
    "Emergency": Severity.CRITICAL,
    "Alert": Severity.CRITICAL,
    "Critical": Severity.CRITICAL,
    "Error": Severity.HIGH,
    "Warning": Severity.MEDIUM,
    "Notice": Severity.LOW,
    "Informational": Severity.INFO,
    "Debug": Severity.INFO,
}

MITRE_TAG_PATTERN = re.compile(r'^T\d+(\.\d+)?$')


def _extract_technique(tags: list[str]):
    for tag in tags:
        if MITRE_TAG_PATTERN.match(tag):
            if tag in KNOWN_FALCO_TECHNIQUES:
                return KNOWN_FALCO_TECHNIQUES[tag]
            print(f"  [INFO] Unmapped Falco MITRE tag encountered: {tag} "
                  f"-- add it to KNOWN_FALCO_TECHNIQUES + ATTCKTechnique "
                  f"enum once confirmed real")
            return None
    return None


def detect(events: list[FalcoEvent]) -> list[Alert]:
    alerts = []
    skipped_unknown = 0

    for event in events:
        technique = _extract_technique(event.tags)
        if technique is None:
            skipped_unknown += 1
            continue

        severity = FALCO_PRIORITY_TO_SEVERITY.get(event.priority, Severity.MEDIUM)

        alerts.append(Alert(
            rule_id     = "rule_017_falco_default_passthrough",
            technique   = technique,
            severity    = severity,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            username    = event.user_name,
            dedup_key   = f"{event.hostname}:{event.rule}:{event.timestamp.date()}",
            log_source  = LogSource.FALCO,
            description = f"Falco: {event.rule} on {event.hostname} -- {event.output}",
            extra = {
                "hostname":       event.hostname,
                "falco_priority": event.priority,
                "falco_rule":     event.rule,
                "event_source":   event.event_source,
                "proc_name":      event.proc_name,
                "proc_cmdline":   event.proc_cmdline,
                "fd_name":        event.fd_name,
                "container_name": event.container_name,
                "k8s_pod_name":   event.k8s_pod_name,
            }
        ))

    if skipped_unknown:
        print(f"  [INFO] Skipped {skipped_unknown} Falco alerts with unmapped/no MITRE tag")

    return alerts