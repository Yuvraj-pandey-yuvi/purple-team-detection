# rules/rule_018_collector_heartbeat.py
"""
rule_018: a log source that stops delivering input is itself an alert.

WHY: for weeks the engine read a frozen copy of auth.log and printed "New lines: 0"
every cycle. "0 alerts" and "0 input" look identical, so nothing noticed. This rule
watches the INPUT, not the alerts.

It needs memory between runs, so detect() takes the previous state and returns the
new one. One alert opens when a source has been silent longer than its limit, and one
"closed" alert (severity INFO) is raised when input resumes, so each outage produces
exactly two alerts, however many cycles it lasts.
"""
from datetime import datetime, timedelta

from schemas import Alert, ATTCKTechnique, Severity, LogSource

RULE_ID = "rule_018_collector_heartbeat"

# How long each source may stay silent. Observed on this host: auth.log gets lines
# in almost every 5-minute cycle and auditd hundreds of events, so one hour of silence
# is abnormal. The honeypot and CloudTrail are burstier, so they get a day.
# Falco is deliberately not listed: its lab cluster is switched off.
SOURCES = {
    "auth_log": {
        "limit": timedelta(hours=1), "log_source": LogSource.AUTH_LOG,
        "technique": ATTCKTechnique.T1562_001, "severity": Severity.HIGH,
    },
    "auditd": {
        "limit": timedelta(hours=1), "log_source": LogSource.AUDITD,
        "technique": ATTCKTechnique.T1562_001, "severity": Severity.HIGH,
    },
    "cowrie": {
        "limit": timedelta(hours=24), "log_source": LogSource.COWRIE,
        "technique": ATTCKTechnique.T1562_001, "severity": Severity.MEDIUM,
    },
    "cloudtrail": {
        "limit": timedelta(hours=24), "log_source": LogSource.CLOUDTRAIL,
        "technique": ATTCKTechnique.T1562_002, "severity": Severity.MEDIUM,
    },
}


def _hours(duration: timedelta) -> float:
    return duration.total_seconds() / 3600


def _open_alert(source: str, config: dict, quiet_since: datetime, now: datetime) -> Alert:
    silent_for = now - quiet_since
    return Alert(
        rule_id=RULE_ID,
        technique=config["technique"],
        severity=config["severity"],
        timestamp=now,
        first_seen=quiet_since,
        last_seen=now,
        log_source=config["log_source"],
        dedup_key=f"{source}|open|{quiet_since.isoformat()}",
        description=(
            f"No {source} input for {_hours(silent_for):.1f}h "
            f"(limit {_hours(config['limit']):g}h). The collector may be stalled, "
            f"the log file may have been replaced, or logging may have been switched off."
        ),
        extra={
            "state": "open",
            "source": source,
            "silent_seconds": int(silent_for.total_seconds()),
            "limit_seconds": int(config["limit"].total_seconds()),
            "quiet_since": quiet_since.isoformat(),
        },
    )


def _closed_alert(source: str, config: dict, quiet_since: datetime, now: datetime) -> Alert:
    outage = now - quiet_since
    return Alert(
        rule_id=RULE_ID,
        technique=config["technique"],
        severity=Severity.INFO,
        timestamp=now,
        first_seen=quiet_since,
        last_seen=now,
        log_source=config["log_source"],
        dedup_key=f"{source}|closed|{quiet_since.isoformat()}",
        description=f"{source} input resumed after {_hours(outage):.1f}h of silence.",
        extra={
            "state": "closed",
            "source": source,
            "outage_seconds": int(outage.total_seconds()),
            "quiet_since": quiet_since.isoformat(),
        },
    )


def detect(received: dict, state: dict, now: datetime) -> tuple[list[Alert], dict]:
    """
    received: {source: number of raw input items collected this cycle}
    state:    what this function returned last time ({} on the very first run)
    now:      timezone-aware current time (passed in so tests can control it)

    Returns (alerts, new_state). The state per source is:
      watching_since - when we first saw the source (a source that never delivers
                       is measured from here, so it alerts after its limit, not at once)
      last_input     - last time input arrived (None until then)
      outage_since   - when the current outage began (None when healthy)
    """
    alerts: list[Alert] = []
    new_state: dict = {}

    for source, config in SOURCES.items():
        entry = dict(state.get(source) or {})
        entry.setdefault("watching_since", now.isoformat())
        entry.setdefault("last_input", None)
        entry.setdefault("outage_since", None)

        if received.get(source, 0) > 0:
            if entry["outage_since"]:
                quiet_since = datetime.fromisoformat(entry["outage_since"])
                alerts.append(_closed_alert(source, config, quiet_since, now))
                entry["outage_since"] = None
            entry["last_input"] = now.isoformat()

        elif entry["outage_since"] is None:
            quiet_since = datetime.fromisoformat(entry["last_input"] or entry["watching_since"])
            if now - quiet_since > config["limit"]:
                entry["outage_since"] = quiet_since.isoformat()
                alerts.append(_open_alert(source, config, quiet_since, now))

        new_state[source] = entry

    return alerts, new_state
