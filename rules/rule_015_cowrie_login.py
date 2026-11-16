from collections import defaultdict
from datetime import datetime, timezone
from schemas import CowrieSession, Alert, ATTCKTechnique, Severity, LogSource

# NOTE: "honeypot login" has no dedicated ATT&CK technique — ATT&CK describes
# attacker behavior, not defender deception infra. A successful login here
# IS technically a brute-force success (T1110.001), same family rule_007
# already uses for real SSH. Reusing it is deliberate, not a placeholder:
# it means the dashboard's T1110.001 coverage now reflects both real-target
# and honeypot successes. If that muddies the coverage story later, split
# out a distinct enum value — flagged here so it isn't forgotten.

import re

# Word-boundary matching, not raw substring — avoids false positives like
# "wget" appearing inside an unrelated echo string. Small known-tools list,
# same tier of effort as SHADOW_WHITELIST/TAMPER_KEYS elsewhere in this repo.
# Known limitation, not fixed here: deliberate evasion (w''get, base64-decoded
# eval, variable reassembly) won't match. Acceptable because this only
# enriches metadata on an alert that's already CRITICAL from the login
# itself — it never decides whether to alert, only what the extra fields say.
DOWNLOAD_TOOL_PATTERN = re.compile(r"\b(wget|curl|nc|ncat|netcat)\b")
CHMOD_X_PATTERN = re.compile(r"chmod\s+\+x")


def _detect_download_tools(commands: list) -> list[str]:
    found = set()
    for cmd in commands:
        for match in DOWNLOAD_TOOL_PATTERN.findall(cmd.input):
            found.add(match)
    return sorted(found)


def _detect_chmod_x(commands: list) -> bool:
    return any(CHMOD_X_PATTERN.search(cmd.input) for cmd in commands)


def _as_utc(moment: datetime) -> datetime:
    """Force a datetime to UTC-aware so max()/date() never mix naive and aware."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def detect(sessions: list[CowrieSession]) -> list[Alert]:
    """T1110.001 (Cowrie honeypot) — one CRITICAL alert per SOURCE IP per UTC
    DAY (per batch), not per session.

    Why: a single bot opened ~13,900 honeypot sessions in ten hours on
    2026-11-13. With one alert per session that was ~13,900 alerts, the
    alert store grew past the engine's memory limit and the engine was
    OOM-killed in a restart loop. Nothing legitimate ever authenticates
    against a honeypot, so every success is already 100% confidence — more
    alerts for the same IP the same day add noise, not information.

    dedup_key is "<ip>|<UTC date of first success>", the same shape as
    rule_001, so engine.py's deduplicate_alerts() keeps one alert per IP
    per day even across engine runs.

    Known limits (accepted on purpose, document before relying on them):
      * The count is a LOWER BOUND. This rule only sees the sessions of the
        current batch; the first batch of the day creates the alert and
        later batches for the same IP are deduplicated away. The alert says
        "at least N" and carries extra["count_is_lower_bound"] = True. The
        true session totals live in cowrie.db and on the dashboard.
      * extra["download_tools"] / extra["chmod_x_used"] are merged across the
        sessions of the FIRST batch only. A wget or chmod +x in a later
        session the same day is not added to the alert (historically ~1 in
        28,000 alerts had either). Payload details are read from cowrie.db
        when wanted; no separate per-session alert is raised.
    """
    # (src_ip, UTC date) -> [(session, its first successful login), ...]
    groups: dict[tuple[str, str], list] = defaultdict(list)

    for session in sessions:
        successes = [a for a in session.login_attempts if a.success]
        if not successes:
            continue
        first_success = successes[0]
        day = _as_utc(first_success.timestamp).date().isoformat()
        groups[(session.src_ip, day)].append((session, first_success))

    alerts: list[Alert] = []

    for (src_ip, day), members in groups.items():
        members.sort(key=lambda member: _as_utc(member[1].timestamp))
        first_session, first_success = members[0]
        group_sessions = [session for session, _ in members]
        all_commands = [cmd for session in group_sessions for cmd in session.commands]

        session_count = len(group_sessions)
        login_attempt_count = sum(len(s.login_attempts) for s in group_sessions)
        command_count = len(all_commands)
        download_tools = _detect_download_tools(all_commands)
        chmod_used = _detect_chmod_x(all_commands)
        last_seen = max(
            _as_utc(session.end_time or success.timestamp)
            for session, success in members
        )

        alerts.append(Alert(
            rule_id="rule_015_cowrie_login",
            technique=ATTCKTechnique.T1110_001,
            severity=Severity.CRITICAL,
            timestamp=datetime.now(timezone.utc),
            first_seen=first_success.timestamp,
            last_seen=last_seen,
            source_ip=src_ip,
            username=first_success.username,
            dedup_key=f"{src_ip}|{day}",
            log_source=LogSource.COWRIE,
            description=(
                f"Honeypot login succeeded from {src_ip} — "
                f"at least {session_count} session(s) on {day} (UTC), "
                f"{login_attempt_count} login attempt(s), "
                f"first credentials {first_success.username}/{first_success.password}, "
                f"{command_count} command(s) run post-login. "
                f"Count is a lower bound: later sessions the same day are "
                f"deduplicated into this alert; totals are in cowrie.db. "
                f"100% confidence — no legitimate traffic reaches this port."
            ),
            extra={
                "first_session_id": first_session.session_id,
                "session_count": session_count,
                "count_is_lower_bound": True,
                "login_attempt_count": login_attempt_count,
                "command_count": command_count,
                "password": first_success.password,
                "download_tools": download_tools,
                "chmod_x_used": chmod_used,
            },
        ))

    alerts.sort(key=lambda alert: (_as_utc(alert.first_seen), alert.source_ip))
    return alerts
