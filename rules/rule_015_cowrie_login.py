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

def detect(sessions: list[CowrieSession]) -> list[Alert]:
    """T1110.001 (Cowrie honeypot) — one CRITICAL alert per SESSION that
    contains at least one successful login, not per login attempt.

    No threshold tuning needed, unlike rule_001/rule_007: nothing legitimate
    ever authenticates against a honeypot, so any success is 100% confidence
    malicious. The only judgment call is dedup granularity — a session can
    have several failed attempts before a success, and we don't want one
    dashboard alert per attempt (bot traffic would flood alerts.json).
    dedup_key is the session_id itself, so re-running the engine against
    the same session data never produces duplicate alerts.
    """
    alerts: list[Alert] = []

    for session in sessions:
        successes = [a for a in session.login_attempts if a.success]
        if not successes:
            continue

        first_success = successes[0]
        download_tools = _detect_download_tools(session.commands)
        chmod_used = _detect_chmod_x(session.commands)

        alerts.append(Alert(
            rule_id="rule_015_cowrie_login",
            technique=ATTCKTechnique.T1110_001,
            severity=Severity.CRITICAL,
            timestamp=datetime.now(timezone.utc),
            first_seen=first_success.timestamp,
            last_seen=(session.end_time or first_success.timestamp),
            source_ip=session.src_ip,
            username=first_success.username,
            dedup_key=f"cowrie_login:{session.session_id}",
            log_source=LogSource.COWRIE,
            description=(
                f"Honeypot login succeeded from {session.src_ip} "
                f"(session {session.session_id}) — "
                f"{len(session.login_attempts)} login attempt(s), "
                f"credentials {first_success.username}/{first_success.password}, "
                f"{len(session.commands)} command(s) run post-login. "
                f"100% confidence — no legitimate traffic reaches this port."
            ),
            extra={
                "session_id": session.session_id,
                "login_attempt_count": len(session.login_attempts),
                "command_count": len(session.commands),
                "password": first_success.password,
		"download_tools": download_tools,
                "chmod_x_used": chmod_used,
            },
        ))

    return alerts
