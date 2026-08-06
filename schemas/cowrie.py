"""
schemas/cowrie.py
------------------
Typed schema + parser for Cowrie SSH/Telnet honeypot logs.

WHY THIS SHAPE:
Unlike auditd/auth_log/CloudTrail, a single Cowrie connection produces
many related JSON lines (login attempts, commands, connect/close) sharing
one "session" ID. CowrieLoginAttempt and CowrieCommand are the atomic,
BaseLogEvent-compatible units — each is one real event, one timestamp,
safe to mix into the same flat list as any other log source for rules
and future cross-source correlation.

CowrieSession is a separate, non-BaseLogEvent aggregate used only during
parsing/grouping (and for session-level facts like duration) — it is not
itself iterated by rules.

ORDERING ASSUMPTION:
Events within one Cowrie session are logged synchronously, in the order
they occur (Cowrie is single-threaded per connection) — no re-sorting is
done here. Different sessions may interleave in the raw file; grouping by
session id (not file position) is what makes this safe.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from schemas.base import BaseLogEvent, LogSource


# ── Atomic events (BaseLogEvent subclasses) ─────────────────────────────────

class CowrieLoginAttempt(BaseLogEvent):
    """One login attempt (success or failure) within a Cowrie session."""

    session_id: str
    username: str
    password: str
    success: bool


class CowrieCommand(BaseLogEvent):
    """One command an attacker typed inside the fake Cowrie shell."""

    session_id: str
    input: str


# ── Session aggregate (parsing/grouping helper, not a BaseLogEvent) ─────────

class CowrieSession(BaseModel):
    """Groups all events belonging to one Cowrie connection.

    Built during parsing by grouping raw JSON lines on their shared
    "session" field. Useful for session-level facts (duration, src_ip)
    and as an intermediate step — rules should iterate the flat
    login_attempts / commands lists (or a merged BaseLogEvent stream),
    not this object directly.
    """

    session_id: str
    src_ip: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[int] = None
    login_attempts: list[CowrieLoginAttempt] = []
    commands: list[CowrieCommand] = []

    model_config = {"frozen": False}


# ── Parser ───────────────────────────────────────────────────────────────────

def _parse_ts(raw_ts: str) -> datetime:
    """Cowrie timestamps are ISO-8601 with a trailing 'Z' — normalize to +00:00
    so datetime.fromisoformat() accepts it (matches ensure_utc in base.py)."""
    return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))


def parse_cowrie_sessions(jsonlog_path: str) -> list[CowrieSession]:
    """Read a Cowrie cowrie.json (JSON Lines) file and return one
    CowrieSession per distinct "session" id found in the file.
    """
    sessions_raw: dict[str, list[dict]] = defaultdict(list)

    with open(jsonlog_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            session_id = event.get("session")
            if session_id:
                sessions_raw[session_id].append(event)

    sessions: list[CowrieSession] = []

    for session_id, events in sessions_raw.items():
        src_ip = events[0]["src_ip"]
        start_time: Optional[datetime] = None
        end_time: Optional[datetime] = None
        duration_ms: Optional[int] = None
        login_attempts: list[CowrieLoginAttempt] = []
        commands: list[CowrieCommand] = []

        for event in events:
            eventid = event["eventid"]
            ts = _parse_ts(event["timestamp"])
            raw_line = json.dumps(event)

            if eventid == "cowrie.session.connect":
                start_time = ts

            elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
                login_attempts.append(CowrieLoginAttempt(
                    source=LogSource.COWRIE,
                    timestamp=ts,
                    raw=raw_line,
                    session_id=session_id,
                    username=event["username"],
                    password=event["password"],
                    success=(eventid == "cowrie.login.success"),
                ))

            elif eventid == "cowrie.command.input":
                commands.append(CowrieCommand(
                    source=LogSource.COWRIE,
                    timestamp=ts,
                    raw=raw_line,
                    session_id=session_id,
                    input=event["input"],
                ))

            elif eventid == "cowrie.session.closed":
                end_time = ts
                duration_ms = event.get("duration_ms")

        sessions.append(CowrieSession(
            session_id=session_id,
            src_ip=src_ip,
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            login_attempts=login_attempts,
            commands=commands,
        ))

    return sessions
