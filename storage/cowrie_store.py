"""
storage/cowrie_store.py — SQLite persistence layer for Cowrie honeypot data.

Lives alongside reports/alerts.json (same reports/ dir, matching engine.py's
ALERTS_FILE convention) as reports/cowrie.db — one file, no server process,
stdlib sqlite3 only.

Three tables:
  sessions          — one row per Cowrie session (keyed by session_id)
  session_logins    — one row per login attempt (FK -> sessions)
  session_commands  — one row per command run (FK -> sessions)
  blocked_ips       — one row per blocked IP (keyed by ip)

WHY SQLITE HERE BUT alerts.json ELSEWHERE (polyglot persistence, deliberate):
  - alerts.json: low volume, read rarely, human-readable -> flat file is fine
  - Cowrie data: grows unbounded under real internet exposure, needs to be
    queried by src_ip/timestamp for Phase 5 correlation without a full scan
    on every lookup -> needs an index, hence SQLite

WHY blocked_ips IS ITS OWN TABLE, NOT A COLUMN ON sessions:
  Blocking is an IP-level concept — one IP can have many sessions. Putting
  is_blocked on sessions means updating N rows per block/unblock, and every
  future session insert from that IP would need to remember to re-check the
  flag. One row per IP, independent of session count, is correct.

WHY session_commands / session_logins ARE SEPARATE TABLES, NOT JSON BLOBS:
  A session can have multiple login attempts and multiple commands.
  Cramming them into one text column loses queryability — "find every
  session where wget was run" becomes a LIKE scan with no index. Broken
  into their own tables with an FK back to session_id, that's an indexed
  lookup instead.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from schemas import CowrieSession

# Matches engine.py's ALERTS_FILE convention: reports/ dir, one level up
# from this file's parent (storage/cowrie_store.py -> project root/reports/)
DB_PATH = Path(__file__).resolve().parent.parent / "reports" / "cowrie.db"


@contextmanager
def _get_conn(db_path: Path = DB_PATH):
    """Always closes the connection; rolls back on exception."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH) -> None:
    """
    Create tables/indexes if missing. Idempotent — safe to call on every
    engine startup, same spirit as engine.py's os.makedirs before writes.
    """
    with _get_conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                src_ip      TEXT NOT NULL,
                start_time  TEXT,
                end_time    TEXT,
                duration_ms INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_src_ip
                ON sessions(src_ip);

            CREATE INDEX IF NOT EXISTS idx_sessions_start_time
                ON sessions(start_time);

            CREATE TABLE IF NOT EXISTS session_logins (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL REFERENCES sessions(session_id),
                username    TEXT NOT NULL,
                password    TEXT NOT NULL,
                success     INTEGER NOT NULL,   -- 1/0, sqlite has no bool
                timestamp   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_logins_session_id
                ON session_logins(session_id);

            CREATE TABLE IF NOT EXISTS session_commands (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT NOT NULL REFERENCES sessions(session_id),
                command_text  TEXT NOT NULL,
                ran_at        TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_commands_session_id
                ON session_commands(session_id);

            CREATE INDEX IF NOT EXISTS idx_commands_text
                ON session_commands(command_text);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip            TEXT PRIMARY KEY,
                blocked_at    TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                session_count INTEGER NOT NULL DEFAULT 0,
                reason        TEXT,
                blocked_by    TEXT NOT NULL DEFAULT 'manual'
                               CHECK(blocked_by IN ('manual', 'auto'))
            );
        """)


def store_session(session: CowrieSession, db_path: Path = DB_PATH) -> None:
    """
    Persist one CowrieSession (+ its login attempts + commands).
    INSERT OR IGNORE on session_id — idempotent, safe to call on every
    engine run even if the session was already stored.
    """
    with _get_conn(db_path) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO sessions
                (session_id, src_ip, start_time, end_time, duration_ms)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.src_ip,
            session.start_time.isoformat() if session.start_time else None,
            session.end_time.isoformat() if session.end_time else None,
            session.duration_ms,
        ))

        already_have_children = conn.execute(
            "SELECT 1 FROM session_logins WHERE session_id = ? LIMIT 1",
            (session.session_id,)
        ).fetchone()

        if already_have_children is None:
            for attempt in session.login_attempts:
                conn.execute("""
                    INSERT INTO session_logins
                        (session_id, username, password, success, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    session.session_id,
                    attempt.username,
                    attempt.password,
                    1 if attempt.success else 0,
                    attempt.timestamp.isoformat(),
                ))

            for cmd in session.commands:
                conn.execute("""
                    INSERT INTO session_commands
                        (session_id, command_text, ran_at)
                    VALUES (?, ?, ?)
                """, (
                    session.session_id,
                    cmd.input,
                    cmd.timestamp.isoformat(),
                ))


def get_sessions_by_ip(src_ip: str, db_path: Path = DB_PATH) -> list[dict]:
    """Phase 5 correlation entry point — indexed lookup via idx_sessions_src_ip."""
    with _get_conn(db_path) as conn:
        rows = conn.execute("""
            SELECT * FROM sessions WHERE src_ip = ?
            ORDER BY start_time DESC
        """, (src_ip,)).fetchall()
        return [dict(r) for r in rows]


def get_commands_by_session(session_id: str, db_path: Path = DB_PATH) -> list[dict]:
    with _get_conn(db_path) as conn:
        rows = conn.execute("""
            SELECT * FROM session_commands WHERE session_id = ?
            ORDER BY ran_at ASC
        """, (session_id,)).fetchall()
        return [dict(r) for r in rows]


def block_ip(
    ip: str,
    reason: str,
    blocked_by: str = "manual",
    db_path: Path = DB_PATH,
) -> None:
    """
    Add/update an IP in blocked_ips. attempt_count and session_count are
    computed from existing session data at block time, not passed in —
    keeps the caller (dashboard button) simple.
    """
    with _get_conn(db_path) as conn:
        session_count = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE src_ip = ?", (ip,)
        ).fetchone()[0]

        attempt_count = conn.execute("""
            SELECT COUNT(*) FROM session_logins sl
            JOIN sessions s ON sl.session_id = s.session_id
            WHERE s.src_ip = ?
        """, (ip,)).fetchone()[0]

        conn.execute("""
            INSERT OR REPLACE INTO blocked_ips
                (ip, blocked_at, attempt_count, session_count, reason, blocked_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ip,
            datetime.now(timezone.utc).isoformat(),
            attempt_count,
            session_count,
            reason,
            blocked_by,
        ))


def unblock_ip(ip: str, db_path: Path = DB_PATH) -> None:
    with _get_conn(db_path) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def is_blocked(ip: str, db_path: Path = DB_PATH) -> bool:
    with _get_conn(db_path) as conn:
        return conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)
        ).fetchone() is not None


def get_all_blocked(db_path: Path = DB_PATH) -> list[dict]:
    with _get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
