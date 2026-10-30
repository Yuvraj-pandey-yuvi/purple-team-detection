# detection/public_alerts.py
"""
Public-safe alert store for the dashboard's alerts page.

The engine builds public_alerts.db (SQLite) from alerts.json each cycle; the read-only
dashboard pod queries it one day / one page at a time, so it never loads the 13 MB file.

WHAT IS EXCLUDED: the owner's own activity (auid in OWNER_AUIDS, checked in BOTH the
top-level field and extra['auid'], because rule_014 only stores it in extra), heartbeat
alerts (pipeline health, not detections) and INFO alerts.
WHAT IS MASKED: AWS account IDs, internal hostnames, private/loopback IPs and any IP listed in
PURPLE_MASK_IPS (the server's and owner's addresses). Attacker IPs are left alone.
RAW LOG: only shown for log sources that carry attacker traffic (auth_log, cowrie).

The database is rebuilt into a temp file and swapped in with os.replace, so a reader
always sees a complete file, and only when the set of alerts actually changed.
"""
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone

SCHEMA_VERSION = "1"
OWNER_AUIDS = {x.strip() for x in os.environ.get("PURPLE_INTERNAL_AUIDS", "1000").split(",") if x.strip()}
EXCLUDED_RULES = {"rule_018_collector_heartbeat"}
RAW_LOG_SOURCES = {"auth_log", "cowrie"}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
MAX_EXTRA_KEYS, MAX_VALUE_CHARS, MAX_PER_PAGE = 30, 500, 100

_ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")
_HOSTNAME = re.compile(r"\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _enum(value) -> str:
    return getattr(value, "value", str(value))


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def mask_text(value, hidden_ips=None) -> str:
    """Hide what must not be public; leave attacker-controlled data (global IPs) intact."""
    hidden = set(hidden_ips if hidden_ips is not None else
                 {x.strip() for x in os.environ.get("PURPLE_MASK_IPS", "").split(",") if x.strip()})

    def ip_sub(match):
        text = match.group(0)
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return text
        return "[masked-ip]" if (not address.is_global or text in hidden) else text

    text = _CONTROL.sub(" ", str(value))
    text = _ACCOUNT_ID.sub("[aws-account]", text)
    text = _HOSTNAME.sub("[internal-host]", text)
    return _IPV4.sub(ip_sub, text)


def is_owner_activity(alert) -> bool:
    extra_auid = str((alert.extra or {}).get("auid", "")).strip()
    return str(alert.auid) in OWNER_AUIDS or extra_auid in OWNER_AUIDS


def is_public(alert) -> bool:
    return (alert.rule_id not in EXCLUDED_RULES and _enum(alert.severity) != "INFO"
            and not is_owner_activity(alert))


def event_moment(alert) -> datetime:
    return _utc(alert.first_seen or alert.timestamp)


def alert_id(alert) -> str:
    key = f"{alert.rule_id}|{alert.dedup_key or alert.description}|{event_moment(alert).isoformat()}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def public_view(alert, hidden_ips=None) -> dict:
    source = _enum(alert.log_source)
    raw = alert.raw_log or ""
    show_raw = bool(raw) and source in RAW_LOG_SOURCES
    moment = event_moment(alert)
    return {
        "id": alert_id(alert), "rule_id": alert.rule_id, "technique": _enum(alert.technique),
        "severity": _enum(alert.severity), "severity_rank": SEVERITY_RANK.get(_enum(alert.severity), 0),
        "log_source": source, "timestamp": moment.isoformat(), "day": moment.date().isoformat(),
        "first_seen": _utc(alert.first_seen).isoformat() if alert.first_seen else None,
        "last_seen": _utc(alert.last_seen).isoformat() if alert.last_seen else None,
        "source_ip": mask_text(alert.source_ip, hidden_ips) if alert.source_ip else None,
        "username": mask_text(alert.username, hidden_ips)[:80] if alert.username else None,
        "auid": alert.auid, "dedup_key": mask_text(alert.dedup_key, hidden_ips)[:200] if alert.dedup_key else None,
        "description": mask_text(alert.description, hidden_ips)[:2000],
        "extra": {mask_text(k, hidden_ips)[:60]: mask_text(v, hidden_ips)[:MAX_VALUE_CHARS]
                  for k, v in list((alert.extra or {}).items())[:MAX_EXTRA_KEYS]},
        "raw_log": mask_text(raw, hidden_ips)[:4000] if show_raw else None,
        "raw_log_note": None if show_raw or not raw else "withheld (internal telemetry)",
    }


def _create(connection):
    connection.executescript("""
        CREATE TABLE alerts (id TEXT PRIMARY KEY, day TEXT NOT NULL, ts TEXT NOT NULL,
            severity_rank INTEGER NOT NULL, severity TEXT NOT NULL, rule_id TEXT NOT NULL,
            log_source TEXT NOT NULL, source_ip TEXT, description TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE INDEX idx_day_prio ON alerts(day, severity_rank DESC, ts DESC);
        CREATE INDEX idx_day_time ON alerts(day, ts DESC);
        CREATE INDEX idx_prio ON alerts(severity_rank DESC, ts DESC);
        CREATE INDEX idx_rule ON alerts(rule_id);
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);""")


def rebuild(alerts, db_path: str, hidden_ips=None) -> bool:
    """Rebuild the public database if the set of public alerts changed. True if rebuilt."""
    chosen = {alert_id(a): a for a in alerts if is_public(a)}       # cheap: ids only, no masking yet
    fingerprint = hashlib.sha1((SCHEMA_VERSION + "|" + ",".join(sorted(chosen))).encode()).hexdigest()
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        current = connection.execute("SELECT value FROM meta WHERE key='fingerprint'").fetchone()
        connection.close()
        if current and current[0] == fingerprint:
            return False
    except sqlite3.Error:
        pass
    temp_path = db_path + ".tmp"
    if os.path.exists(temp_path):
        os.remove(temp_path)

    def rows():                                                      # one view at a time: flat memory
        for alert in chosen.values():
            v = public_view(alert, hidden_ips)
            yield (v["id"], v["day"], v["timestamp"], v["severity_rank"], v["severity"], v["rule_id"],
                   v["log_source"], v["source_ip"], v["description"], json.dumps(v, separators=(",", ":")))

    connection = sqlite3.connect(temp_path)
    try:
        _create(connection)
        connection.executemany("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)", rows())
        connection.execute("INSERT INTO meta VALUES ('fingerprint', ?)", (fingerprint,))
        connection.commit()
    finally:
        connection.close()
    os.replace(temp_path, db_path)
    return True


def _open(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def list_days(db_path: str) -> list[dict]:
    connection = _open(db_path)
    try:
        return [dict(r) for r in connection.execute(
            "SELECT day, COUNT(*) AS count, SUM(severity_rank=4) AS critical, SUM(severity_rank=3) AS high "
            "FROM alerts GROUP BY day ORDER BY day DESC")]
    finally:
        connection.close()


def rule_counts(db_path: str, since_iso: str) -> dict[str, dict]:
    connection = _open(db_path)
    try:
        return {r["rule_id"]: {"total": r["total"], "last_24h": r["recent"], "last_seen": r["last"]}
                for r in connection.execute(
                    "SELECT rule_id, COUNT(*) AS total, SUM(ts >= ?) AS recent, MAX(ts) AS last "
                    "FROM alerts GROUP BY rule_id", (since_iso,))}
    finally:
        connection.close()


def query_alerts(db_path: str, day=None, since=None, sort="priority", rule=None, page=1, per_page=50) -> dict:
    """One page of alerts. Every user-supplied value is validated or bound as a parameter."""
    order = "severity_rank DESC, ts DESC, id" if sort != "time" else "ts DESC, id"
    where, params = [], []
    if day and _DAY.match(day):
        where.append("day = ?"); params.append(day)
    if since:
        where.append("ts >= ?"); params.append(str(since)[:40])
    if rule:
        where.append("rule_id = ?"); params.append(str(rule)[:80])
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    per_page = max(1, min(int(per_page), MAX_PER_PAGE))
    connection = _open(db_path)
    try:
        total = connection.execute(f"SELECT COUNT(*) FROM alerts {clause}", params).fetchone()[0]
        pages = max(1, -(-total // per_page))
        page = max(1, min(int(page), pages))
        rows = connection.execute(
            f"SELECT id, ts, severity, rule_id, log_source, source_ip, description FROM alerts {clause} "
            f"ORDER BY {order} LIMIT ? OFFSET ?", params + [per_page, (page - 1) * per_page]).fetchall()
    finally:
        connection.close()
    return {"total": total, "page": page, "pages": pages, "per_page": per_page, "items": [dict(r) for r in rows]}


def get_alert(db_path: str, alert_id_value: str):
    connection = _open(db_path)
    try:
        row = connection.execute("SELECT detail FROM alerts WHERE id = ?", (str(alert_id_value)[:20],)).fetchone()
    finally:
        connection.close()
    return json.loads(row["detail"]) if row else None
