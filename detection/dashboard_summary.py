# detection/dashboard_summary.py
"""
Builds the SMALL file the public dashboard reads: dashboard_summary.json.

WHY: the old dashboard loaded the whole 16 MB report on every request and printed raw
alert text. The engine already holds every alert in memory once per cycle, so it
writes down just what the page draws (a few hundred KB at most). The dashboard pod
then only serves that file, read-only.

PUBLIC-SAFETY RULES (the page is reachable from the internet):
- no raw_log and no `extra` fields leave this module
- the owner's own activity (INTERNAL_AUIDS) is left out of the "notable alerts" list
- every free-text value that an attacker controls (usernames, passwords, descriptions)
  is stripped of control characters and length-capped here; the page ALSO escapes it
"""
import json
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone

from rules.rule_018_collector_heartbeat import SOURCES as HEARTBEAT_SOURCES
from detection import public_alerts

WINDOW_HOURS = 24
TOP_ATTACKERS = 25
TOP_CREDENTIALS = 12
NOTABLE_LIMIT = 15
TIMELINE_DAYS = 30
INTERNAL_AUIDS = {int(x) for x in os.environ.get("PURPLE_INTERNAL_AUIDS", "1000").split(",") if x.strip()}
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value, limit: int) -> str:
    """Plain, bounded text: no control characters, capped length. HTML is NOT stripped
    here on purpose (the page escapes it); this only keeps hostile input small and flat."""
    return _CONTROL_CHARS.sub(" ", str(value))[:limit]


def _as_utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def event_time(alert) -> datetime:
    """When the thing happened (first_seen), falling back to when the alert was made."""
    return _as_utc(alert.first_seen or alert.timestamp)


def _sev(alert) -> str:
    return getattr(alert.severity, "value", str(alert.severity))


def _src(alert) -> str:
    return getattr(alert.log_source, "value", str(alert.log_source))


def is_public_alert(alert) -> bool:
    """Alerts the public page may count or list: not honeypot, not INFO, not the owner's own."""
    return _src(alert) != "cowrie" and public_alerts.is_public(alert)


def honeypot_daily_sessions(db_path: str, now: datetime, days: int = TIMELINE_DAYS) -> dict[str, int]:
    """Honeypot sessions per UTC day for the last `days` days, counted in SQL.
    Sessions, not alerts: rule_015 only alerts on a SUCCESSFUL login, so alerts alone
    would hide the scanners that connect and leave."""
    first_day = (now - timedelta(days=days - 1)).date().isoformat()
    connection = _open_ro(db_path)
    try:
        return {row["day"]: row["n"] for row in connection.execute(
            "SELECT substr(start_time, 1, 10) AS day, COUNT(*) AS n FROM sessions "
            "WHERE substr(start_time, 1, 10) >= ? GROUP BY day", (first_day,))}
    finally:
        connection.close()


def daily_timeline(alerts, honeypot_by_day: dict[str, int], now: datetime, days: int = TIMELINE_DAYS) -> list[dict]:
    """One bucket per UTC day, oldest first: honeypot sessions next to public alerts."""
    first = now.date() - timedelta(days=days - 1)
    buckets = {}
    for offset in range(days):
        day = (first + timedelta(days=offset)).isoformat()
        buckets[day] = {"day": day, "honeypot": honeypot_by_day.get(day, 0), "other": 0}
    for alert in alerts:
        if is_public_alert(alert):
            bucket = buckets.get(event_time(alert).date().isoformat())
            if bucket is not None:
                bucket["other"] += 1
    return list(buckets.values())


def notable_alerts(alerts, now: datetime, limit: int = NOTABLE_LIMIT) -> list[dict]:
    """Newest non-honeypot alerts, minus INFO and the owner's own activity."""
    picked = [alert for alert in alerts if is_public_alert(alert)]
    picked.sort(key=event_time, reverse=True)
    return [{
        "time": event_time(a).isoformat(),
        "severity": _sev(a),
        "rule": clean_text(a.rule_id, 60),
        "technique": getattr(a.technique, "value", str(a.technique)),
        "source": _src(a),
        "ip": clean_text(a.source_ip or "", 45),
        "text": clean_text(a.description, 160),
    } for a in picked[:limit]]


def _open_ro(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def honeypot_stats(db_path: str, now: datetime) -> tuple[list[dict], list[dict], list[dict], dict]:
    """Top attacker IPs, top usernames, top passwords, and totals from the honeypot DB.
    Aggregated in SQL, so memory stays flat however many sessions exist."""
    since = (now - timedelta(hours=WINDOW_HOURS)).isoformat()
    connection = _open_ro(db_path)
    try:
        attackers = [dict(row) for row in connection.execute(
            """SELECT s.src_ip AS ip, COUNT(DISTINCT s.session_id) AS sessions,
                      COUNT(l.id) AS attempts, MAX(s.start_time) AS last_seen
               FROM sessions s LEFT JOIN session_logins l ON l.session_id = s.session_id
               GROUP BY s.src_ip ORDER BY sessions DESC, attempts DESC LIMIT ?""", (TOP_ATTACKERS,))]
        usernames = [{"value": clean_text(r["value"], 40), "count": r["n"]} for r in connection.execute(
            "SELECT username AS value, COUNT(*) AS n FROM session_logins GROUP BY username "
            "ORDER BY n DESC LIMIT ?", (TOP_CREDENTIALS,))]
        passwords = [{"value": clean_text(r["value"], 40), "count": r["n"]} for r in connection.execute(
            "SELECT password AS value, COUNT(*) AS n FROM session_logins GROUP BY password "
            "ORDER BY n DESC LIMIT ?", (TOP_CREDENTIALS,))]
        totals = dict(connection.execute(
            """SELECT COUNT(*) AS sessions_total,
                      COUNT(DISTINCT src_ip) AS attackers_total,
                      COUNT(DISTINCT CASE WHEN start_time >= ? THEN src_ip END) AS attackers_24h,
                      SUM(CASE WHEN start_time >= ? THEN 1 ELSE 0 END) AS sessions_24h
               FROM sessions""", (since, since)).fetchone())
        totals["sessions_24h"] = totals["sessions_24h"] or 0
    finally:
        connection.close()
    for entry in attackers:
        entry["ip"] = clean_text(entry["ip"], 45)
        entry["last_seen"] = entry["last_seen"] or ""
    return attackers, usernames, passwords, totals


def ssh_probe_sources(alerts) -> dict[str, int]:
    """Real-sshd scanners (rule_001) by source IP: how many alerts each produced."""
    counts: Counter = Counter()
    for alert in alerts:
        if alert.rule_id.startswith("rule_001") and alert.source_ip:
            counts[alert.source_ip] += 1
    return dict(counts)


def pipeline_health(heartbeat_state: dict | None, now: datetime) -> list[dict]:
    """One row per monitored log source, using the same limits as rule_018.
    ok = delivered input within its limit; waiting = never delivered yet but still inside
    the limit; silent = past the limit (the state rule_018 raises an alert for)."""
    rows = []
    state = heartbeat_state or {}
    for source, config in HEARTBEAT_SOURCES.items():
        entry = state.get(source)
        limit_hours = config["limit"].total_seconds() / 3600
        if not entry:
            rows.append({"source": source, "status": "unknown", "last_input": None,
                         "limit_hours": limit_hours, "silent_hours": None})
            continue
        last_input = entry.get("last_input")
        reference = last_input or entry.get("watching_since")
        silent_hours = None
        status = "unknown"
        if reference:
            silent_hours = round((now - _as_utc(datetime.fromisoformat(reference))).total_seconds() / 3600, 1)
            if entry.get("outage_since") or silent_hours > limit_hours:
                status = "silent"
            else:
                status = "ok" if last_input else "waiting"
        rows.append({"source": source, "status": status, "last_input": last_input,
                     "limit_hours": limit_hours, "silent_hours": silent_hours})
    rows.append({"source": "falco", "status": "not_monitored", "last_input": None,
                 "limit_hours": None, "silent_hours": None})
    return rows


def build_summary(alerts, coverage, heartbeat_state, db_path: str, geo: dict, now: datetime | None = None) -> dict:
    now = _as_utc(now or datetime.now(timezone.utc))
    warnings: list[str] = []
    since = now - timedelta(hours=WINDOW_HOURS)
    public = [a for a in alerts if public_alerts.is_public(a)]      # same rule as the alerts page
    recent = [a for a in public if event_time(a) >= since]
    severity_24h = Counter(_sev(a) for a in recent)

    try:
        attackers, usernames, passwords, hp_totals = honeypot_stats(db_path, now)
        honeypot_by_day = honeypot_daily_sessions(db_path, now)
    except sqlite3.Error as error:
        warnings.append(f"honeypot database unreadable: {error}")
        attackers, usernames, passwords, honeypot_by_day = [], [], [], {}
        hp_totals = {"sessions_total": 0, "attackers_total": 0, "attackers_24h": 0, "sessions_24h": 0}

    probes = ssh_probe_sources(alerts)
    by_ip = {a["ip"]: {**a, "ssh_probe_alerts": 0} for a in attackers}
    for ip, count in probes.items():
        by_ip.setdefault(clean_text(ip, 45), {"ip": clean_text(ip, 45), "sessions": 0, "attempts": 0,
                                              "last_seen": "", "ssh_probe_alerts": 0})["ssh_probe_alerts"] = count
    attacker_rows = sorted(by_ip.values(), key=lambda a: (a["sessions"] + a["ssh_probe_alerts"], a["attempts"]), reverse=True)[:TOP_ATTACKERS]
    for row in attacker_rows:
        place = geo.get(row["ip"])
        row["geo"] = place if place else None

    return {
        "generated_at": now.isoformat(),
        "window_hours": WINDOW_HOURS,
        "timeline_days": TIMELINE_DAYS,
        "warnings": warnings,
        "totals": {
            "alerts_total": len(public),
            "alerts_24h": len(recent),
            "critical_24h": severity_24h.get("CRITICAL", 0),
            "high_24h": severity_24h.get("HIGH", 0),
            "honeypot_sessions_total": hp_totals["sessions_total"],
            "honeypot_sessions_24h": hp_totals["sessions_24h"],
            "attackers_total": hp_totals["attackers_total"],
            "attackers_24h": hp_totals["attackers_24h"],
        },
        "severity_24h": dict(severity_24h),
        "timeline": daily_timeline(alerts, honeypot_by_day, now),
        "notable": notable_alerts(alerts, now),
        "attackers": attacker_rows,
        "usernames": usernames,
        "passwords": passwords,
        "pipeline": pipeline_health(heartbeat_state, now),
        "coverage": {
            "pct": coverage.coverage_pct,
            "detected": coverage.detected_count,
            "total": coverage.total_techniques,
            "techniques": [{
                "id": getattr(t.technique, "value", str(t.technique)), "name": clean_text(t.name, 60),
                "detected": t.detected, "alerts": t.alert_count,
                "source": getattr(t.log_source, "value", str(t.log_source)) if t.log_source else None,
            } for t in coverage.techniques],
        },
    }


def write_summary(summary: dict, path: str) -> None:
    """Atomic write, same pattern as the alert store: temp file, fsync, rename."""
    temp_path = path + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(summary, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, path)


def attach_geo(summary: dict, geo: dict) -> None:
    for row in summary["attackers"]:
        row["geo"] = geo.get(row["ip"])


def publish(alerts, coverage, reports_dir, heartbeat_state=None, geo_enabled: bool = True,
            now: datetime | None = None) -> dict:
    """Build the summary, locate the attackers it lists (cached), write it. Returns it."""
    from detection import geo_lookup                      # local import keeps the module light
    reports_dir = str(reports_dir)
    summary = build_summary(alerts, coverage, heartbeat_state, os.path.join(reports_dir, "cowrie.db"), {}, now)
    if geo_enabled:
        try:
            geo = geo_lookup.enrich([row["ip"] for row in summary["attackers"]],
                                    os.path.join(reports_dir, "geo_cache.json"), now=now)
            attach_geo(summary, geo)
        except Exception as error:                        # a geo problem must never cost us the summary
            summary["warnings"].append(f"geolocation failed: {clean_text(error, 120)}")
    try:
        db_path = os.path.join(reports_dir, "public_alerts.db")
        public_alerts.rebuild(alerts, db_path, hidden_ips=None)
        since_iso = ((now or datetime.now(timezone.utc)) - timedelta(hours=WINDOW_HOURS)).isoformat()
        summary["rule_counts"] = public_alerts.rule_counts(db_path, since_iso)
    except Exception as error:                            # the alerts page degrades; the engine carries on
        summary["warnings"].append(f"public alert store failed: {clean_text(error, 120)}")
        summary["rule_counts"] = {}
    write_summary(summary, os.path.join(reports_dir, "dashboard_summary.json"))
    return summary
