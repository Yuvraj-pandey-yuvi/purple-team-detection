# detection/public_attackers.py
"""
Per-attacker detail and honeypot aggregates for the public dashboard.

The engine builds public_attackers.json (detail for the top TOP_N attackers by sessions) and
returns small aggregates (countries, networks, commands, map points) for the summary. The
dashboard pod only reads the file, so it never touches the live honeypot database.

Attacker-controlled text (commands, usernames, passwords) is flattened, length-capped and
URLs are defanged (http -> hxxp). Binary-looking payloads are never printed.
"""
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

from detection import public_alerts

TOP_N = 200
LIST_LIMIT = 8
COMMAND_LIMIT = 12
COMMAND_CHARS = 120
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_URL = re.compile(r"(?i)\b(h)ttp(s?)://|\bftp://")

# (substring or regex on the normalised command, plain-English meaning)
MEANINGS = [
    (re.compile(r"\\x6f\\x6b", re.I), "Prints “ok”: bots use this to check the shell works."),
    (re.compile(r"^(/bin/\./)?uname\b"), "Fingerprints the operating system."),
    (re.compile(r"/proc/cpuinfo"), "Reads CPU details: is this a real machine or a trap?"),
    (re.compile(r"\b(wget|curl)\b"), "Downloads a file: a malware-dropper attempt."),
    (re.compile(r"\bchmod\b"), "Makes a file executable."),
    (re.compile(r"\becho\b.*>\s*\S+"), "Writes a file, often a password or a marker."),
]


def flat(value, limit: int) -> str:
    return _CONTROL.sub(" ", str(value))[:limit]


def defang(text: str) -> str:
    return _URL.sub(lambda m: ("hxx" + "p" + (m.group(2) or "") + "://") if m.group(1) else "fxp://", text)


def looks_binary(text: str) -> bool:
    if "ELF" in text[:16]:
        return True
    if len(text) >= 8:
        readable = sum(ch.isalnum() or ch in " /._-:=\"'|;&<>$#" for ch in text)
        return readable / len(text) < 0.5
    return False


def display_command(text: str) -> str:
    if looks_binary(text):
        return f"(binary payload, {len(text):,} characters)"
    text = defang(flat(text, 5000))
    return text if len(text) <= COMMAND_CHARS else text[:COMMAND_CHARS] + "…"


def meaning_of(text: str) -> str:
    if looks_binary(text):
        return "A program sent through the shell: a malware-dropper attempt."
    for pattern, meaning in MEANINGS:
        if pattern.search(text.strip()):
            return meaning
    return ""


def _ro(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def top_ips(db_path: str, limit: int = TOP_N) -> list[str]:
    """Attacker IPs by session count, most active first. Empty if the database is unreadable."""
    try:
        connection = _ro(db_path)
        try:
            return [r[0] for r in connection.execute(
                "SELECT src_ip FROM sessions GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT ?", (limit,))]
        finally:
            connection.close()
    except sqlite3.Error:
        return []


def _grouped(connection, sql, keep):
    """Run one grouped query and keep the top 5 (value, count) per IP among `keep`."""
    per_ip = defaultdict(list)
    for ip, value, n in connection.execute(sql):
        if ip in keep:
            per_ip[ip].append((value, n))
    return {ip: sorted(v, key=lambda x: -x[1])[:5] for ip, v in per_ip.items()}


def build(cowrie_db: str, geo: dict, alerts, out_path: str, now: datetime | None = None, top_n: int = TOP_N) -> dict:
    now = now or datetime.now(timezone.utc)
    connection = _ro(cowrie_db)
    try:
        total_sessions = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        top = connection.execute(
            "SELECT src_ip AS ip, COUNT(*) AS sessions, MIN(start_time) AS first_seen, MAX(start_time) AS last_seen "
            "FROM sessions GROUP BY src_ip ORDER BY sessions DESC LIMIT ?", (top_n,)).fetchall()
        keep = {r["ip"] for r in top}
        attempts = dict(connection.execute(
            "SELECT s.src_ip, COUNT(*) FROM session_logins l JOIN sessions s ON s.session_id = l.session_id GROUP BY s.src_ip").fetchall())
        users = _grouped(connection, "SELECT s.src_ip, l.username, COUNT(*) FROM session_logins l JOIN sessions s "
                                     "ON s.session_id = l.session_id GROUP BY s.src_ip, l.username", keep)
        pwds = _grouped(connection, "SELECT s.src_ip, l.password, COUNT(*) FROM session_logins l JOIN sessions s "
                                    "ON s.session_id = l.session_id GROUP BY s.src_ip, l.password", keep)
        cmds = _grouped(connection, "SELECT s.src_ip, c.command_text, COUNT(*) FROM session_commands c JOIN sessions s "
                                    "ON s.session_id = c.session_id GROUP BY s.src_ip, c.command_text", keep)
        cmd_rows = connection.execute("SELECT command_text, COUNT(*) AS n FROM session_commands "
                                      "GROUP BY command_text ORDER BY n DESC").fetchall()
        with_commands = connection.execute("SELECT COUNT(DISTINCT session_id) FROM session_commands").fetchone()[0]
    finally:
        connection.close()

    rules_by_ip: dict[str, Counter] = defaultdict(Counter)
    for alert in alerts:
        if alert.source_ip in keep and public_alerts.is_public(alert):
            rules_by_ip[alert.source_ip][alert.rule_id] += 1

    detail, countries, networks, points = {}, {}, {}, []
    located_sessions = 0
    for r in top:
        ip, place = r["ip"], geo.get(r["ip"]) or {}
        detail[ip] = {
            "ip": ip, "sessions": r["sessions"], "login_attempts": attempts.get(ip, 0),
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "country": place.get("country"), "cc": place.get("cc"), "city": place.get("city"),
            "network": place.get("org") or None, "asn": place.get("asn") or None,
            "usernames": [{"value": flat(v, 40), "count": n} for v, n in users.get(ip, [])],
            "passwords": [{"value": flat(v, 40), "count": n} for v, n in pwds.get(ip, [])],
            "commands": [{"value": display_command(v), "count": n, "meaning": meaning_of(v)} for v, n in cmds.get(ip, [])],
            "rules": [{"rule_id": k, "count": n} for k, n in rules_by_ip[ip].most_common(5)],
        }
        if "lat" in place:
            located_sessions += r["sessions"]
            points.append({"ip": ip, "lat": place["lat"], "lon": place["lon"], "sessions": r["sessions"], "cc": place.get("cc")})
            c = countries.setdefault(place.get("cc") or "??", {"cc": place.get("cc") or "??", "country": place.get("country") or "Unknown", "sessions": 0, "attackers": 0})
            c["sessions"] += r["sessions"]; c["attackers"] += 1
            key = place.get("org") or "Unknown network"
            n_ = networks.setdefault(key, {"network": key, "sessions": 0, "attackers": 0})
            n_["sessions"] += r["sessions"]; n_["attackers"] += 1

    shown = cmd_rows[:COMMAND_LIMIT]
    commands = {"total": sum(r["n"] for r in cmd_rows), "distinct": len(cmd_rows), "sessions_with_commands": with_commands,
                "sessions_total": total_sessions,
                "top": [{"value": display_command(r["command_text"]), "count": r["n"], "meaning": meaning_of(r["command_text"])} for r in shown],
                "other": sum(r["n"] for r in cmd_rows[COMMAND_LIMIT:])}
    document = {"generated_at": now.isoformat(), "attackers": detail}
    temp_path = out_path + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(document, f, separators=(",", ":"))
        f.flush(); os.fsync(f.fileno())
    os.replace(temp_path, out_path)
    by = lambda d: sorted(d.values(), key=lambda x: -x["sessions"])[:10]
    return {"countries": by(countries), "networks": by(networks), "map": points, "commands": commands,
            "geo_coverage": {"top_n": top_n, "total_sessions": total_sessions, "located_sessions": located_sessions}}
